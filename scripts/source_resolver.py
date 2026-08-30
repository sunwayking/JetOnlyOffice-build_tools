#!/usr/bin/env python3

import argparse
import fnmatch
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse
import zipfile

from cef_evidence import CefEvidenceError, derived_cef_pak_resource
from contracts.contract_tool import (
  ContractError,
  SOURCE_LICENSE_EXPRESSIONS,
  SOURCE_LICENSE_REVIEW_CODES,
  canonical_json_bytes,
  load_json,
  validate_contract,
)


SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
MIRROR_PATTERN = re.compile(
  r"^https://github\.com/sunwayking/JetOnlyOffice-[A-Za-z0-9._-]+\.git$"
)
REPOSITORY_ROLES = {
  "product-fork",
  "superproject",
  "gitlink",
  "auxiliary-mirror",
  "build-input",
  "package-input",
  "toolchain-source",
}
REPOSITORY_KEYS = {
  "id",
  "role",
  "checkoutPath",
  "origin",
  "upstream",
  "commit",
  "commitSource",
  "refHint",
  "selection",
  "projectFork",
  "buildInput",
  "active",
  "license",
}
WINDOWS_DEVICE_PATTERN = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)
SOURCE_TREE_MANIFEST_PATH = "source-tree-manifest.json"
LICENSE_REF_PATTERN = re.compile(r"LicenseRef-[A-Za-z0-9.-]+")


class ResolutionError(ValueError):
  def __init__(self, message, exit_code=3):
    super().__init__(message)
    self.exit_code = exit_code


class AnonymousHttpError(ResolutionError):
  def __init__(self, message, status_code):
    super().__init__(message, 3)
    self.status_code = status_code


class LfsActionRefreshRequired(ResolutionError):
  pass


def _require_exact_keys(value, required, optional, path):
  if not isinstance(value, dict):
    raise ResolutionError(f"{path}: expected object", 2)
  missing = sorted(required - set(value))
  if missing:
    raise ResolutionError(f"{path}: missing properties: {', '.join(missing)}", 2)
  unknown = sorted(set(value) - required - optional)
  if unknown:
    raise ResolutionError(f"{path}: unknown properties: {', '.join(unknown)}", 2)


def _validate_relative_path(value, path):
  if not isinstance(value, str):
    raise ResolutionError(f"{path}: expected string", 2)
  candidate = PurePosixPath(value)
  parts = value.split("/")
  if (
    candidate.is_absolute()
    or value in ("", ".")
    or "\\" in value
    or "//" in value
    or re.match(r"^[A-Za-z]:", value)
    or any(part in ("", ".", "..") for part in parts)
    or any(part.rstrip(" .") != part for part in parts)
    or any(WINDOWS_DEVICE_PATTERN.match(part) for part in parts)
    or any(any(ord(character) < 32 or character in '<>:"|?*' for character in part) for part in parts)
  ):
    raise ResolutionError(f"{path}: path must be normalized and relative", 2)


def _resolve_within(root, relative_path, path):
  root = Path(root).resolve()
  candidate = (root / PurePosixPath(relative_path)).resolve()
  if not candidate.is_relative_to(root):
    raise ResolutionError(f"{path}: resolved path escapes its root", 3)
  return candidate


def _validate_https(value, path):
  if not isinstance(value, str):
    raise ResolutionError(f"{path}: expected string", 2)
  parsed = urlparse(value)
  if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
    raise ResolutionError(f"{path}: expected credential-free HTTPS URL", 2)


def validate_inputs(value):
  canonical_json_bytes(value)
  required = {
    "schemaVersion",
    "productVersion",
    "releaseCutoff",
    "baseline",
    "repositories",
    "relationships",
  }
  _require_exact_keys(value, required, set(), "$")
  if value["schemaVersion"] != 1:
    raise ResolutionError("$.schemaVersion: expected 1", 2)
  if not isinstance(value["productVersion"], str) or not re.fullmatch(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?",
    value["productVersion"],
  ):
    raise ResolutionError("$.productVersion: invalid product version", 2)
  if (
    not isinstance(value["releaseCutoff"], int)
    or isinstance(value["releaseCutoff"], bool)
    or value["releaseCutoff"] < 1
  ):
    raise ResolutionError("$.releaseCutoff: expected integer", 2)

  baseline = value["baseline"]
  _require_exact_keys(baseline, {"repository", "commit"}, set(), "$.baseline")
  if not SHA1_PATTERN.fullmatch(baseline["commit"]):
    raise ResolutionError("$.baseline.commit: expected full Git commit", 2)

  repositories = value["repositories"]
  if not isinstance(repositories, list) or not repositories:
    raise ResolutionError("$.repositories: expected non-empty array", 2)
  ids = []
  checkout_paths = []
  for index, repository in enumerate(repositories):
    path = f"$.repositories[{index}]"
    required_repository = REPOSITORY_KEYS - {"commit", "commitSource"}
    _require_exact_keys(
      repository,
      required_repository,
      {"commit", "commitSource"},
      path,
    )
    repository_id = repository["id"]
    if not isinstance(repository_id, str) or not ID_PATTERN.fullmatch(repository_id):
      raise ResolutionError(f"{path}.id: invalid repository id", 2)
    ids.append(repository_id)
    if repository["role"] not in REPOSITORY_ROLES:
      raise ResolutionError(f"{path}.role: unsupported repository role", 2)
    _validate_relative_path(repository["checkoutPath"], path + ".checkoutPath")
    checkout_paths.append(repository["checkoutPath"])
    _validate_https(repository["origin"], path + ".origin")
    _validate_https(repository["upstream"], path + ".upstream")
    if not MIRROR_PATTERN.fullmatch(repository["origin"]):
      raise ResolutionError(
        f"{path}.origin: build inputs must use a sunwayking JetOnlyOffice mirror",
        2,
      )
    has_commit = "commit" in repository
    has_self = repository.get("commitSource") == "self"
    if has_commit == has_self:
      raise ResolutionError(
        f"{path}: specify exactly one fixed commit or commitSource=self",
        2,
      )
    if has_commit and not SHA1_PATTERN.fullmatch(repository["commit"]):
      raise ResolutionError(f"{path}.commit: expected full Git commit", 2)
    if "commitSource" in repository and not has_self:
      raise ResolutionError(f"{path}.commitSource: only self is supported", 2)
    if has_self and repository_id != "build-tools":
      raise ResolutionError(f"{path}.commitSource: self is reserved for build-tools", 2)
    if not isinstance(repository["refHint"], str) or not repository["refHint"]:
      raise ResolutionError(f"{path}.refHint: expected non-empty string", 2)
    _validate_selection_input(repository["selection"], path + ".selection")
    if has_self != (repository["selection"]["type"] == "self"):
      raise ResolutionError(
        f"{path}.selection: self selection must match commitSource=self",
        2,
      )
    for flag in ("projectFork", "buildInput", "active"):
      if not isinstance(repository[flag], bool):
        raise ResolutionError(f"{path}.{flag}: expected boolean", 2)
    if repository["selection"]["type"] == "branch" and not repository["projectFork"]:
      raise ResolutionError(
        f"{path}.selection: branch selection is reserved for project forks",
        2,
      )
    _validate_license_input(repository["license"], path + ".license")

  if ids != sorted(ids) or len(ids) != len(set(ids)):
    raise ResolutionError("$.repositories: ids must be sorted and unique", 2)
  self_ids = [
    repository["id"]
    for repository in repositories
    if repository.get("commitSource") == "self"
  ]
  if self_ids != ["build-tools"]:
    raise ResolutionError("$.repositories: build-tools must be the only self commit", 2)
  if len(checkout_paths) != len(set(checkout_paths)):
    raise ResolutionError("$.repositories: checkoutPath values must be unique", 2)
  for index, checkout_path in enumerate(checkout_paths):
    for other in checkout_paths[index + 1:]:
      if checkout_path.startswith(other + "/") or other.startswith(checkout_path + "/"):
        raise ResolutionError(
          "$.repositories: checkoutPath values must not overlap", 2
        )
  repository_ids = set(ids)
  if baseline["repository"] not in repository_ids:
    raise ResolutionError("$.baseline.repository: repository is not selected", 2)
  selected_baseline = next(
    repository for repository in repositories if repository["id"] == baseline["repository"]
  )
  if selected_baseline.get("commit") != baseline["commit"]:
    raise ResolutionError("$.baseline.commit: does not match selected repository", 2)
  _validate_repository_evidence_links(repositories)

  relationships = value["relationships"]
  if not isinstance(relationships, list):
    raise ResolutionError("$.relationships: expected array", 2)
  keys = []
  for index, relationship in enumerate(relationships):
    path = f"$.relationships[{index}]"
    _require_exact_keys(
      relationship,
      {"parent", "child", "path", "mode"},
      set(),
      path,
    )
    if relationship["parent"] not in repository_ids:
      raise ResolutionError(f"{path}.parent: repository is not selected", 2)
    if relationship["child"] not in repository_ids:
      raise ResolutionError(f"{path}.child: repository is not selected", 2)
    _validate_relative_path(relationship["path"], path + ".path")
    if relationship["mode"] != "160000":
      raise ResolutionError(f"{path}.mode: expected 160000", 2)
    keys.append((relationship["parent"], relationship["path"], relationship["child"]))
  if keys != sorted(keys) or len(keys) != len(set(keys)):
    raise ResolutionError("$.relationships: entries must be sorted and unique", 2)
  relationships_by_child = {
    (relationship["child"], relationship["parent"], relationship["path"])
    for relationship in relationships
  }
  for index, repository in enumerate(repositories):
    selection = repository["selection"]
    if selection["type"] != "gitlink":
      continue
    key = (repository["id"], selection["parent"], selection["path"])
    if key not in relationships_by_child:
      raise ResolutionError(
        f"$.repositories[{index}].selection: does not match a declared relationship",
        2,
      )


def _validate_selection_input(value, path):
  if not isinstance(value, dict):
    raise ResolutionError(f"{path}: expected object", 2)
  selection_type = value.get("type")
  if selection_type == "self":
    _require_exact_keys(value, {"type"}, set(), path)
  elif selection_type == "branch":
    _require_exact_keys(value, {"type", "ref"}, set(), path)
    if value["ref"] != "refs/heads/develop":
      raise ResolutionError(f"{path}.ref: expected develop branch ref", 2)
  elif selection_type == "tag":
    _require_exact_keys(value, {"type", "ref"}, set(), path)
    ref = value["ref"]
    if (
      not isinstance(ref, str)
      or not re.fullmatch(r"refs/tags/[0-9A-Za-z][0-9A-Za-z._/-]*", ref)
      or ".." in ref
      or "@{" in ref
      or "//" in ref
      or ref.endswith(("/", "."))
    ):
      raise ResolutionError(f"{path}.ref: expected full immutable tag ref", 2)
  elif selection_type == "gitlink":
    _require_exact_keys(value, {"type", "parent", "path"}, set(), path)
    if not isinstance(value["parent"], str) or not ID_PATTERN.fullmatch(value["parent"]):
      raise ResolutionError(f"{path}.parent: invalid repository id", 2)
    _validate_relative_path(value["path"], path + ".path")
  elif selection_type == "cutoff":
    _require_exact_keys(value, {"type", "refPrefix"}, set(), path)
    if value["refPrefix"] != "refs/heads/upstream/":
      raise ResolutionError(
        f"{path}.refPrefix: expected official upstream head prefix",
        2,
      )
  else:
    raise ResolutionError(f"{path}.type: unsupported selection type", 2)


def _validate_license_input(value, path):
  if not isinstance(value, dict):
    raise ResolutionError(f"{path}: expected object", 2)
  status = value.get("status")
  if status == "declared":
    _require_exact_keys(value, {"status", "path", "spdx"}, set(), path)
    _validate_relative_path(value["path"], path + ".path")
    if not isinstance(value["spdx"], str) or not value["spdx"]:
      raise ResolutionError(f"{path}.spdx: expected non-empty SPDX expression", 2)
    if value["spdx"] not in SOURCE_LICENSE_EXPRESSIONS:
      raise ResolutionError(
        f"{path}.spdx: license expression is not in the reviewed source set",
        2,
      )
  elif status == "component-scoped":
    _require_exact_keys(
      value,
      {
        "status",
        "payloadPatterns",
        "patterns",
        "reason",
        "unresolvedComponents",
      },
      {"blockingReviews", "reviewedComponents"},
      path,
    )
    if (
      not isinstance(value["patterns"], list)
      or not value["patterns"]
      or not all(isinstance(item, str) and item for item in value["patterns"])
    ):
      raise ResolutionError(f"{path}.patterns: expected non-empty string array", 2)
    if value["patterns"] != sorted(set(value["patterns"])):
      raise ResolutionError(f"{path}.patterns: values must be sorted and unique", 2)
    _validate_patterns(value["payloadPatterns"], path + ".payloadPatterns")
    _validate_unresolved_components(value["unresolvedComponents"], path)
    _validate_blocking_reviews(value.get("blockingReviews", []), path)
    _validate_reviewed_components(value.get("reviewedComponents", []), path)
    reviewed_ids = {
      component["id"] for component in value.get("reviewedComponents", [])
    }
    overlap = reviewed_ids.intersection(value["unresolvedComponents"])
    if overlap:
      raise ResolutionError(
        f"{path}: components cannot be both reviewed and unresolved: "
        + ", ".join(sorted(overlap)),
        2,
      )
    blocking_ids = {
      review["id"] for review in value.get("blockingReviews", [])
    }
    missing_unresolved = blocking_ids.difference(value["unresolvedComponents"])
    if missing_unresolved:
      raise ResolutionError(
        f"{path}: every blocking review must remain unresolved: "
        + ", ".join(sorted(missing_unresolved)),
        2,
      )
    if not isinstance(value["reason"], str) or not value["reason"]:
      raise ResolutionError(f"{path}.reason: expected non-empty string", 2)
  elif status == "missing":
    _require_exact_keys(
      value,
      {"status", "payloadPatterns", "reason", "unresolvedComponents"},
      set(),
      path,
    )
    _validate_patterns(value["payloadPatterns"], path + ".payloadPatterns")
    _validate_unresolved_components(value["unresolvedComponents"], path)
    if not isinstance(value["reason"], str) or not value["reason"]:
      raise ResolutionError(f"{path}.reason: expected non-empty string", 2)
  else:
    raise ResolutionError(f"{path}.status: unsupported license status", 2)


def _validate_unresolved_components(value, path):
  if (
    not isinstance(value, list)
    or not all(isinstance(item, str) and item for item in value)
    or value != sorted(set(value))
  ):
    raise ResolutionError(
      f"{path}.unresolvedComponents: expected sorted unique strings",
      2,
    )


def _validate_blocking_reviews(value, path):
  if not isinstance(value, list):
    raise ResolutionError(f"{path}.blockingReviews: expected array", 2)
  review_ids = []
  for review_index, review in enumerate(value):
    review_path = f"{path}.blockingReviews[{review_index}]"
    _require_exact_keys(
      review,
      {"id", "code", "reason", "evidence"},
      set(),
      review_path,
    )
    review_id = review["id"]
    if not isinstance(review_id, str) or not review_id:
      raise ResolutionError(f"{review_path}.id: expected non-empty string", 2)
    review_ids.append(review_id)
    if review["code"] not in SOURCE_LICENSE_REVIEW_CODES:
      raise ResolutionError(f"{review_path}.code: unsupported review code", 2)
    if not isinstance(review["reason"], str) or not review["reason"]:
      raise ResolutionError(f"{review_path}.reason: expected non-empty string", 2)
    evidence = review["evidence"]
    if not isinstance(evidence, list) or not evidence:
      raise ResolutionError(f"{review_path}.evidence: expected non-empty array", 2)
    evidence_paths = []
    for evidence_index, record in enumerate(evidence):
      evidence_path = f"{review_path}.evidence[{evidence_index}]"
      _require_exact_keys(record, {"path", "sha256"}, set(), evidence_path)
      _validate_relative_path(record["path"], evidence_path + ".path")
      if record["path"].partition("/")[0] != review_id:
        raise ResolutionError(
          f"{evidence_path}.path: must belong to the reviewed component",
          2,
        )
      if not isinstance(record["sha256"], str) or not SHA256_PATTERN.fullmatch(
        record["sha256"]
      ):
        raise ResolutionError(f"{evidence_path}.sha256: expected SHA-256", 2)
      evidence_paths.append(record["path"])
    if evidence_paths != sorted(set(evidence_paths)):
      raise ResolutionError(
        f"{review_path}.evidence: entries must be sorted and unique",
        2,
      )
  if review_ids != sorted(set(review_ids)):
    raise ResolutionError(f"{path}.blockingReviews: ids must be sorted and unique", 2)


def _validate_reviewed_components(value, path):
  if not isinstance(value, list):
    raise ResolutionError(f"{path}.reviewedComponents: expected array", 2)
  component_ids = []
  for component_index, component in enumerate(value):
    component_path = f"{path}.reviewedComponents[{component_index}]"
    _require_exact_keys(component, {"id", "spdx", "evidence"}, set(), component_path)
    component_id = component["id"]
    if not isinstance(component_id, str) or not component_id:
      raise ResolutionError(f"{component_path}.id: expected non-empty string", 2)
    component_ids.append(component_id)
    if component["spdx"] not in SOURCE_LICENSE_EXPRESSIONS:
      raise ResolutionError(
        f"{component_path}.spdx: license expression is not in the reviewed source set",
        2,
      )
    evidence = component["evidence"]
    if not isinstance(evidence, list) or not evidence:
      raise ResolutionError(f"{component_path}.evidence: expected non-empty array", 2)
    evidence_keys = []
    license_references = sorted(set(LICENSE_REF_PATTERN.findall(component["spdx"])))
    bound_license_references = set()
    for evidence_index, record in enumerate(evidence):
      evidence_path = f"{component_path}.evidence[{evidence_index}]"
      evidence_type = record.get("type") if isinstance(record, dict) else None
      if evidence_type == "repository-git-blob":
        _require_exact_keys(
          record,
          {"type", "path", "repository", "referencePath", "locator", "sha256"},
          {"licenseRefs"},
          evidence_path,
        )
      elif evidence_type == "repository-cef-pak-resource":
        _require_exact_keys(
          record,
          {
            "type", "path", "repository", "locator", "sha256",
            "archiveMember", "resourceId", "compression",
          },
          {"licenseRefs"},
          evidence_path,
        )
      else:
        _require_exact_keys(
          record,
          {"type", "path", "locator", "sha256"},
          {"licenseRefs"},
          evidence_path,
        )
      if evidence_type not in {
        "font-name",
        "git-blob",
        "repository-cef-pak-resource",
        "repository-git-blob",
        "zip-member",
      }:
        raise ResolutionError(f"{evidence_path}.type: unsupported evidence type", 2)
      _validate_relative_path(record["path"], evidence_path + ".path")
      if evidence_type == "font-name":
        if record["locator"] not in {"name:0", "name:13"}:
          raise ResolutionError(
            f"{evidence_path}.locator: unsupported font license name record",
            2,
          )
      else:
        _validate_relative_path(record["locator"], evidence_path + ".locator")
      if evidence_type in {
        "repository-cef-pak-resource",
        "repository-git-blob",
      }:
        if not isinstance(record["repository"], str) or not ID_PATTERN.fullmatch(
          record["repository"]
        ):
          raise ResolutionError(
            f"{evidence_path}.repository: invalid repository id", 2
          )
        if record["locator"].partition("/")[0] != component_id:
          raise ResolutionError(
            f"{evidence_path}.locator: must belong to the reviewed component",
            2,
          )
      if evidence_type == "repository-git-blob":
        _validate_relative_path(
          record["referencePath"], evidence_path + ".referencePath"
        )
        if record["referencePath"].partition("/")[0] != component_id:
          raise ResolutionError(
            f"{evidence_path}.referencePath: must belong to the reviewed component",
            2,
          )
      elif evidence_type == "repository-cef-pak-resource":
        _validate_relative_path(
          record["archiveMember"], evidence_path + ".archiveMember"
        )
        if (
          not isinstance(record["resourceId"], int)
          or isinstance(record["resourceId"], bool)
          or not 0 < record["resourceId"] <= 65535
        ):
          raise ResolutionError(
            f"{evidence_path}.resourceId: expected a positive uint16", 2
          )
        if record["compression"] not in {"none", "chromium-grit-brotli"}:
          raise ResolutionError(
            f"{evidence_path}.compression: unsupported transform", 2
          )
      if not isinstance(record["sha256"], str) or not SHA256_PATTERN.fullmatch(
        record["sha256"]
      ):
        raise ResolutionError(f"{evidence_path}.sha256: expected SHA-256", 2)
      bindings = record.get("licenseRefs")
      if bindings is None:
        if len(license_references) > 1:
          raise ResolutionError(
            f"{evidence_path}.licenseRefs: required when an expression has "
            "multiple LicenseRef identifiers",
            2,
          )
        bindings = license_references
      if (
        not isinstance(bindings, list)
        or not all(
          isinstance(item, str) and LICENSE_REF_PATTERN.fullmatch(item)
          for item in bindings
        )
        or bindings != sorted(set(bindings))
      ):
        raise ResolutionError(
          f"{evidence_path}.licenseRefs: expected sorted unique LicenseRef identifiers",
          2,
        )
      if not set(bindings).issubset(license_references):
        raise ResolutionError(
          f"{evidence_path}.licenseRefs: identifier is not present in the SPDX expression",
          2,
        )
      bound_license_references.update(bindings)
      evidence_keys.append((
        record["path"],
        evidence_type,
        record.get("repository", ""),
        record.get("referencePath", ""),
        record["locator"],
      ))
    if bound_license_references != set(license_references):
      raise ResolutionError(
        f"{component_path}.evidence: every LicenseRef identifier needs evidence",
        2,
      )
    if evidence_keys != sorted(set(evidence_keys)):
      raise ResolutionError(
        f"{component_path}.evidence: entries must be sorted and unique",
        2,
      )
  if component_ids != sorted(set(component_ids)):
    raise ResolutionError(f"{path}.reviewedComponents: ids must be sorted and unique", 2)


def _validate_repository_evidence_links(repositories):
  repositories_by_id = {repository["id"]: repository for repository in repositories}
  for repository_index, repository in enumerate(repositories):
    for component_index, component in enumerate(
      repository["license"].get("reviewedComponents", [])
    ):
      for evidence_index, evidence in enumerate(component["evidence"]):
        if evidence["type"] not in {
          "repository-cef-pak-resource",
          "repository-git-blob",
        }:
          continue
        path = (
          f"$.repositories[{repository_index}].license.reviewedComponents"
          f"[{component_index}].evidence[{evidence_index}]"
        )
        reference = repositories_by_id.get(evidence["repository"])
        if reference is None:
          raise ResolutionError(
            f"{path}.repository: evidence repository is not selected", 2
          )
        if reference is repository:
          raise ResolutionError(
            f"{path}.repository: cross-repository evidence must use another repository",
            2,
          )
        if not reference["active"] or not reference["buildInput"]:
          raise ResolutionError(
            f"{path}.repository: evidence repository must be an active build input",
            2,
          )
        if reference["selection"]["type"] != "tag":
          raise ResolutionError(
            f"{path}.repository: evidence repository must use an immutable tag",
            2,
          )
        if reference["license"]["status"] != "component-scoped":
          raise ResolutionError(
            f"{path}.repository: evidence repository must use component licenses",
            2,
          )
        reference_component = next(
          (
            item
            for item in reference["license"].get("reviewedComponents", [])
            if item["id"] == component["id"]
          ),
          None,
        )
        if reference_component is None:
          raise ResolutionError(
            f"{path}.repository: matching reviewed component is missing", 2
          )
        if reference_component["spdx"] != component["spdx"]:
          raise ResolutionError(
            f"{path}.repository: reviewed SPDX expressions do not match", 2
          )
        matching = [
          item
          for item in reference_component["evidence"]
          if item["type"] == "git-blob"
          and item["path"] == (
            evidence["referencePath"]
            if evidence["type"] == "repository-git-blob"
            else evidence["locator"]
          )
          and item["locator"] == evidence["locator"]
          and item["sha256"] == evidence["sha256"]
          and item.get("licenseRefs") == evidence.get("licenseRefs")
        ]
        if len(matching) != 1:
          raise ResolutionError(
            f"{path}: evidence is not mapped by the referenced component", 2
          )


def _validate_patterns(value, path):
  if (
    not isinstance(value, list)
    or not value
    or not all(isinstance(item, str) and item for item in value)
    or value != sorted(set(value))
  ):
    raise ResolutionError(f"{path}: expected sorted unique non-empty strings", 2)
  for index, pattern in enumerate(value):
    if "\\" in pattern or pattern.startswith("/") or ".." in pattern.split("/"):
      raise ResolutionError(f"{path}[{index}]: invalid repository glob", 2)


def policy_findings(inputs):
  findings = []
  for repository in inputs["repositories"]:
    license_input = repository["license"]
    if (
      license_input["status"] == "declared"
      or (
        license_input["status"] == "component-scoped"
        and not license_input["unresolvedComponents"]
      )
    ):
      continue
    findings.append({
      "code": "LICENSE_INCOMPLETE",
      "repository": repository["id"],
      "message": license_input["reason"],
      "unresolvedComponents": license_input["unresolvedComponents"],
    })
  return sorted(findings, key=lambda finding: (finding["code"], finding["repository"]))


def audit_report(inputs):
  findings = policy_findings(inputs)
  return {
    "schemaVersion": 1,
    "auditType": "source-input-policy",
    "productVersion": inputs["productVersion"],
    "status": "passed" if not findings else "failed",
    "findings": findings,
  }


def write_canonical_json(path, value):
  path = Path(path)
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_bytes(canonical_json_bytes(value) + b"\n")


def discard_previous_output(path, description):
  path = Path(path)
  try:
    path.unlink(missing_ok=True)
  except OSError as error:
    raise ResolutionError(
      f"{path}: cannot remove previous {description}: {error}",
      3,
    ) from error


def load_source_lock(path):
  path = Path(path)
  if not path.is_file():
    raise ResolutionError(f"{path}: locked source input is missing", 3)
  return load_json(path)


GIT_COMMAND_TIMEOUT_SECONDS = 180

NETWORK_GIT_COMMANDS = ("fetch", "clone", "ls-remote", "push", "pull")


def _run_git_process(arguments, cwd=None, environment=None, timeout=None):
  process_environment = os.environ.copy()
  if environment:
    for key, value in environment.items():
      if value is None:
        process_environment.pop(key, None)
      else:
        process_environment[key] = value
  return subprocess.run(
    ["git", *arguments],
    cwd=cwd,
    capture_output=True,
    env=process_environment,
    check=False,
    timeout=timeout,
  )


TRANSIENT_GIT_NETWORK_PATTERNS = (
  "Connection was reset",
  "unexpected disconnect while reading sideband packet",
  "RPC failed",
  "closed abruptly",
  "expected flush after ref listing",
  "unable to access",
  "Recv failure",
  "the remote end hung up unexpectedly",
  "Failed to connect",
  "Could not connect",
  "Connection timed out",
)


def _is_transient_git_network_error(stderr):
  return any(pattern in stderr for pattern in TRANSIENT_GIT_NETWORK_PATTERNS)


def _run_git(arguments, cwd=None, exit_code=4, environment=None):
  for attempt in range(3):
    try:
      result = _run_git_process(
        arguments,
        cwd=cwd,
        environment=environment,
        timeout=(
          GIT_COMMAND_TIMEOUT_SECONDS
          if arguments and arguments[0] in NETWORK_GIT_COMMANDS
          else None
        ),
      )
    except subprocess.TimeoutExpired:
      if attempt == 2:
        raise ResolutionError("git command timed out", exit_code)
      time.sleep(attempt + 1)
      continue
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    if result.returncode == 0:
      return stdout.strip()
    if attempt == 2 or not _is_transient_git_network_error(stderr):
      detail = stderr.strip() or stdout.strip() or "git command failed"
      raise ResolutionError(detail, exit_code)
    time.sleep(attempt + 1)


def _run_git_bytes(arguments, cwd=None, exit_code=3, environment=None):
  result = _run_git_process(arguments, cwd=cwd, environment=environment)
  if result.returncode != 0:
    detail = result.stderr.decode("utf-8", errors="replace").strip()
    raise ResolutionError(detail or "git command failed", exit_code)
  return result.stdout


def _matches_repository_pattern(path, pattern):
  if fnmatch.fnmatchcase(path, pattern):
    return True
  return pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:])


def _matches_repository_patterns(path, patterns):
  return any(_matches_repository_pattern(path, pattern) for pattern in patterns)


def _paths_at_commit(cache, commit):
  output = _run_git_bytes(
    ["ls-tree", "-r", "-z", "--name-only", commit],
    cwd=cache,
  )
  paths = []
  for encoded_path in output.split(b"\0"):
    if not encoded_path:
      continue
    try:
      path = encoded_path.decode("utf-8")
    except UnicodeDecodeError as error:
      raise ResolutionError("repository path is not UTF-8", 3) from error
    _validate_relative_path(path, "licenseInventory.path")
    paths.append(path)
  return sorted(paths)


def _component_id(path):
  head, separator, _ = path.partition("/")
  return head if separator else path


def _license_evidence(cache, commit, path):
  blob = _run_git(["rev-parse", f"{commit}:{path}"], cwd=cache, exit_code=3)
  content = _run_git_bytes(["show", f"{commit}:{path}"], cwd=cache)
  return {
    "path": path,
    "blob": blob,
    "sha256": hashlib.sha256(content).hexdigest(),
  }


def _read_uint16(content, offset, context):
  if offset < 0 or offset + 2 > len(content):
    raise ResolutionError(f"{context}: truncated font metadata", 3)
  return struct.unpack_from(">H", content, offset)[0]


def _read_uint32(content, offset, context):
  if offset < 0 or offset + 4 > len(content):
    raise ResolutionError(f"{context}: truncated font metadata", 3)
  return struct.unpack_from(">I", content, offset)[0]


def _font_name_texts(content, name_id, context):
  if content[:4] == b"ttcf":
    font_count = _read_uint32(content, 8, context)
    if font_count < 1 or font_count > 1024:
      raise ResolutionError(f"{context}: invalid TrueType collection", 3)
    offset_end = 12 + (font_count * 4)
    if offset_end > len(content):
      raise ResolutionError(f"{context}: truncated TrueType collection", 3)
    font_offsets = [
      _read_uint32(content, 12 + (index * 4), context)
      for index in range(font_count)
    ]
  elif content[:4] in {b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1"}:
    font_offsets = [0]
  else:
    raise ResolutionError(f"{context}: unsupported font payload", 3)

  texts = set()
  for font_offset in font_offsets:
    table_count = _read_uint16(content, font_offset + 4, context)
    directory_end = font_offset + 12 + (table_count * 16)
    if table_count < 1 or table_count > 4096 or directory_end > len(content):
      raise ResolutionError(f"{context}: invalid font table directory", 3)
    name_offset = None
    name_length = None
    for table_index in range(table_count):
      record_offset = font_offset + 12 + (table_index * 16)
      if content[record_offset:record_offset + 4] != b"name":
        continue
      # Table offsets are relative to the beginning of the font file, including TTC files.
      name_offset = _read_uint32(content, record_offset + 8, context)
      name_length = _read_uint32(content, record_offset + 12, context)
      break
    if name_offset is None or name_offset + name_length > len(content):
      raise ResolutionError(f"{context}: font has no valid name table", 3)
    record_count = _read_uint16(content, name_offset + 2, context)
    string_offset = _read_uint16(content, name_offset + 4, context)
    records_end = name_offset + 6 + (record_count * 12)
    storage_offset = name_offset + string_offset
    if records_end > len(content) or storage_offset > name_offset + name_length:
      raise ResolutionError(f"{context}: invalid font name table", 3)
    for record_index in range(record_count):
      record_offset = name_offset + 6 + (record_index * 12)
      fields = struct.unpack_from(">6H", content, record_offset)
      platform_id, _, _, record_name_id, length, offset = fields
      if record_name_id != name_id or platform_id not in {0, 1, 3}:
        continue
      text_start = storage_offset + offset
      text_end = text_start + length
      if text_end > name_offset + name_length or text_end > len(content):
        raise ResolutionError(f"{context}: invalid font name string", 3)
      encoding = "utf-16-be" if platform_id in {0, 3} else "mac_roman"
      try:
        text = content[text_start:text_end].decode(encoding)
      except UnicodeDecodeError as error:
        raise ResolutionError(f"{context}: invalid font name encoding", 3) from error
      if text:
        texts.add(text)
  if not texts:
    raise ResolutionError(f"{context}: font license name record is missing", 3)
  return sorted(texts)


def _zip_member_bytes(content, member_path, context):
  try:
    with zipfile.ZipFile(io.BytesIO(content), "r") as archive:
      matching = [info for info in archive.infolist() if info.filename == member_path]
      if len(matching) != 1 or matching[0].is_dir():
        raise ResolutionError(f"{context}: archive license member is not unique", 3)
      info = matching[0]
      if info.flag_bits & 1:
        raise ResolutionError(f"{context}: encrypted license evidence is unsupported", 3)
      if info.file_size > 4 * 1024 * 1024:
        raise ResolutionError(f"{context}: archive license evidence is too large", 3)
      return archive.read(info)
  except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as error:
    raise ResolutionError(f"{context}: invalid ZIP license evidence", 3) from error


def _derived_cef_pak_resource(content, evidence, context):
  try:
    return derived_cef_pak_resource(content, evidence, context)
  except CefEvidenceError as error:
    raise ResolutionError(str(error), 3) from error


def _locked_git_blob(cache, commit, path, context):
  object_id = _run_git(["rev-parse", f"{commit}:{path}"], cwd=cache, exit_code=3)
  object_type = _run_git(["cat-file", "-t", object_id], cwd=cache, exit_code=3)
  if object_type != "blob":
    raise ResolutionError(f"{context}: expected locked git blob", 3)
  return object_id


def _locked_materialized_blob(repository_context, path, context):
  cache = repository_context["cache"]
  commit = repository_context["commit"]
  blob = _locked_git_blob(cache, commit, path, context)
  content = _run_git_bytes(["cat-file", "blob", blob], cwd=cache)
  materialized = _materialized_lfs_content(
    cache,
    path,
    content,
    repository_context["lfsObjects"],
    context,
  )
  return blob, content, materialized


def _verified_component_evidence(
  cache,
  commit,
  component,
  candidate_evidence_paths,
  lfs_objects,
  repository_contexts,
):
  candidate_evidence_paths = set(candidate_evidence_paths)
  records = []
  for evidence_input in component["evidence"]:
    path = evidence_input["path"]
    context = f"{path}:{evidence_input['locator']}"
    blob = _locked_git_blob(cache, commit, path, context)
    content = _run_git_bytes(["cat-file", "blob", blob], cwd=cache)
    payload_content = _materialized_lfs_content(
      cache, path, content, lfs_objects, context
    )
    if evidence_input["type"] == "repository-git-blob":
      reference = repository_contexts.get(evidence_input["repository"])
      if reference is None:
        raise ResolutionError(
          f"{context}: locked evidence repository is unavailable", 3
        )
      reference_lfs_paths = {
        item
        for lfs_object in reference["lfsObjects"]
        for item in lfs_object["paths"]
      }
      if (
        evidence_input["referencePath"] in reference_lfs_paths
        or evidence_input["locator"] in reference_lfs_paths
      ):
        raise ResolutionError(
          f"{context}: repository evidence must be stored as regular Git blobs",
          3,
        )
      reference_blob, _, reference_content = _locked_materialized_blob(
        reference,
        evidence_input["referencePath"],
        context,
      )
      if reference_content != payload_content:
        raise ResolutionError(
          f"{context}: referenced payload bytes do not match", 3
        )
      evidence_blob, _, evidence_content = _locked_materialized_blob(
        reference,
        evidence_input["locator"],
        context,
      )
      if hashlib.sha256(evidence_content).hexdigest() != evidence_input["sha256"]:
        raise ResolutionError(f"{context}: license evidence digest does not match", 3)
    elif evidence_input["type"] == "repository-cef-pak-resource":
      reference = repository_contexts.get(evidence_input["repository"])
      if reference is None:
        raise ResolutionError(
          f"{context}: locked evidence repository is unavailable", 3
        )
      reference_lfs_paths = {
        item
        for lfs_object in reference["lfsObjects"]
        for item in lfs_object["paths"]
      }
      if evidence_input["locator"] in reference_lfs_paths:
        raise ResolutionError(
          f"{context}: derived evidence must be stored as a regular Git blob", 3
        )
      evidence_blob, _, evidence_content = _locked_materialized_blob(
        reference,
        evidence_input["locator"],
        context,
      )
      derived_content = _derived_cef_pak_resource(
        payload_content,
        evidence_input,
        context,
      )
      if evidence_content != derived_content:
        raise ResolutionError(
          f"{context}: derived license evidence does not match", 3
        )
      if hashlib.sha256(evidence_content).hexdigest() != evidence_input["sha256"]:
        raise ResolutionError(f"{context}: license evidence digest does not match", 3)
    elif evidence_input["type"] == "font-name":
      name_id = int(evidence_input["locator"].split(":", 1)[1])
      evidence_digests = {
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        for text in _font_name_texts(payload_content, name_id, context)
      }
      if evidence_input["sha256"] not in evidence_digests:
        raise ResolutionError(f"{context}: license evidence digest does not match", 3)
    elif evidence_input["type"] == "zip-member":
      evidence_content = _zip_member_bytes(
        payload_content, evidence_input["locator"], context
      )
      if hashlib.sha256(evidence_content).hexdigest() != evidence_input["sha256"]:
        raise ResolutionError(f"{context}: license evidence digest does not match", 3)
    else:
      locator = evidence_input["locator"]
      evidence_blob = _locked_git_blob(cache, commit, locator, context)
      if locator not in candidate_evidence_paths:
        raise ResolutionError(
          f"{context}: git-blob locator is not a component license candidate",
          3,
        )
      evidence_content = _run_git_bytes(
        ["cat-file", "blob", evidence_blob], cwd=cache
      )
      evidence_content = _materialized_lfs_content(
        cache, locator, evidence_content, lfs_objects, context
      )
      if hashlib.sha256(evidence_content).hexdigest() != evidence_input["sha256"]:
        raise ResolutionError(f"{context}: license evidence digest does not match", 3)
    record = {
      "type": evidence_input["type"],
      "path": path,
      "blob": blob,
      "sha256": hashlib.sha256(content).hexdigest(),
      "locator": evidence_input["locator"],
      "evidenceSha256": evidence_input["sha256"],
    }
    if "licenseRefs" in evidence_input:
      record["licenseRefs"] = list(evidence_input["licenseRefs"])
    if evidence_input["type"] == "repository-git-blob":
      record.update({
        "repository": evidence_input["repository"],
        "referencePath": evidence_input["referencePath"],
        "referenceBlob": reference_blob,
        "referenceSha256": hashlib.sha256(reference_content).hexdigest(),
        "evidenceBlob": evidence_blob,
      })
    elif evidence_input["type"] == "repository-cef-pak-resource":
      record.update({
        "repository": evidence_input["repository"],
        "archiveMember": evidence_input["archiveMember"],
        "resourceId": evidence_input["resourceId"],
        "compression": evidence_input["compression"],
        "evidenceBlob": evidence_blob,
      })
    elif evidence_input["type"] == "git-blob":
      record["evidenceBlob"] = evidence_blob
    records.append(record)
  return records


def repository_license_inventory(
  repository,
  cache,
  commit,
  lfs_objects=None,
  repository_contexts=None,
):
  license_input = repository["license"]
  if license_input["status"] == "declared":
    raise ResolutionError(
      f"{repository['id']}: declared repositories do not need a component inventory",
      2,
    )
  if lfs_objects is None:
    lfs_objects = lfs_objects_at_commit(repository, cache, commit)
  if repository_contexts is None:
    repository_contexts = {
      repository["id"]: {
        "repository": repository,
        "cache": cache,
        "commit": commit,
        "lfsObjects": lfs_objects,
      },
    }
  paths = _paths_at_commit(cache, commit)
  payloads = [
    path
    for path in paths
    if _matches_repository_patterns(path, license_input["payloadPatterns"])
  ]
  if not payloads:
    raise ResolutionError(
      f"{repository['id']}: payload patterns matched no locked files",
      3,
    )
  evidence_paths = [
    path
    for path in paths
    if _matches_repository_patterns(path, license_input.get("patterns", []))
  ]
  evidence_by_component = {}
  for path in evidence_paths:
    evidence_by_component.setdefault(_component_id(path), []).append(path)
  payloads_by_component = {}
  for path in payloads:
    payloads_by_component.setdefault(_component_id(path), []).append(path)

  reviewed_components = {
    component["id"]: component
    for component in license_input.get("reviewedComponents", [])
  }
  blocking_reviews = {
    review["id"]: review
    for review in license_input.get("blockingReviews", [])
  }
  unknown_reviewed = sorted(set(reviewed_components) - set(payloads_by_component))
  if unknown_reviewed:
    raise ResolutionError(
      f"{repository['id']}: reviewed component inventory is stale; "
      f"unknown {unknown_reviewed}",
      3,
    )
  unknown_blocked = sorted(set(blocking_reviews) - set(payloads_by_component))
  if unknown_blocked:
    raise ResolutionError(
      f"{repository['id']}: blocking review inventory is stale; "
      f"unknown {unknown_blocked}",
      3,
    )

  components = []
  actual_unresolved = []
  for component_id in sorted(payloads_by_component):
    component_evidence = evidence_by_component.get(component_id, [])
    reviewed_component = reviewed_components.get(component_id)
    blocking_review = blocking_reviews.get(component_id)
    if reviewed_component is None:
      actual_unresolved.append(component_id)
    component_record = {
      "id": component_id,
      "status": (
        "resolved"
        if reviewed_component is not None
        else "blocked"
        if blocking_review is not None
        else "review-required"
        if component_evidence
        else "unresolved"
      ),
      "payloadPaths": payloads_by_component[component_id],
      "candidateEvidence": [
        _license_evidence(cache, commit, path) for path in component_evidence
      ] if reviewed_component is None else [],
    }
    if blocking_review is not None:
      candidate_paths = set(component_evidence)
      verified_evidence = []
      for evidence_input in blocking_review["evidence"]:
        if evidence_input["path"] not in candidate_paths:
          raise ResolutionError(
            f"{repository['id']}:{component_id}: blocking review evidence is not "
            "a component license candidate",
            3,
          )
        evidence_record = _license_evidence(cache, commit, evidence_input["path"])
        if evidence_record["sha256"] != evidence_input["sha256"]:
          raise ResolutionError(
            f"{repository['id']}:{component_id}: blocking review digest does not match",
            3,
          )
        verified_evidence.append(evidence_record)
      component_record["blockingReview"] = {
        "code": blocking_review["code"],
        "reason": blocking_review["reason"],
        "evidence": verified_evidence,
      }
    if reviewed_component is not None:
      evidence_paths = [record["path"] for record in reviewed_component["evidence"]]
      if sorted(set(evidence_paths)) != payloads_by_component[component_id]:
        raise ResolutionError(
          f"{repository['id']}:{component_id}: reviewed evidence must exactly cover payloads",
          3,
        )
      component_record["license"] = {
        "spdx": reviewed_component["spdx"],
        "evidence": _verified_component_evidence(
          cache,
          commit,
          reviewed_component,
          component_evidence,
          lfs_objects,
          repository_contexts,
        ),
      }
    components.append(component_record)
  if actual_unresolved != license_input["unresolvedComponents"]:
    raise ResolutionError(
      f"{repository['id']}: unresolved component inventory is stale; "
      f"expected {actual_unresolved}",
      3,
    )
  return {
    "repository": repository["id"],
    "commit": commit,
    "tree": _run_git(["rev-parse", commit + "^{tree}"], cwd=cache, exit_code=3),
    "status": (
      "complete"
      if all(component["status"] == "resolved" for component in components)
      else "incomplete"
    ),
    "components": components,
  }


def license_inventory_report(inputs, cache_directory):
  cache_directory = Path(cache_directory).resolve()
  reviewed_paths = {}
  required_repository_ids = set()
  for repository in inputs["repositories"]:
    if repository["license"]["status"] == "declared":
      continue
    required_repository_ids.add(repository["id"])
    for component in repository["license"].get("reviewedComponents", []):
      for evidence in component["evidence"]:
        reviewed_paths.setdefault(repository["id"], set()).add(evidence["path"])
        if evidence["type"] == "git-blob":
          reviewed_paths[repository["id"]].add(evidence["locator"])
        elif evidence["type"] in {
          "repository-cef-pak-resource",
          "repository-git-blob",
        }:
          required_repository_ids.add(evidence["repository"])
          referenced_paths = {evidence["locator"]}
          if evidence["type"] == "repository-git-blob":
            referenced_paths.add(evidence["referencePath"])
          reviewed_paths.setdefault(evidence["repository"], set()).update(
            referenced_paths
          )
  repositories_by_id = {
    repository["id"]: repository for repository in inputs["repositories"]
  }
  repository_contexts = {}
  for repository_id in sorted(required_repository_ids):
    repository = repositories_by_id[repository_id]
    if "commit" not in repository:
      raise ResolutionError(
        f"{repository_id}: incomplete self license input cannot be audited",
        3,
      )
    cache = _repository_cache_path(cache_directory, repository_id)
    if not cache.is_dir():
      raise ResolutionError(f"{repository_id}: license audit cache is missing", 3)
    origin = _run_git(["remote", "get-url", "origin"], cwd=cache, exit_code=3)
    if origin != repository["origin"]:
      raise ResolutionError(
        f"{repository_id}: license audit cache origin does not match policy",
        3,
      )
    lfs_objects = lfs_objects_at_commit(repository, cache, repository["commit"])
    evidence_lfs_objects = [
      item
      for item in lfs_objects
      if reviewed_paths.get(repository_id, set()).intersection(item["paths"])
    ]
    fetch_lfs_objects(
      repository,
      cache,
      repository["commit"],
      evidence_lfs_objects,
    )
    repository_contexts[repository_id] = {
      "repository": repository,
      "cache": cache,
      "commit": repository["commit"],
      "lfsObjects": lfs_objects,
    }
  records = []
  for repository in inputs["repositories"]:
    if repository["license"]["status"] == "declared":
      continue
    context = repository_contexts[repository["id"]]
    records.append(
      repository_license_inventory(
        repository,
        context["cache"],
        repository["commit"],
        context["lfsObjects"],
        repository_contexts,
      )
    )
  if not records:
    raise ResolutionError("license inventory audit selected no incomplete inputs", 2)
  return {
    "schemaVersion": 1,
    "auditType": "source-license-inventory",
    "productVersion": inputs["productVersion"],
    "status": (
      "passed"
      if all(record["status"] == "complete" for record in records)
      else "failed"
    ),
    "repositories": records,
  }


def lfs_public_audit_report(inputs, cache_directory, repository_ids):
  if repository_ids != sorted(set(repository_ids)) or not repository_ids:
    raise ResolutionError(
      "LFS audit repositories must be sorted, unique, and non-empty",
      2,
    )
  repositories = {repository["id"]: repository for repository in inputs["repositories"]}
  cache_directory = Path(cache_directory).resolve()
  records = []
  for repository_id in repository_ids:
    repository = repositories.get(repository_id)
    if repository is None:
      raise ResolutionError(f"{repository_id}: LFS audit repository is not selected", 2)
    if "commit" not in repository:
      raise ResolutionError(f"{repository_id}: self commit cannot be audited from policy", 2)
    cache = _repository_cache_path(cache_directory, repository_id)
    if not cache.is_dir():
      raise ResolutionError(f"{repository_id}: LFS audit cache is missing", 3)
    origin = _run_git(["remote", "get-url", "origin"], cwd=cache, exit_code=3)
    if origin != repository["origin"]:
      raise ResolutionError(
        f"{repository_id}: LFS audit cache origin does not match policy",
        3,
      )
    lfs_objects = lfs_objects_at_commit(repository, cache, repository["commit"])
    if not lfs_objects:
      raise ResolutionError(f"{repository_id}: locked commit has no LFS objects", 2)
    fetch_lfs_objects(repository, cache, repository["commit"], lfs_objects)
    records.append({
      "repository": repository_id,
      "origin": repository["origin"],
      "commit": repository["commit"],
      "tree": _run_git(
        ["rev-parse", repository["commit"] + "^{tree}"],
        cwd=cache,
        exit_code=3,
      ),
      "repositoryAuthentication": "none",
      "objectCount": len(lfs_objects),
      "totalBytes": sum(item["size"] for item in lfs_objects),
      "objects": lfs_objects,
    })
  return {
    "schemaVersion": 1,
    "auditType": "source-lfs-public",
    "productVersion": inputs["productVersion"],
    "status": "passed",
    "repositories": records,
  }


def _anonymous_git_environment():
  environment = {
    "GCM_INTERACTIVE": "Never",
    "GIT_ASKPASS": "",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "SSH_ASKPASS": "",
  }
  for key in os.environ:
    if (
      key == "GIT_CONFIG_COUNT"
      or key == "GIT_CONFIG_PARAMETERS"
      or re.fullmatch(r"GIT_CONFIG_(?:KEY|VALUE)_[0-9]+", key)
    ):
      environment[key] = None
  return environment


def _run_anonymous_git(arguments, cwd=None, exit_code=4):
  return _run_git(
    [
      "-c",
      "credential.helper=",
      "-c",
      "core.askPass=",
      "-c",
      "http.extraHeader=",
      *arguments,
    ],
    cwd=cwd,
    exit_code=exit_code,
    environment=_anonymous_git_environment(),
  )


def verify_public_mirror(repository):
  output = _run_anonymous_git(
    ["ls-remote", "--refs", repository["origin"]],
    exit_code=3,
  )
  if not output:
    raise ResolutionError(
      f"{repository['id']}: project mirror is not anonymously readable",
      3,
    )


def _repository_cache_path(cache_directory, repository_id):
  return Path(cache_directory).resolve() / "git" / (repository_id + ".git")


def _mirror_refs_digest(cache):
  output = _run_git(["show-ref"], cwd=cache, exit_code=3)
  return hashlib.sha256(output.encode("utf-8")).hexdigest()


def _fsck_state_path(cache_directory, repository_id):
  return Path(cache_directory) / "fsck-state" / f"{repository_id}.json"


def sync_cache(repository, cache_directory, commit=None):
  verify_public_mirror(repository)
  cache = _repository_cache_path(cache_directory, repository["id"])
  cache.parent.mkdir(parents=True, exist_ok=True)
  if cache.exists():
    if _run_git(["rev-parse", "--is-bare-repository"], cwd=cache) != "true":
      raise ResolutionError(f"{cache}: expected bare Git cache")
    origin = _run_git(["remote", "get-url", "origin"], cwd=cache)
    if origin != repository["origin"]:
      raise ResolutionError(f"{cache}: origin does not match the source policy")
    _run_anonymous_git([
      "fetch",
      "--prune",
      "origin",
      "+refs/heads/*:refs/heads/*",
      "+refs/tags/*:refs/tags/*",
    ], cwd=cache)
  else:
    _run_anonymous_git(["clone", "--mirror", repository["origin"], str(cache)])
  if commit:
    _run_anonymous_git(
      ["fetch", "--no-tags", "origin", commit],
      cwd=cache,
      exit_code=3,
    )
  # The mirror refs digest changes whenever a fetch moves any reference,
  # so a previously verified mirror with an unchanged ref set can reuse
  # its fsck result. Disk corruption between runs is not covered by this
  # cache; a fresh cache directory or any ref change re-runs the check.
  state_path = _fsck_state_path(cache_directory, repository["id"])
  digest = _mirror_refs_digest(cache)
  state = None
  if state_path.is_file():
    try:
      state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
      state = None
  if (
    state
    and state.get("refsDigest") == digest
    and state.get("fsck") == "ok"
  ):
    return cache
  _run_git(["fsck", "--full", "--strict"], cwd=cache)
  state_path.parent.mkdir(parents=True, exist_ok=True)
  state_path.write_text(
    json.dumps({"refsDigest": digest, "fsck": "ok"}, sort_keys=True),
    encoding="utf-8",
  )
  return cache


def _parse_lfs_pointer(content, repository_id, path):
  if len(content) > 1024 or not content.startswith(
    b"version https://git-lfs.github.com/spec/v1\n"
  ):
    return None
  try:
    lines = content.decode("utf-8").splitlines()
  except UnicodeDecodeError as error:
    raise ResolutionError(
      f"{repository_id}:{path}: invalid Git LFS pointer encoding",
      3,
    ) from error
  fields = {}
  for line in lines[1:]:
    name, separator, value = line.partition(" ")
    if not separator or name in fields:
      raise ResolutionError(
        f"{repository_id}:{path}: malformed Git LFS pointer",
        3,
      )
    fields[name] = value
  if set(fields) != {"oid", "size"}:
    raise ResolutionError(
      f"{repository_id}:{path}: unsupported Git LFS pointer fields",
      3,
    )
  algorithm, separator, oid = fields["oid"].partition(":")
  if not separator or algorithm != "sha256" or not SHA256_PATTERN.fullmatch(oid):
    raise ResolutionError(
      f"{repository_id}:{path}: invalid Git LFS object id",
      3,
    )
  if not re.fullmatch(r"0|[1-9][0-9]*", fields["size"]):
    raise ResolutionError(
      f"{repository_id}:{path}: invalid Git LFS object size",
      3,
    )
  size = int(fields["size"])
  canonical = (
    "version https://git-lfs.github.com/spec/v1\n"
    f"oid sha256:{oid}\n"
    f"size {size}\n"
  ).encode("ascii")
  if content != canonical:
    raise ResolutionError(
      f"{repository_id}:{path}: Git LFS pointer is not canonical",
      3,
    )
  return oid, size


def lfs_objects_at_commit(repository, cache, commit):
  result = _run_git_process([
    "grep",
    "-l",
    "-z",
    "-F",
    "version https://git-lfs.github.com/spec/v1",
    commit,
    "--",
  ], cwd=cache)
  if result.returncode not in (0, 1):
    detail = result.stderr.decode("utf-8", errors="replace").strip()
    raise ResolutionError(detail or "git grep failed", 3)
  prefix = (commit + ":").encode("ascii")
  objects = {}
  for item in result.stdout.split(b"\0"):
    if not item:
      continue
    if not item.startswith(prefix):
      raise ResolutionError(
        f"{repository['id']}: unexpected Git LFS path record",
        3,
      )
    try:
      path = item[len(prefix):].decode("utf-8")
    except UnicodeDecodeError as error:
      raise ResolutionError(
        f"{repository['id']}: Git LFS path is not UTF-8",
        3,
      ) from error
    _validate_relative_path(path, f"{repository['id']}.lfsObjects.path")
    pointer = _parse_lfs_pointer(
      _run_git_bytes(["show", f"{commit}:{path}"], cwd=cache),
      repository["id"],
      path,
    )
    if pointer is None:
      continue
    oid, size = pointer
    record = objects.setdefault(oid, {"oid": oid, "size": size, "paths": []})
    if record["size"] != size:
      raise ResolutionError(
        f"{repository['id']}:{path}: Git LFS object size is inconsistent",
        3,
      )
    record["paths"].append(path)
  records = list(objects.values())
  for record in records:
    record["paths"].sort()
  return sorted(records, key=lambda record: record["oid"])


def _lfs_endpoint(origin):
  return origin + "/info/lfs"


def _lfs_object_path(git_directory, oid):
  return Path(git_directory) / "lfs" / "objects" / oid[:2] / oid[2:4] / oid


def _lfs_storage_object_path(storage, oid):
  return Path(storage) / "objects" / oid[:2] / oid[2:4] / oid


def _git_directory(repository):
  git_directory = Path(_run_git(["rev-parse", "--git-dir"], cwd=repository))
  if not git_directory.is_absolute():
    git_directory = Path(repository) / git_directory
  return git_directory


def _materialized_lfs_content(cache, path, git_content, lfs_objects, context):
  matches = [item for item in lfs_objects if path in item["paths"]]
  if not matches:
    return git_content
  if len(matches) != 1:
    raise ResolutionError(f"{context}: ambiguous Git LFS payload", 3)
  lfs_object = matches[0]
  local_object = _lfs_object_path(_git_directory(cache), lfs_object["oid"])
  if not local_object.is_file():
    raise ResolutionError(
      f"{context}: locked Git LFS object is missing: {lfs_object['oid']}", 3
    )
  if local_object.stat().st_size != lfs_object["size"]:
    raise ResolutionError(f"{context}: Git LFS object size does not match", 3)
  content = local_object.read_bytes()
  if hashlib.sha256(content).hexdigest() != lfs_object["oid"]:
    raise ResolutionError(f"{context}: Git LFS object digest does not match", 3)
  return content


def _sha256_file(path):
  digest = hashlib.sha256()
  with Path(path).open("rb") as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
      digest.update(chunk)
  return digest.hexdigest()


def _verify_lfs_objects(repository, lfs_objects, object_path):
  for lfs_object in lfs_objects:
    local_object = object_path(lfs_object["oid"])
    if not local_object.is_file():
      raise ResolutionError(
        f"{repository['id']}: locked Git LFS object is missing: {lfs_object['oid']}",
        3,
      )
    if local_object.stat().st_size != lfs_object["size"]:
      raise ResolutionError(
        f"{repository['id']}: Git LFS object size does not match: {lfs_object['oid']}",
        3,
      )
    digest = _sha256_file(local_object)
    if digest != lfs_object["oid"]:
      raise ResolutionError(
        f"{repository['id']}: Git LFS object digest does not match: {lfs_object['oid']}",
        3,
      )


def _verify_lfs_cache(repository, cache, lfs_objects):
  _verify_lfs_objects(
    repository,
    lfs_objects,
    lambda oid: _lfs_object_path(cache, oid),
  )


def _anonymous_url_opener():
  return urllib.request.build_opener()


def _read_limited_response(response, maximum_bytes, description):
  content = response.read(maximum_bytes + 1)
  if len(content) > maximum_bytes:
    raise ResolutionError(f"{description}: response exceeds size limit", 3)
  return content


def _open_anonymous_request(request, description):
  for attempt in range(3):
    try:
      response = _anonymous_url_opener().open(request, timeout=120)
      _validate_https(response.geturl(), description + ".finalUrl")
      return response
    except urllib.error.HTTPError as error:
      if attempt < 2 and (error.code == 429 or error.code >= 500):
        time.sleep(attempt + 1)
        continue
      raise AnonymousHttpError(f"{description}: HTTP {error.code}", error.code) from error
    except (urllib.error.URLError, OSError) as error:
      if attempt < 2:
        time.sleep(attempt + 1)
        continue
      raise ResolutionError(f"{description}: anonymous request failed", 3) from error


def _fetch_anonymous_lfs_actions(repository, lfs_objects):
  endpoint = _lfs_endpoint(repository["origin"]) + "/objects/batch"
  _validate_https(endpoint, f"{repository['id']}.lfsBatchEndpoint")
  request_body = json.dumps(
    {
      "operation": "download",
      "transfers": ["basic"],
      "objects": [
        {"oid": item["oid"], "size": item["size"]} for item in lfs_objects
      ],
    },
    ensure_ascii=True,
    separators=(",", ":"),
    sort_keys=True,
  ).encode("ascii")
  request = urllib.request.Request(
    endpoint,
    data=request_body,
    method="POST",
    headers={
      "Accept": "application/vnd.git-lfs+json",
      "Content-Type": "application/vnd.git-lfs+json",
      "User-Agent": "JetOnlyOffice-Source-Resolver/1",
    },
  )
  with _open_anonymous_request(request, f"{repository['id']}: Git LFS batch") as response:
    content = _read_limited_response(
      response,
      4 * 1024 * 1024,
      f"{repository['id']}: Git LFS batch",
    )
  try:
    result = json.loads(content.decode("utf-8"))
  except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise ResolutionError(
      f"{repository['id']}: invalid Git LFS batch response",
      3,
    ) from error
  if not isinstance(result, dict) or not isinstance(result.get("objects"), list):
    raise ResolutionError(f"{repository['id']}: invalid Git LFS batch response", 3)

  expected = {item["oid"]: item for item in lfs_objects}
  actions = {}
  for item in result["objects"]:
    if not isinstance(item, dict):
      raise ResolutionError(f"{repository['id']}: invalid Git LFS object response", 3)
    oid = item.get("oid")
    if oid not in expected or oid in actions or item.get("size") != expected[oid]["size"]:
      raise ResolutionError(f"{repository['id']}: Git LFS batch identity mismatch", 3)
    if "error" in item:
      error = item["error"] if isinstance(item["error"], dict) else {}
      code = error.get("code", "unknown")
      raise ResolutionError(
        f"{repository['id']}: Git LFS object is not anonymously readable: {oid} ({code})",
        3,
      )
    download = item.get("actions", {}).get("download")
    if not isinstance(download, dict) or not isinstance(download.get("href"), str):
      raise ResolutionError(
        f"{repository['id']}: Git LFS download action is missing: {oid}",
        3,
      )
    _validate_https(download["href"], f"{repository['id']}.lfsDownload")
    headers = download.get("header", {})
    if not isinstance(headers, dict) or not all(
      isinstance(key, str) and isinstance(value, str)
      for key, value in headers.items()
    ):
      raise ResolutionError(
        f"{repository['id']}: invalid Git LFS download headers: {oid}",
        3,
      )
    expires_at = download.get("expires_at")
    if expires_at is not None and not isinstance(expires_at, str):
      raise ResolutionError(
        f"{repository['id']}: invalid Git LFS download expiry: {oid}",
        3,
      )
    expires_in = download.get("expires_in")
    if (
      expires_in is not None
      and (not isinstance(expires_in, int) or isinstance(expires_in, bool) or expires_in < 0)
    ):
      raise ResolutionError(
        f"{repository['id']}: invalid Git LFS download expiry: {oid}",
        3,
      )
    actions[oid] = {
      "href": download["href"],
      "headers": headers,
      **({"expiresAt": expires_at} if expires_at is not None else {}),
      **({"expiresIn": expires_in} if expires_in is not None else {}),
      "fetchedAt": time.time(),
    }
  if set(actions) != set(expected):
    raise ResolutionError(f"{repository['id']}: incomplete Git LFS batch response", 3)
  return actions


def _download_anonymous_lfs_object_once(repository, lfs_object, action, destination):
  request = urllib.request.Request(
    action["href"],
    method="GET",
    headers={
      **action["headers"],
      "User-Agent": "JetOnlyOffice-Source-Resolver/1",
    },
  )
  destination = Path(destination)
  destination.parent.mkdir(parents=True, exist_ok=True)
  digest = hashlib.sha256()
  size = 0
  try:
    response = _open_anonymous_request(
      request,
      f"{repository['id']}: Git LFS object {lfs_object['oid']}",
    )
  except AnonymousHttpError as error:
    if error.status_code in (401, 403):
      raise LfsActionRefreshRequired(
        f"{repository['id']}: Git LFS download action was rejected"
      ) from error
    raise
  with response:
    with destination.open("wb") as output:
      while True:
        chunk = response.read(1024 * 1024)
        if not chunk:
          break
        output.write(chunk)
        digest.update(chunk)
        size += len(chunk)
        if size > lfs_object["size"]:
          raise ResolutionError(
            f"{repository['id']}: Git LFS object exceeds locked size: "
            f"{lfs_object['oid']}",
            3,
          )
  if size != lfs_object["size"] or digest.hexdigest() != lfs_object["oid"]:
    raise ResolutionError(
      f"{repository['id']}: downloaded Git LFS object does not match lock: "
      f"{lfs_object['oid']}",
      3,
    )


def _download_anonymous_lfs_object(repository, lfs_object, action, destination):
  for attempt in range(3):
    try:
      _download_anonymous_lfs_object_once(
        repository,
        lfs_object,
        action,
        destination,
      )
      return
    except (OSError, ResolutionError):
      if attempt == 2:
        raise
      time.sleep(attempt + 1)


def _lfs_action_is_expired(action):
  expires_in = action.get("expiresIn")
  if expires_in is not None:
    return time.time() >= action["fetchedAt"] + max(0, expires_in - 5)
  expires_at = action.get("expiresAt")
  if expires_at is None:
    return False
  try:
    from datetime import datetime, timezone

    normalized = expires_at[:-1] + "+00:00" if expires_at.endswith("Z") else expires_at
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
      raise ValueError("timezone is required")
    expiration = parsed.astimezone(timezone.utc).timestamp()
  except ValueError as error:
    raise ResolutionError("invalid Git LFS download expires_at", 3) from error
  return time.time() >= expiration - 5


def fetch_lfs_objects(repository, cache, commit, lfs_objects):
  if not lfs_objects:
    return
  with tempfile.TemporaryDirectory(prefix="jetonlyoffice-lfs-") as directory:
    storage = Path(directory)
    for lfs_object in lfs_objects:
      for attempt in range(3):
        try:
          actions = _fetch_anonymous_lfs_actions(repository, [lfs_object])
        except ResolutionError as error:
          if attempt == 2 or "Git LFS batch" not in str(error):
            raise
          time.sleep(attempt + 1)
          continue
        action = actions[lfs_object["oid"]]
        if _lfs_action_is_expired(action):
          if attempt == 2:
            raise ResolutionError(
              f"{repository['id']}: Git LFS download action repeatedly expired",
              3,
            )
          continue
        try:
          _download_anonymous_lfs_object(
            repository,
            lfs_object,
            action,
            _lfs_storage_object_path(storage, lfs_object["oid"]),
          )
          break
        except LfsActionRefreshRequired:
          if attempt == 2:
            raise
        except ResolutionError as error:
          if attempt == 2:
            raise
          if not str(error).startswith(
            f"{repository['id']}: downloaded Git LFS object"
          ):
            raise
      else:
        raise ResolutionError(
          f"{repository['id']}: Git LFS object download did not complete",
          3,
        )
    _verify_lfs_objects(
      repository,
      lfs_objects,
      lambda oid: _lfs_storage_object_path(storage, oid),
    )
    for lfs_object in lfs_objects:
      downloaded = _lfs_storage_object_path(storage, lfs_object["oid"])
      cached = _lfs_object_path(cache, lfs_object["oid"])
      cached.parent.mkdir(parents=True, exist_ok=True)
      shutil.copyfile(downloaded, cached)
  _verify_lfs_cache(repository, cache, lfs_objects)


def resolve_self_commit(self_root, expected_origin):
  self_root = Path(self_root).resolve()
  verify_git_index_flags(self_root)
  if _run_git(["status", "--porcelain", "--untracked-files=all"], cwd=self_root):
    raise ResolutionError("build-tools self checkout must be clean")
  origin = _run_git(["remote", "get-url", "origin"], cwd=self_root)
  if origin != expected_origin:
    raise ResolutionError("build-tools self checkout origin does not match the source policy")
  commit = _run_git(["rev-parse", "HEAD^{commit}"], cwd=self_root)
  if not SHA1_PATTERN.fullmatch(commit):
    raise ResolutionError("build-tools self checkout did not resolve to a full commit")
  return commit


def verify_selections(inputs, caches, commits):
  records = []
  relationships = {
    (relationship["child"], relationship["parent"], relationship["path"]): relationship
    for relationship in inputs["relationships"]
  }
  for repository in inputs["repositories"]:
    repository_id = repository["id"]
    if repository_id not in commits:
      raise ResolutionError(f"{repository_id}: selection commit is unavailable", 3)
    selection = repository["selection"]
    selection_type = selection["type"]
    commit = commits[repository_id]
    record = {
      "repository": repository_id,
      "type": selection_type,
      "commit": commit,
    }

    if selection_type == "self":
      records.append(record)
      continue

    if repository_id not in caches:
      raise ResolutionError(f"{repository_id}: selection cache is unavailable", 3)
    cache = caches[repository_id]
    if selection_type == "branch":
      try:
        resolved = _run_git(
          ["rev-parse", selection["ref"] + "^{commit}"],
          cwd=cache,
          exit_code=3,
        )
      except ResolutionError as error:
        raise ResolutionError(
          f"{repository_id}: locked branch is unavailable: {selection['ref']}",
          3,
        ) from error
      if resolved != commit:
        raise ResolutionError(
          f"{repository_id}: branch does not resolve to the locked commit",
          3,
        )
      record["ref"] = selection["ref"]
    elif selection_type == "tag":
      try:
        resolved = _run_git(
          ["rev-parse", selection["ref"] + "^{commit}"],
          cwd=cache,
          exit_code=3,
        )
      except ResolutionError as error:
        raise ResolutionError(
          f"{repository_id}: locked tag is unavailable: {selection['ref']}",
          3,
        ) from error
      if resolved != commit:
        raise ResolutionError(
          f"{repository_id}: tag does not resolve to the locked commit",
          3,
        )
      record["ref"] = selection["ref"]
    elif selection_type == "gitlink":
      key = (repository_id, selection["parent"], selection["path"])
      if key not in relationships:
        raise ResolutionError(
          f"{repository_id}: selection does not match a declared gitlink",
          3,
        )
      parent = selection["parent"]
      if parent not in caches or parent not in commits:
        raise ResolutionError(
          f"{repository_id}: gitlink parent is unavailable",
          3,
        )
      output = _run_git(
        ["ls-tree", commits[parent], "--", selection["path"]],
        cwd=caches[parent],
        exit_code=3,
      )
      fields = output.split(None, 3)
      if (
        len(fields) != 4
        or fields[0] != "160000"
        or fields[1] != "commit"
        or fields[2] != commit
        or fields[3] != selection["path"]
      ):
        raise ResolutionError(
          f"{repository_id}: gitlink does not resolve to the locked commit",
          3,
        )
      record["parent"] = parent
      record["path"] = selection["path"]
    elif selection_type == "cutoff":
      prefix = selection["refPrefix"]
      refs = _run_git(
        ["for-each-ref", "--format=%(refname)", prefix],
        cwd=cache,
        exit_code=3,
      ).splitlines()
      refs = sorted(ref for ref in refs if ref.startswith(prefix))
      if not refs:
        raise ResolutionError(
          f"{repository_id}: official upstream heads are unavailable",
          3,
        )
      output = _run_git(
        [
          "rev-list",
          "--timestamp",
          f"--before=@{inputs['releaseCutoff']}",
          *refs,
        ],
        cwd=cache,
        exit_code=3,
      )
      candidates = []
      for line in output.splitlines():
        timestamp, separator, candidate = line.partition(" ")
        if not separator or not timestamp.isdigit() or not SHA1_PATTERN.fullmatch(candidate):
          raise ResolutionError(
            f"{repository_id}: cutoff selection returned malformed history",
            3,
          )
        candidates.append((int(timestamp), candidate))
      if not candidates:
        raise ResolutionError(
          f"{repository_id}: no upstream commit exists before the release cutoff",
          3,
        )
      selected_time, selected_commit = max(candidates)
      if selected_commit != commit:
        raise ResolutionError(
          f"{repository_id}: cutoff does not resolve to the locked commit",
          3,
        )
      containing_refs = _run_git(
        ["for-each-ref", "--contains", commit, "--format=%(refname)", prefix],
        cwd=cache,
        exit_code=3,
      ).splitlines()
      containing_refs = sorted(ref for ref in containing_refs if ref.startswith(prefix))
      if not containing_refs:
        raise ResolutionError(
          f"{repository_id}: cutoff commit is not reachable from an upstream head",
          3,
        )
      record["refPrefix"] = prefix
      record["releaseCutoff"] = inputs["releaseCutoff"]
      record["resolvedRef"] = containing_refs[0]
      record["commitTime"] = selected_time
    records.append(record)
  return records


def selection_audit_report(inputs, cache_directory, self_root):
  self_repository = next(
    repository
    for repository in inputs["repositories"]
    if repository.get("commitSource") == "self"
  )
  self_commit = resolve_self_commit(self_root, self_repository["origin"])
  caches = {}
  commits = {}
  for repository in inputs["repositories"]:
    commit = self_commit if repository.get("commitSource") == "self" else repository["commit"]
    commits[repository["id"]] = commit
    if repository.get("commitSource") != "self":
      caches[repository["id"]] = sync_cache(repository, cache_directory, commit)
  records = verify_selections(inputs, caches, commits)
  verify_relationships(inputs, caches, commits)
  return {
    "schemaVersion": 1,
    "auditType": "source-selection",
    "productVersion": inputs["productVersion"],
    "releaseCutoff": inputs["releaseCutoff"],
    "status": "passed",
    "repositories": records,
  }


def repository_metadata(repository, cache, commit, repository_contexts=None):
  _run_git(["cat-file", "-e", commit + "^{commit}"], cwd=cache, exit_code=3)
  tree = _run_git(["rev-parse", commit + "^{tree}"], cwd=cache, exit_code=3)
  commit_time_text = _run_git(["show", "-s", "--format=%ct", commit], cwd=cache, exit_code=3)
  try:
    commit_time = int(commit_time_text)
  except ValueError as error:
    raise ResolutionError(f"{repository['id']}: invalid commit timestamp", 3) from error
  lfs_objects = lfs_objects_at_commit(repository, cache, commit)
  license_record = repository_license_metadata(
    repository,
    cache,
    commit,
    lfs_objects,
    repository_contexts,
  )
  return {
    "id": repository["id"],
    "role": repository["role"],
    "checkoutPath": repository["checkoutPath"],
    "origin": repository["origin"],
    "upstream": repository["upstream"],
    "commit": commit,
    "tree": tree,
    "commitTime": commit_time,
    "refHint": repository["refHint"],
    "projectFork": repository["projectFork"],
    "buildInput": repository["buildInput"],
    "active": repository["active"],
    "lfsObjects": lfs_objects,
    "license": license_record,
  }


def _git_blob_metadata(cache, object_ids, retained_object_ids):
  records = {}
  process = subprocess.Popen(
    ["git", "cat-file", "--batch"],
    cwd=cache,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
  )
  try:
    for object_id in sorted(set(object_ids)):
      process.stdin.write((object_id + "\n").encode("ascii"))
      process.stdin.flush()
      header = process.stdout.readline()
      fields = header.rstrip(b"\n").split(b" ")
      if (
        len(fields) != 3
        or fields[0] != object_id.encode("ascii")
        or fields[1] != b"blob"
        or not fields[2].isdigit()
      ):
        raise ResolutionError(
          f"{cache}: invalid Git batch response for {object_id}", 3
        )
      size = int(fields[2])
      digest = hashlib.sha256()
      retained = bytearray() if object_id in retained_object_ids else None
      remaining = size
      while remaining:
        chunk = process.stdout.read(min(1024 * 1024, remaining))
        if not chunk:
          raise ResolutionError(
            f"{cache}: truncated Git blob {object_id}", 3
          )
        digest.update(chunk)
        if retained is not None:
          retained.extend(chunk)
        remaining -= len(chunk)
      if process.stdout.read(1) != b"\n":
        raise ResolutionError(
          f"{cache}: invalid Git batch terminator for {object_id}", 3
        )
      records[object_id] = {
        "size": size,
        "sha256": digest.hexdigest(),
        **({"content": bytes(retained)} if retained is not None else {}),
      }
    process.stdin.close()
    stderr = process.stderr.read()
    return_code = process.wait()
    if return_code != 0:
      detail = stderr.decode("utf-8", errors="replace").strip()
      raise ResolutionError(detail or "git cat-file --batch failed", 3)
  except (OSError, BrokenPipeError) as error:
    process.kill()
    process.wait()
    raise ResolutionError(f"{cache}: cannot read Git objects: {error}", 3) from error
  except Exception:
    process.kill()
    process.wait()
    raise
  finally:
    if process.stdin and not process.stdin.closed:
      process.stdin.close()
    if process.stdout:
      process.stdout.close()
    if process.stderr:
      process.stderr.close()
  return records


def repository_tree_manifest(repository, cache):
  commit = repository["commit"]
  output = _run_git_bytes(
    ["ls-tree", "-r", "-t", "-z", "--full-tree", commit],
    cwd=cache,
  )
  raw_entries = []
  blob_ids = []
  for raw_entry in output.split(b"\0"):
    if not raw_entry:
      continue
    metadata, separator, raw_path = raw_entry.partition(b"\t")
    fields = metadata.split(b" ")
    if not separator or len(fields) != 3:
      raise ResolutionError(
        f"{repository['id']}: malformed Git tree entry", 3
      )
    try:
      mode, object_type, object_id = (
        field.decode("ascii") for field in fields
      )
      path = raw_path.decode("utf-8")
    except UnicodeDecodeError as error:
      raise ResolutionError(
        f"{repository['id']}: Git tree entry is not UTF-8", 3
      ) from error
    _validate_relative_path(path, f"{repository['id']}.sourceTree.path")
    expected_type = {
      "040000": "tree",
      "100644": "blob",
      "100755": "blob",
      "120000": "blob",
      "160000": "commit",
    }.get(mode)
    if expected_type is None or object_type != expected_type \
        or not SHA1_PATTERN.fullmatch(object_id):
      raise ResolutionError(
        f"{repository['id']}:{path}: unsupported Git tree entry", 3
      )
    raw_entries.append((path, mode, object_id))
    if object_type == "blob":
      blob_ids.append(object_id)

  lfs_by_path = {
    path: lfs_object
    for lfs_object in repository["lfsObjects"]
    for path in lfs_object["paths"]
  }
  blob_by_path = {
    path: object_id
    for path, mode, object_id in raw_entries
    if mode in {"100644", "100755", "120000"}
  }
  missing_lfs_paths = sorted(set(lfs_by_path) - set(blob_by_path))
  if missing_lfs_paths:
    raise ResolutionError(
      f"{repository['id']}: LFS paths are absent from the Git tree: "
      + ", ".join(missing_lfs_paths),
      3,
    )
  retained = {blob_by_path[path] for path in lfs_by_path}
  blob_records = _git_blob_metadata(cache, blob_ids, retained)
  entries = []
  for path, mode, object_id in raw_entries:
    if mode == "040000":
      record = {
        "path": path, "type": "directory", "mode": mode, "oid": object_id,
      }
    elif mode == "160000":
      record = {
        "path": path, "type": "gitlink", "mode": mode, "oid": object_id,
      }
    else:
      blob = blob_records[object_id]
      record = {
        "path": path,
        "type": "symlink" if mode == "120000" else "file",
        "mode": mode,
        "oid": object_id,
        "size": blob["size"],
        "sha256": blob["sha256"],
      }
      if path in lfs_by_path:
        if mode not in {"100644", "100755"}:
          raise ResolutionError(
            f"{repository['id']}:{path}: LFS pointer must be a regular file",
            3,
          )
        lfs_object = lfs_by_path[path]
        pointer = _parse_lfs_pointer(
          blob["content"], repository["id"], path
        )
        if pointer != (lfs_object["oid"], lfs_object["size"]):
          raise ResolutionError(
            f"{repository['id']}:{path}: LFS pointer does not match the lock",
            3,
          )
        record["materialized"] = {
          "size": lfs_object["size"],
          "sha256": lfs_object["oid"],
        }
    entries.append(record)
  return {
    "id": repository["id"],
    "checkoutPath": repository["checkoutPath"],
    "commit": commit,
    "tree": repository["tree"],
    "entries": sorted(entries, key=lambda item: item["path"]),
  }


def source_tree_manifest(repositories, caches):
  return {
    "schemaVersion": 1,
    "manifestType": "source-tree",
    "repositories": [
      repository_tree_manifest(repository, caches[repository["id"]])
      for repository in sorted(repositories, key=lambda item: item["id"])
    ],
  }


def source_tree_manifest_payload(repositories, caches):
  return canonical_json_bytes(source_tree_manifest(repositories, caches)) + b"\n"


def bind_source_tree_manifest(lock, caches):
  payload = source_tree_manifest_payload(lock["repositories"], caches)
  lock["sourceTreeManifest"] = {
    "path": SOURCE_TREE_MANIFEST_PATH,
    "size": len(payload),
    "sha256": hashlib.sha256(payload).hexdigest(),
  }
  return payload


def _declared_license_metadata(license_record, cache, commit, lfs_objects):
  license_path = license_record["path"]
  context = f"{license_path}:license"
  blob = _locked_git_blob(cache, commit, license_path, context)
  content = _run_git_bytes(["cat-file", "blob", blob], cwd=cache)
  metadata = {
    "path": license_path,
    "blob": blob,
    "sha256": hashlib.sha256(content).hexdigest(),
    "spdx": license_record["spdx"],
  }
  materialized = _materialized_lfs_content(
    cache, license_path, content, lfs_objects, context
  )
  if materialized != content:
    metadata["materializedSha256"] = hashlib.sha256(materialized).hexdigest()
  return metadata


def _component_license_metadata(
  repository,
  cache,
  commit,
  lfs_objects,
  repository_contexts,
):
  license_input = repository["license"]
  inventory = repository_license_inventory(
    repository,
    cache,
    commit,
    lfs_objects,
    repository_contexts,
  )
  if inventory["status"] != "complete":
    raise ResolutionError(f"LICENSE_INCOMPLETE: {repository['id']}", 3)
  return {
    "scope": "component",
    "payloadPatterns": list(license_input["payloadPatterns"]),
    "components": [
      {
        "id": component["id"],
        "payloadPaths": list(component["payloadPaths"]),
        "license": {
          "spdx": component["license"]["spdx"],
          "evidence": [dict(record) for record in component["license"]["evidence"]],
        },
      }
      for component in inventory["components"]
    ],
  }


def _verify_locked_component_evidence_mapping(
  evidence,
  component_id,
  spdx,
  repository_contexts,
  context,
):
  reference = repository_contexts.get(evidence["repository"])
  if reference is None:
    raise ResolutionError(f"{context}: locked evidence repository is unavailable", 3)
  reference_lfs_paths = {
    item
    for lfs_object in reference["lfsObjects"]
    for item in lfs_object["paths"]
  }
  if evidence["locator"] in reference_lfs_paths or (
    evidence["type"] == "repository-git-blob"
    and evidence["referencePath"] in reference_lfs_paths
  ):
    raise ResolutionError(
      f"{context}: repository evidence must be stored as regular Git blobs", 3
    )
  license_record = reference["repository"]["license"]
  if license_record.get("scope") != "component":
    raise ResolutionError(f"{context}: evidence repository is not component-scoped", 3)
  component = next(
    (item for item in license_record["components"] if item["id"] == component_id),
    None,
  )
  if component is None or component["license"]["spdx"] != spdx:
    raise ResolutionError(f"{context}: referenced component license does not match", 3)
  matching = [
    item
    for item in component["license"]["evidence"]
    if item["type"] == "git-blob"
    and item["path"] == (
      evidence["referencePath"]
      if evidence["type"] == "repository-git-blob"
      else evidence["locator"]
    )
    and item["locator"] == evidence["locator"]
    and item["evidenceSha256"] == evidence["evidenceSha256"]
    and item["blob"] == (
      evidence["referenceBlob"]
      if evidence["type"] == "repository-git-blob"
      else evidence["evidenceBlob"]
    )
  ]
  if len(matching) != 1:
    raise ResolutionError(f"{context}: referenced component mapping does not match", 3)
  return reference


def _verify_locked_component_evidence(
  evidence,
  component_id,
  spdx,
  repository_context,
  repository_contexts,
):
  cache = repository_context["cache"]
  commit = repository_context["commit"]
  lfs_objects = repository_context["lfsObjects"]
  context = f"{evidence['path']}:{evidence['locator']}"
  blob = _locked_git_blob(cache, commit, evidence["path"], context)
  if blob != evidence["blob"]:
    raise ResolutionError(f"{context}: payload blob does not match the lock", 3)
  content = _run_git_bytes(["cat-file", "blob", blob], cwd=cache)
  if hashlib.sha256(content).hexdigest() != evidence["sha256"]:
    raise ResolutionError(f"{context}: payload digest does not match the lock", 3)
  payload_content = _materialized_lfs_content(
    cache, evidence["path"], content, lfs_objects, context
  )
  if evidence["type"] == "repository-git-blob":
    reference = _verify_locked_component_evidence_mapping(
      evidence,
      component_id,
      spdx,
      repository_contexts,
      context,
    )
    reference_blob, _, reference_content = _locked_materialized_blob(
      reference,
      evidence["referencePath"],
      context,
    )
    if reference_blob != evidence["referenceBlob"]:
      raise ResolutionError(f"{context}: referenced payload blob does not match", 3)
    if hashlib.sha256(reference_content).hexdigest() != evidence["referenceSha256"]:
      raise ResolutionError(f"{context}: referenced payload digest does not match", 3)
    if reference_content != payload_content:
      raise ResolutionError(f"{context}: referenced payload bytes do not match", 3)
    evidence_blob, _, evidence_content = _locked_materialized_blob(
      reference,
      evidence["locator"],
      context,
    )
    if evidence_blob != evidence["evidenceBlob"]:
      raise ResolutionError(f"{context}: license evidence blob does not match", 3)
    if hashlib.sha256(evidence_content).hexdigest() != evidence["evidenceSha256"]:
      raise ResolutionError(f"{context}: license evidence digest does not match", 3)
  elif evidence["type"] == "repository-cef-pak-resource":
    reference = _verify_locked_component_evidence_mapping(
      evidence,
      component_id,
      spdx,
      repository_contexts,
      context,
    )
    evidence_blob, _, evidence_content = _locked_materialized_blob(
      reference,
      evidence["locator"],
      context,
    )
    if evidence_blob != evidence["evidenceBlob"]:
      raise ResolutionError(f"{context}: license evidence blob does not match", 3)
    derived_content = _derived_cef_pak_resource(
      payload_content,
      evidence,
      context,
    )
    if evidence_content != derived_content:
      raise ResolutionError(
        f"{context}: derived license evidence does not match", 3
      )
    if hashlib.sha256(evidence_content).hexdigest() != evidence["evidenceSha256"]:
      raise ResolutionError(f"{context}: license evidence digest does not match", 3)
  elif evidence["type"] == "font-name":
    name_id = int(evidence["locator"].split(":", 1)[1])
    evidence_digests = {
      hashlib.sha256(text.encode("utf-8")).hexdigest()
      for text in _font_name_texts(payload_content, name_id, context)
    }
    if evidence["evidenceSha256"] not in evidence_digests:
      raise ResolutionError(f"{context}: license evidence digest does not match", 3)
  elif evidence["type"] == "zip-member":
    evidence_content = _zip_member_bytes(
      payload_content, evidence["locator"], context
    )
    if hashlib.sha256(evidence_content).hexdigest() != evidence["evidenceSha256"]:
      raise ResolutionError(f"{context}: license evidence digest does not match", 3)
  else:
    evidence_blob = _locked_git_blob(cache, commit, evidence["locator"], context)
    if evidence_blob != evidence["evidenceBlob"]:
      raise ResolutionError(f"{context}: license evidence blob does not match", 3)
    evidence_content = _run_git_bytes(
      ["cat-file", "blob", evidence_blob], cwd=cache
    )
    evidence_content = _materialized_lfs_content(
      cache, evidence["locator"], evidence_content, lfs_objects, context
    )
    if hashlib.sha256(evidence_content).hexdigest() != evidence["evidenceSha256"]:
      raise ResolutionError(f"{context}: license evidence digest does not match", 3)


def _locked_component_license_metadata(
  repository,
  license_record,
  cache,
  commit,
  lfs_objects,
  repository_contexts,
):
  actual_payloads = [
    path
    for path in _paths_at_commit(cache, commit)
    if _matches_repository_patterns(path, license_record["payloadPatterns"])
  ]
  locked_payloads = [
    path
    for component in license_record["components"]
    for path in component["payloadPaths"]
  ]
  if sorted(actual_payloads) != sorted(locked_payloads):
    raise ResolutionError("component license payload inventory does not match the lock", 3)
  for component in license_record["components"]:
    for evidence in component["license"]["evidence"]:
      _verify_locked_component_evidence(
        evidence,
        component["id"],
        component["license"]["spdx"],
        {
          "repository": repository,
          "cache": cache,
          "commit": commit,
          "lfsObjects": lfs_objects,
        },
        repository_contexts,
      )
  return {
    "scope": "component",
    "payloadPatterns": list(license_record["payloadPatterns"]),
    "components": [
      {
        "id": component["id"],
        "payloadPaths": list(component["payloadPaths"]),
        "license": {
          "spdx": component["license"]["spdx"],
          "evidence": [dict(record) for record in component["license"]["evidence"]],
        },
      }
      for component in license_record["components"]
    ],
  }


def repository_license_metadata(
  repository,
  cache,
  commit,
  lfs_objects=None,
  repository_contexts=None,
):
  license_record = repository["license"]
  if lfs_objects is None:
    lfs_objects = lfs_objects_at_commit(repository, cache, commit)
  status = license_record.get("status")
  if status == "declared":
    return _declared_license_metadata(license_record, cache, commit, lfs_objects)
  if status == "component-scoped":
    return _component_license_metadata(
      repository,
      cache,
      commit,
      lfs_objects,
      repository_contexts,
    )
  if status == "missing":
    raise ResolutionError(f"LICENSE_INCOMPLETE: {repository['id']}", 3)
  if license_record.get("scope") == "component":
    return _locked_component_license_metadata(
      repository,
      license_record,
      cache,
      commit,
      lfs_objects,
      repository_contexts,
    )
  if status is None and "path" in license_record:
    return _declared_license_metadata(license_record, cache, commit, lfs_objects)
  raise ResolutionError(f"{repository['id']}: unsupported license metadata", 3)


def verify_relationships(inputs, caches, commits):
  declared = {
    (relationship["parent"], relationship["path"]): relationship
    for relationship in inputs["relationships"]
  }
  for relationship in inputs["relationships"]:
    parent = relationship["parent"]
    expected_child = commits[relationship["child"]]
    output = _run_git([
      "ls-tree",
      commits[parent],
      "--",
      relationship["path"],
    ], cwd=caches[parent], exit_code=3)
    fields = output.split(None, 3)
    if len(fields) != 4:
      raise ResolutionError(
        f"{parent}:{relationship['path']}: gitlink is missing",
        3,
      )
    mode, object_type, object_id, actual_path = fields
    if (
      mode != relationship["mode"]
      or object_type != "commit"
      or object_id != expected_child
      or actual_path != relationship["path"]
    ):
      raise ResolutionError(
        f"{parent}:{relationship['path']}: gitlink does not match the source policy",
        3,
      )

  for repository_id in sorted(caches):
    output = _run_git(
      ["ls-tree", "-r", commits[repository_id]],
      cwd=caches[repository_id],
      exit_code=3,
    )
    for line in output.splitlines():
      fields = line.split(None, 3)
      if len(fields) != 4 or fields[0] != "160000":
        continue
      _, object_type, object_id, path = fields
      relationship = declared.get((repository_id, path))
      if relationship is None:
        raise ResolutionError(
          f"{repository_id}:{path}: gitlink is not declared by the source policy",
          3,
        )
      if object_type != "commit" or object_id != commits[relationship["child"]]:
        raise ResolutionError(
          f"{repository_id}:{path}: gitlink does not match the source policy",
          3,
        )


def build_source_lock(inputs, cache_directory, self_root):
  findings = policy_findings(inputs)
  if findings:
    repositories = ", ".join(finding["repository"] for finding in findings)
    raise ResolutionError("LICENSE_INCOMPLETE: " + repositories, 3)
  self_repository = next(
    repository
    for repository in inputs["repositories"]
    if repository.get("commitSource") == "self"
  )
  self_commit = resolve_self_commit(self_root, self_repository["origin"])
  caches = {}
  commits = {}
  repository_contexts = {}
  for repository in inputs["repositories"]:
    commit = self_commit if repository.get("commitSource") == "self" else repository["commit"]
    cache = sync_cache(repository, cache_directory, commit)
    lfs_objects = lfs_objects_at_commit(repository, cache, commit)
    fetch_lfs_objects(repository, cache, commit, lfs_objects)
    caches[repository["id"]] = cache
    commits[repository["id"]] = commit
    repository_contexts[repository["id"]] = {
      "repository": repository,
      "cache": cache,
      "commit": commit,
      "lfsObjects": lfs_objects,
    }
  records = [
    repository_metadata(
      repository,
      repository_contexts[repository["id"]]["cache"],
      repository_contexts[repository["id"]]["commit"],
      repository_contexts,
    )
    for repository in inputs["repositories"]
  ]
  verify_selections(inputs, caches, commits)
  verify_relationships(inputs, caches, commits)
  baseline = inputs["baseline"]
  lock = {
    "schemaVersion": 1,
    "lockType": "source",
    "productVersion": inputs["productVersion"],
    "baseline": dict(baseline),
    "sourceDateEpoch": max(record["commitTime"] for record in records),
    "repositories": records,
    "relationships": [dict(relationship) for relationship in inputs["relationships"]],
  }
  bind_source_tree_manifest(lock, caches)
  return lock, caches


def caches_from_lock(lock, cache_directory):
  caches = {}
  commits = {}
  repository_contexts = {}
  for repository in lock["repositories"]:
    if not MIRROR_PATTERN.fullmatch(repository["origin"]):
      raise ResolutionError(
        f"{repository['id']}: lock origin is not a sunwayking JetOnlyOffice mirror",
        3,
      )
    cache = sync_cache(repository, cache_directory, repository["commit"])
    actual_lfs_objects = lfs_objects_at_commit(
      repository, cache, repository["commit"]
    )
    if actual_lfs_objects != repository["lfsObjects"]:
      raise ResolutionError(
        f"{repository['id']}: mirror Git LFS metadata does not match the lock", 3
      )
    fetch_lfs_objects(
      repository,
      cache,
      repository["commit"],
      actual_lfs_objects,
    )
    caches[repository["id"]] = cache
    commits[repository["id"]] = repository["commit"]
    repository_contexts[repository["id"]] = {
      "repository": repository,
      "cache": cache,
      "commit": repository["commit"],
      "lfsObjects": actual_lfs_objects,
    }
  for repository in lock["repositories"]:
    context = repository_contexts[repository["id"]]
    actual = repository_metadata(
      repository,
      context["cache"],
      repository["commit"],
      repository_contexts,
    )
    if actual != repository:
      raise ResolutionError(f"{repository['id']}: mirror metadata does not match the lock", 3)
  verify_relationships(lock, caches, commits)
  return caches


def _materialize_into(lock, caches, source_directory):
  for repository in lock["repositories"]:
    cache = caches.get(repository["id"])
    if cache is None or not Path(cache).is_dir():
      raise ResolutionError(
        f"{repository['id']}: source cache is missing", 3
      )
  manifest_payload = source_tree_manifest_payload(lock["repositories"], caches)
  manifest_record = lock["sourceTreeManifest"]
  if (
    len(manifest_payload) != manifest_record["size"]
    or hashlib.sha256(manifest_payload).hexdigest() != manifest_record["sha256"]
  ):
    raise ResolutionError(
      "materialized source tree manifest does not match the source lock", 3
    )
  manifest_path = _resolve_within(
    source_directory,
    manifest_record["path"],
    "sourceTreeManifest.path",
  )
  manifest_path.parent.mkdir(parents=True, exist_ok=True)
  manifest_path.write_bytes(manifest_payload)
  for repository in lock["repositories"]:
    destination = _resolve_within(
      source_directory,
      repository["checkoutPath"],
      f"{repository['id']}.checkoutPath",
    )
    if destination.exists():
      raise ResolutionError(f"{destination}: checkout destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    _run_git(
      ["clone", "--no-checkout", str(caches[repository["id"]]), str(destination)],
      environment={"GIT_LFS_SKIP_SMUDGE": "1"},
    )
    _run_git(["config", "core.autocrlf", "false"], cwd=destination)
    if os.name == "nt":
      # The staging prefix is long enough that repository paths near the
      # Windows MAX_PATH limit would otherwise be skipped silently by
      # git checkout, leaving the materialized tree dirty.
      _run_git(["config", "core.longpaths", "true"], cwd=destination)
    _run_git(
      ["checkout", "--detach", repository["commit"]],
      cwd=destination,
      environment={"GIT_LFS_SKIP_SMUDGE": "1"},
    )
    _run_git(["remote", "set-url", "origin", repository["origin"]], cwd=destination)
    _run_git(
      ["config", "lfs.url", _lfs_endpoint(repository["origin"])],
      cwd=destination,
    )
    git_directory = Path(_run_git(["rev-parse", "--git-dir"], cwd=destination))
    if not git_directory.is_absolute():
      git_directory = destination / git_directory
    _verify_lfs_cache(repository, caches[repository["id"]], repository["lfsObjects"])
    for lfs_object in repository["lfsObjects"]:
      cached_object = _lfs_object_path(caches[repository["id"]], lfs_object["oid"])
      checkout_object = _lfs_object_path(git_directory, lfs_object["oid"])
      checkout_object.parent.mkdir(parents=True, exist_ok=True)
      shutil.copyfile(cached_object, checkout_object)
    if repository["lfsObjects"]:
      _run_git(["lfs", "checkout"], cwd=destination, exit_code=3)
  verify_materialized(lock, source_directory)


def materialize(lock, caches, source_directory):
  source_directory = Path(source_directory).resolve()
  if source_directory.exists():
    verify_materialized(lock, source_directory)
    return
  source_directory.parent.mkdir(parents=True, exist_ok=True)
  staging_directory = Path(tempfile.mkdtemp(
    dir=source_directory.parent,
    prefix="." + source_directory.name + ".",
  ))
  # Windows may briefly hold handles on freshly written Git objects
  # (antivirus scans, lingering helper processes), so publish and cleanup
  # retry with a growing backoff before failing closed.
  publish_backoff = (1, 2, 4, 8, 16)
  try:
    _materialize_into(lock, caches, staging_directory)
    for attempt, delay in enumerate(publish_backoff):
      try:
        staging_directory.rename(source_directory)
        break
      except OSError as error:
        if source_directory.exists():
          verify_materialized(lock, source_directory)
          return
        if attempt == len(publish_backoff) - 1:
          raise ResolutionError(
            f"{source_directory}: cannot publish locked source workspace: {error}",
            3,
          ) from error
        time.sleep(delay)
    staging_directory = None
  finally:
    if staging_directory is not None:
      primary = sys.exc_info()[1]
      for attempt, delay in enumerate(publish_backoff):
        try:
          shutil.rmtree(staging_directory)
          break
        except OSError as error:
          if attempt == len(publish_backoff) - 1:
            detail = f"{staging_directory}: cannot clean source staging: {error}"
            if primary is not None:
              detail += f"; original failure: {primary}"
            raise ResolutionError(detail, 3) from error
          time.sleep(delay)


def verify_workspace_inventory(lock, source_directory):
  expected = {
    PurePosixPath(repository["checkoutPath"]).parts
    for repository in lock["repositories"]
  }
  ancestors = {
    parts[:index]
    for parts in expected
    for index in range(1, len(parts))
  }
  manifest_parts = PurePosixPath(lock["sourceTreeManifest"]["path"]).parts
  manifest_ancestors = {
    manifest_parts[:index]
    for index in range(1, len(manifest_parts))
  }
  ancestors.update(manifest_ancestors)

  def verify_directory(directory, prefix=()):
    try:
      with os.scandir(directory) as stream:
        entries = sorted(stream, key=lambda entry: entry.name)
    except OSError as error:
      raise ResolutionError(
        f"{directory}: cannot inspect locked source workspace: {error}"
      ) from error
    for entry in entries:
      relative = prefix + (entry.name,)
      path = Path(entry.path)
      is_junction = getattr(path, "is_junction", lambda: False)()
      if relative == manifest_parts:
        if entry.is_symlink() or is_junction or not entry.is_file(follow_symlinks=False):
          raise ResolutionError(
            f"{source_directory}: source tree manifest is not a regular file"
          )
        continue
      if relative in expected:
        if entry.is_symlink() or is_junction or not entry.is_dir(follow_symlinks=False):
          raise ResolutionError(
            f"{source_directory}: locked checkout path is not a directory: "
            + PurePosixPath(*relative).as_posix()
          )
        continue
      if relative in ancestors:
        if entry.is_symlink() or is_junction or not entry.is_dir(follow_symlinks=False):
          raise ResolutionError(
            f"{source_directory}: locked checkout parent is not a directory: "
            + PurePosixPath(*relative).as_posix()
          )
        verify_directory(path, relative)
        continue
      raise ResolutionError(
        f"{source_directory}: unexpected path outside locked checkouts: "
        + PurePosixPath(*relative).as_posix()
      )

  verify_directory(source_directory)


def verify_git_index_flags(checkout):
  entries = _run_git_bytes(["ls-files", "-v", "-z"], cwd=checkout)
  for entry in entries.split(b"\0"):
    if not entry:
      continue
    marker = entry[:1]
    if marker == b"S" or marker.islower():
      path = entry[2:].decode("utf-8", errors="replace")
      raise ResolutionError(
        f"{checkout}:{path}: unsafe Git index flag {marker.decode('ascii')}"
      )


def verify_materialized(lock, source_directory):
  source_directory = Path(source_directory).resolve()
  verify_workspace_inventory(lock, source_directory)
  manifest_record = lock["sourceTreeManifest"]
  manifest_path = _resolve_within(
    source_directory,
    manifest_record["path"],
    "sourceTreeManifest.path",
  )
  manifest_missing = not manifest_path.is_file()
  if not manifest_missing and (
    manifest_path.stat().st_size != manifest_record["size"]
    or _sha256_file(manifest_path) != manifest_record["sha256"]
  ):
    raise ResolutionError(
      "materialized source tree manifest does not match the source lock"
    )
  checkout_caches = {}
  repository_contexts = {}
  for repository in lock["repositories"]:
    checkout = _resolve_within(
      source_directory,
      repository["checkoutPath"],
      f"{repository['id']}.checkoutPath",
    )
    if not checkout.is_dir():
      raise ResolutionError(f"{checkout}: locked checkout is missing")
    origin = _run_git(["remote", "get-url", "origin"], cwd=checkout)
    if origin != repository["origin"]:
      raise ResolutionError(f"{checkout}: origin does not match the lock")
    lfs_endpoint = _run_git(["config", "--local", "--get", "lfs.url"], cwd=checkout)
    if lfs_endpoint != _lfs_endpoint(repository["origin"]):
      raise ResolutionError(f"{checkout}: Git LFS endpoint does not match the lock")
    head = _run_git(["rev-parse", "HEAD^{commit}"], cwd=checkout)
    if head != repository["commit"]:
      raise ResolutionError(f"{checkout}: commit does not match the lock")
    tree = _run_git(["rev-parse", "HEAD^{tree}"], cwd=checkout)
    if tree != repository["tree"]:
      raise ResolutionError(f"{checkout}: tree does not match the lock")
    verify_git_index_flags(checkout)
    actual_lfs_objects = lfs_objects_at_commit(repository, checkout, head)
    if actual_lfs_objects != repository["lfsObjects"]:
      raise ResolutionError(f"{checkout}: Git LFS object manifest does not match the lock")
    for lfs_object in repository["lfsObjects"]:
      for path in lfs_object["paths"]:
        materialized = _resolve_within(
          checkout,
          path,
          f"{repository['id']}.lfsObjects.path",
        )
        if not materialized.is_file():
          raise ResolutionError(f"{checkout}:{path}: Git LFS content is missing")
        if materialized.stat().st_size != lfs_object["size"]:
          raise ResolutionError(f"{checkout}:{path}: Git LFS size does not match the lock")
        if _sha256_file(materialized) != lfs_object["oid"]:
          raise ResolutionError(f"{checkout}:{path}: Git LFS digest does not match the lock")
    if _run_git(
      ["status", "--porcelain", "--untracked-files=all", "--ignored"],
      cwd=checkout,
    ):
      raise ResolutionError(f"{checkout}: checkout is dirty")
    checkout_caches[repository["id"]] = checkout
    repository_contexts[repository["id"]] = {
      "repository": repository,
      "cache": checkout,
      "commit": "HEAD",
      "lfsObjects": actual_lfs_objects,
    }
  for repository in lock["repositories"]:
    context = repository_contexts[repository["id"]]
    actual_license = repository_license_metadata(
      repository,
      context["cache"],
      "HEAD",
      context["lfsObjects"],
      repository_contexts,
    )
    if actual_license != repository["license"]:
      raise ResolutionError(
        f"{context['cache']}: license metadata does not match the lock"
      )
  if manifest_missing:
    raise ResolutionError("materialized source tree manifest is missing")
  expected_manifest = source_tree_manifest_payload(
    lock["repositories"], checkout_caches
  )
  if manifest_path.read_bytes() != expected_manifest:
    raise ResolutionError(
      "materialized source tree manifest does not match the Git checkouts"
    )


def main(argv=None):
  parser = argparse.ArgumentParser(description="Resolve JetOnlyOffice source inputs")
  subparsers = parser.add_subparsers(dest="command", required=True)

  audit_parser = subparsers.add_parser("audit")
  audit_parser.add_argument("--inputs", required=True)
  audit_parser.add_argument("--report")

  license_audit_parser = subparsers.add_parser("license-audit")
  license_audit_parser.add_argument("--inputs", required=True)
  license_audit_parser.add_argument("--cache-directory", required=True)
  license_audit_parser.add_argument("--report", required=True)
  license_audit_parser.add_argument("--schema-dir", required=True)

  lfs_audit_parser = subparsers.add_parser("lfs-audit")
  lfs_audit_parser.add_argument("--inputs", required=True)
  lfs_audit_parser.add_argument("--cache-directory", required=True)
  lfs_audit_parser.add_argument("--repository", action="append", required=True)
  lfs_audit_parser.add_argument("--report", required=True)
  lfs_audit_parser.add_argument("--schema-dir", required=True)

  selection_audit_parser = subparsers.add_parser("selection-audit")
  selection_audit_parser.add_argument("--inputs", required=True)
  selection_audit_parser.add_argument("--cache-directory", required=True)
  selection_audit_parser.add_argument("--self-root", required=True)
  selection_audit_parser.add_argument("--report", required=True)
  selection_audit_parser.add_argument("--schema-dir", required=True)

  resolve_parser = subparsers.add_parser("resolve")
  resolve_parser.add_argument("--inputs", required=True)
  resolve_parser.add_argument("--cache-directory", required=True)
  resolve_parser.add_argument("--lock-output", required=True)
  resolve_parser.add_argument("--self-root", required=True)
  resolve_parser.add_argument("--schema-dir", required=True)

  bootstrap_parser = subparsers.add_parser("bootstrap")
  bootstrap_parser.add_argument("--lock", required=True)
  bootstrap_parser.add_argument("--cache-directory", required=True)
  bootstrap_parser.add_argument("--source-directory", required=True)
  bootstrap_parser.add_argument("--schema-dir", required=True)

  verify_parser = subparsers.add_parser("verify")
  verify_parser.add_argument("--lock", required=True)
  verify_parser.add_argument("--source-directory", required=True)
  verify_parser.add_argument("--schema-dir", required=True)

  args = parser.parse_args(argv)
  try:
    if args.command == "audit":
      if args.report:
        discard_previous_output(args.report, "source input audit report")
      inputs = load_json(args.inputs)
      validate_inputs(inputs)
      report = audit_report(inputs)
      if args.report:
        write_canonical_json(args.report, report)
      if report["status"] != "passed":
        for finding in report["findings"]:
          print(
            f"{finding['code']}: {finding['repository']}: {finding['message']}",
            file=sys.stderr,
          )
        return 3
    elif args.command == "license-audit":
      discard_previous_output(args.report, "source license audit report")
      inputs = load_json(args.inputs)
      validate_inputs(inputs)
      report = license_inventory_report(inputs, args.cache_directory)
      validate_contract(report, "source-license-audit", args.schema_dir)
      write_canonical_json(args.report, report)
      for repository in report["repositories"]:
        if repository["status"] == "complete":
          continue
        unresolved = [
          component["id"]
          for component in repository["components"]
          if component["status"] != "resolved"
        ]
        print(
          "LICENSE_INCOMPLETE: "
          f"{repository['repository']}: {', '.join(unresolved)}",
          file=sys.stderr,
        )
      if report["status"] == "failed":
        return 3
    elif args.command == "lfs-audit":
      discard_previous_output(args.report, "source LFS audit report")
      inputs = load_json(args.inputs)
      validate_inputs(inputs)
      report = lfs_public_audit_report(
        inputs,
        args.cache_directory,
        args.repository,
      )
      validate_contract(report, "source-lfs-audit", args.schema_dir)
      write_canonical_json(args.report, report)
    elif args.command == "selection-audit":
      discard_previous_output(args.report, "source selection audit report")
      inputs = load_json(args.inputs)
      validate_inputs(inputs)
      report = selection_audit_report(
        inputs,
        args.cache_directory,
        args.self_root,
      )
      validate_contract(report, "source-selection-audit", args.schema_dir)
      write_canonical_json(args.report, report)
    elif args.command == "resolve":
      discard_previous_output(args.lock_output, "source lock")
      inputs = load_json(args.inputs)
      validate_inputs(inputs)
      lock, _ = build_source_lock(inputs, args.cache_directory, args.self_root)
      validate_contract(lock, "source-lock", args.schema_dir)
      write_canonical_json(args.lock_output, lock)
    elif args.command == "bootstrap":
      lock = load_source_lock(args.lock)
      validate_contract(lock, "source-lock", args.schema_dir)
      caches = caches_from_lock(lock, args.cache_directory)
      materialize(lock, caches, args.source_directory)
    elif args.command == "verify":
      lock = load_source_lock(args.lock)
      validate_contract(lock, "source-lock", args.schema_dir)
      verify_materialized(lock, args.source_directory)
    return 0
  except (ContractError, ResolutionError) as error:
    print("source resolver error: " + str(error), file=sys.stderr)
    return error.exit_code if isinstance(error, ResolutionError) else 2


if __name__ == "__main__":
  sys.exit(main())
