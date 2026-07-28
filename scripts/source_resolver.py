#!/usr/bin/env python3

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from urllib.parse import urlparse

from contracts.contract_tool import (
  ContractError,
  canonical_json_bytes,
  load_json,
  validate_contract,
)


SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")
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
  "projectFork",
  "buildInput",
  "active",
  "license",
}


class ResolutionError(ValueError):
  def __init__(self, message, exit_code=3):
    super().__init__(message)
    self.exit_code = exit_code


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
  if (
    candidate.is_absolute()
    or value in ("", ".")
    or "\\" in value
    or "//" in value
    or any(part in ("", ".", "..") for part in value.split("/"))
  ):
    raise ResolutionError(f"{path}: path must be normalized and relative", 2)


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
    for flag in ("projectFork", "buildInput", "active"):
      if not isinstance(repository[flag], bool):
        raise ResolutionError(f"{path}.{flag}: expected boolean", 2)
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
  repository_ids = set(ids)
  if baseline["repository"] not in repository_ids:
    raise ResolutionError("$.baseline.repository: repository is not selected", 2)
  selected_baseline = next(
    repository for repository in repositories if repository["id"] == baseline["repository"]
  )
  if selected_baseline.get("commit") != baseline["commit"]:
    raise ResolutionError("$.baseline.commit: does not match selected repository", 2)

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


def _validate_license_input(value, path):
  if not isinstance(value, dict):
    raise ResolutionError(f"{path}: expected object", 2)
  status = value.get("status")
  if status == "declared":
    _require_exact_keys(value, {"status", "path", "spdx"}, set(), path)
    _validate_relative_path(value["path"], path + ".path")
    if not isinstance(value["spdx"], str) or not value["spdx"]:
      raise ResolutionError(f"{path}.spdx: expected non-empty SPDX expression", 2)
  elif status == "component-scoped":
    _require_exact_keys(value, {"status", "patterns", "reason"}, set(), path)
    if (
      not isinstance(value["patterns"], list)
      or not value["patterns"]
      or not all(isinstance(item, str) and item for item in value["patterns"])
    ):
      raise ResolutionError(f"{path}.patterns: expected non-empty string array", 2)
    if value["patterns"] != sorted(set(value["patterns"])):
      raise ResolutionError(f"{path}.patterns: values must be sorted and unique", 2)
    if not isinstance(value["reason"], str) or not value["reason"]:
      raise ResolutionError(f"{path}.reason: expected non-empty string", 2)
  elif status == "missing":
    _require_exact_keys(value, {"status", "reason"}, set(), path)
    if not isinstance(value["reason"], str) or not value["reason"]:
      raise ResolutionError(f"{path}.reason: expected non-empty string", 2)
  else:
    raise ResolutionError(f"{path}.status: unsupported license status", 2)


def policy_findings(inputs):
  findings = []
  for repository in inputs["repositories"]:
    license_input = repository["license"]
    if license_input["status"] != "declared":
      findings.append({
        "code": "LICENSE_INCOMPLETE",
        "repository": repository["id"],
        "message": license_input["reason"],
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


def load_source_lock(path):
  path = Path(path)
  if not path.is_file():
    raise ResolutionError(f"{path}: locked source input is missing", 3)
  return load_json(path)


def _run_git(arguments, cwd=None, exit_code=4):
  result = subprocess.run(
    ["git", *arguments],
    cwd=cwd,
    capture_output=True,
    encoding="utf-8",
    errors="replace",
    check=False,
  )
  if result.returncode != 0:
    detail = result.stderr.strip() or result.stdout.strip() or "git command failed"
    raise ResolutionError(detail, exit_code)
  return result.stdout.strip()


def _run_git_bytes(arguments, cwd=None):
  result = subprocess.run(
    ["git", *arguments],
    cwd=cwd,
    capture_output=True,
    check=False,
  )
  if result.returncode != 0:
    detail = result.stderr.decode("utf-8", errors="replace").strip()
    raise ResolutionError(detail or "git command failed", 3)
  return result.stdout


def sync_cache(repository, cache_directory):
  cache = Path(cache_directory).resolve() / "git" / (repository["id"] + ".git")
  cache.parent.mkdir(parents=True, exist_ok=True)
  if cache.exists():
    if _run_git(["rev-parse", "--is-bare-repository"], cwd=cache) != "true":
      raise ResolutionError(f"{cache}: expected bare Git cache")
    origin = _run_git(["remote", "get-url", "origin"], cwd=cache)
    if origin != repository["origin"]:
      raise ResolutionError(f"{cache}: origin does not match the source policy")
    _run_git([
      "fetch",
      "--prune",
      "--tags",
      "origin",
      "+refs/heads/*:refs/heads/*",
    ], cwd=cache)
  else:
    _run_git(["clone", "--mirror", repository["origin"], str(cache)])
  _run_git(["fsck", "--full", "--strict"], cwd=cache)
  return cache


def resolve_self_commit(self_root, expected_origin):
  self_root = Path(self_root).resolve()
  if _run_git(["status", "--porcelain", "--untracked-files=all"], cwd=self_root):
    raise ResolutionError("build-tools self checkout must be clean")
  origin = _run_git(["remote", "get-url", "origin"], cwd=self_root)
  if origin != expected_origin:
    raise ResolutionError("build-tools self checkout origin does not match the source policy")
  commit = _run_git(["rev-parse", "HEAD^{commit}"], cwd=self_root)
  if not SHA1_PATTERN.fullmatch(commit):
    raise ResolutionError("build-tools self checkout did not resolve to a full commit")
  return commit


def repository_metadata(repository, cache, commit):
  _run_git(["cat-file", "-e", commit + "^{commit}"], cwd=cache, exit_code=3)
  tree = _run_git(["rev-parse", commit + "^{tree}"], cwd=cache, exit_code=3)
  commit_time_text = _run_git(["show", "-s", "--format=%ct", commit], cwd=cache, exit_code=3)
  try:
    commit_time = int(commit_time_text)
  except ValueError as error:
    raise ResolutionError(f"{repository['id']}: invalid commit timestamp", 3) from error
  license_input = repository["license"]
  license_path = license_input["path"]
  blob = _run_git(["rev-parse", f"{commit}:{license_path}"], cwd=cache, exit_code=3)
  content = _run_git_bytes(["show", f"{commit}:{license_path}"], cwd=cache)
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
    "license": {
      "path": license_path,
      "blob": blob,
      "sha256": hashlib.sha256(content).hexdigest(),
      "spdx": license_input["spdx"],
    },
  }


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
  records = []
  for repository in inputs["repositories"]:
    cache = sync_cache(repository, cache_directory)
    commit = self_commit if repository.get("commitSource") == "self" else repository["commit"]
    caches[repository["id"]] = cache
    commits[repository["id"]] = commit
    records.append(repository_metadata(repository, cache, commit))
  verify_relationships(inputs, caches, commits)
  baseline = inputs["baseline"]
  return {
    "schemaVersion": 1,
    "lockType": "source",
    "productVersion": inputs["productVersion"],
    "baseline": dict(baseline),
    "sourceDateEpoch": max(record["commitTime"] for record in records),
    "repositories": records,
    "relationships": [dict(relationship) for relationship in inputs["relationships"]],
  }, caches


def caches_from_lock(lock, cache_directory):
  caches = {}
  commits = {}
  for repository in lock["repositories"]:
    if not MIRROR_PATTERN.fullmatch(repository["origin"]):
      raise ResolutionError(
        f"{repository['id']}: lock origin is not a sunwayking JetOnlyOffice mirror",
        3,
      )
    cache = sync_cache(repository, cache_directory)
    metadata_input = dict(repository)
    metadata_input["license"] = {
      "status": "declared",
      "path": repository["license"]["path"],
      "spdx": repository["license"]["spdx"],
    }
    actual = repository_metadata(metadata_input, cache, repository["commit"])
    if actual != repository:
      raise ResolutionError(f"{repository['id']}: mirror metadata does not match the lock", 3)
    caches[repository["id"]] = cache
    commits[repository["id"]] = repository["commit"]
  verify_relationships(lock, caches, commits)
  return caches


def materialize(lock, caches, source_directory):
  source_directory = Path(source_directory).resolve()
  source_directory.mkdir(parents=True, exist_ok=True)
  for repository in lock["repositories"]:
    destination = source_directory / PurePosixPath(repository["checkoutPath"])
    if destination.exists():
      raise ResolutionError(f"{destination}: checkout destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    _run_git(["clone", "--no-checkout", str(caches[repository["id"]]), str(destination)])
    _run_git(["config", "core.autocrlf", "false"], cwd=destination)
    _run_git(["checkout", "--detach", repository["commit"]], cwd=destination)
    _run_git(["remote", "set-url", "origin", repository["origin"]], cwd=destination)
  verify_materialized(lock, source_directory)


def verify_materialized(lock, source_directory):
  source_directory = Path(source_directory).resolve()
  for repository in lock["repositories"]:
    checkout = source_directory / PurePosixPath(repository["checkoutPath"])
    if not checkout.is_dir():
      raise ResolutionError(f"{checkout}: locked checkout is missing")
    origin = _run_git(["remote", "get-url", "origin"], cwd=checkout)
    if origin != repository["origin"]:
      raise ResolutionError(f"{checkout}: origin does not match the lock")
    head = _run_git(["rev-parse", "HEAD^{commit}"], cwd=checkout)
    if head != repository["commit"]:
      raise ResolutionError(f"{checkout}: commit does not match the lock")
    tree = _run_git(["rev-parse", "HEAD^{tree}"], cwd=checkout)
    if tree != repository["tree"]:
      raise ResolutionError(f"{checkout}: tree does not match the lock")
    if _run_git(["status", "--porcelain", "--untracked-files=all"], cwd=checkout):
      raise ResolutionError(f"{checkout}: checkout is dirty")
    license_path = repository["license"]["path"]
    content = _run_git_bytes(["show", f"HEAD:{license_path}"], cwd=checkout)
    digest = hashlib.sha256(content).hexdigest()
    if digest != repository["license"]["sha256"]:
      raise ResolutionError(f"{checkout}: license digest does not match the lock")


def main(argv=None):
  parser = argparse.ArgumentParser(description="Resolve JetOnlyOffice source inputs")
  subparsers = parser.add_subparsers(dest="command", required=True)

  audit_parser = subparsers.add_parser("audit")
  audit_parser.add_argument("--inputs", required=True)
  audit_parser.add_argument("--report")

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
    elif args.command == "resolve":
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
