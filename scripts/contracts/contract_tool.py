#!/usr/bin/env python3

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.parse import urlparse


CONTRACT_SCHEMAS = {
  "source-lock": "source-lock.schema.json",
  "toolchain-lock": "toolchain-lock.schema.json",
  "image-lock": "image-lock.schema.json",
  "build-manifest": "build-manifest.schema.json",
  "artifact-manifest": "artifact-manifest.schema.json",
  "command-catalog": "command-catalog.schema.json",
  "corpus-manifest": "corpus-manifest.schema.json",
  "performance-samples": "performance-samples.schema.json",
  "gate-result": "gate-result.schema.json",
  "release-policy": "release-policy.schema.json",
  "release-evidence": "release-evidence.schema.json",
  "gate-catalog": "gate-catalog.schema.json",
}

EXPECTED_ENVIRONMENT = {
  "timezone": "UTC",
  "locale": "C.UTF-8",
  "umask": "022",
  "pythonHashSeed": "0",
  "buildPath": "/work",
  "concurrency": 4,
}
SOURCE_LICENSE_EXPRESSIONS = {
  "AGPL-3.0-only",
  "Apache-2.0",
  "MIT",
}
WINDOWS_DEVICE_PATTERN = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)

MAX_SAFE_INTEGER = 9007199254740991

MOBILE_PERFORMANCE_FORMATS = ("docx", "pdf", "pptx", "xlsx")
MOBILE_PERFORMANCE_POLICY = {
  "performance.xiaomi.command-p95": {
    "field": "commands",
    "minimum_samples": 30,
    "percentile_numerator": 95,
    "percentile_denominator": 100,
    "maximum_milliseconds": 250,
    "error_code": "PERFORMANCE_COMMAND_P95_EXCEEDED",
  },
  "performance.xiaomi.gesture-fps": {
    "field": "gestures",
    "rounds": (1, 2, 3),
    "minimum_milli_fps": 45000,
    "maximum_freeze_milliseconds": 1000,
    "error_code": "PERFORMANCE_GESTURE_BUDGET_EXCEEDED",
  },
  "performance.xiaomi.open-time": {
    "field": "openTime",
    "sample_count": 10,
    "maximum_milliseconds": 8000,
    "error_code": "PERFORMANCE_OPEN_TIME_EXCEEDED",
  },
}


class ContractError(ValueError):
  pass


def _reject_float(value):
  raise ContractError("floating-point values are not allowed: " + value)


def _reject_constant(value):
  raise ContractError("non-finite values are not allowed: " + value)


def _unique_object(pairs):
  result = {}
  for key, value in pairs:
    if key in result:
      raise ContractError("duplicate JSON object key: " + key)
    result[key] = value
  return result


def load_json(path):
  path = Path(path)
  try:
    return json.loads(
      path.read_text(encoding="utf-8"),
      object_pairs_hook=_unique_object,
      parse_float=_reject_float,
      parse_constant=_reject_constant,
    )
  except OSError as error:
    raise ContractError(f"cannot read {path}: {error}") from error
  except json.JSONDecodeError as error:
    raise ContractError(f"invalid JSON in {path}: {error}") from error


def _check_canonical_value(value, path="$"):
  if value is None or isinstance(value, bool):
    return
  if isinstance(value, str):
    for character in value:
      if 0xD800 <= ord(character) <= 0xDFFF:
        raise ContractError(f"{path}: strings must contain only Unicode scalar values")
    return
  if isinstance(value, int) and not isinstance(value, bool):
    if abs(value) > MAX_SAFE_INTEGER:
      raise ContractError(f"{path}: integer exceeds the RFC 8785 interoperable range")
    return
  if isinstance(value, list):
    for index, item in enumerate(value):
      _check_canonical_value(item, f"{path}[{index}]")
    return
  if isinstance(value, dict):
    for key, item in value.items():
      if not isinstance(key, str) or not key.isascii():
        raise ContractError(f"{path}: object keys must be ASCII strings")
      _check_canonical_value(item, f"{path}.{key}")
    return
  raise ContractError(f"{path}: unsupported canonical JSON value {type(value).__name__}")


def canonical_json_bytes(value):
  """Return the RFC 8785 representation for the contracts' integer-only subset."""
  _check_canonical_value(value)
  return json.dumps(
    value,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
  ).encode("utf-8")


def canonical_sha256(value):
  return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class SchemaStore:
  def __init__(self, schema_dir):
    self.schema_dir = Path(schema_dir).resolve()
    self._cache = {}

  def load(self, name):
    name = Path(name).name
    if name not in self._cache:
      self._cache[name] = load_json(self.schema_dir / name)
    return self._cache[name]

  def resolve(self, reference, current_name):
    name, separator, pointer = reference.partition("#")
    target_name = Path(name).name if name else current_name
    target = self.load(target_name)
    if not separator or not pointer:
      return target, target_name
    if not pointer.startswith("/"):
      raise ContractError("unsupported schema reference: " + reference)
    for raw_part in pointer[1:].split("/"):
      part = raw_part.replace("~1", "/").replace("~0", "~")
      try:
        target = target[part]
      except (KeyError, TypeError) as error:
        raise ContractError("unresolved schema reference: " + reference) from error
    return target, target_name


def _matches_type(value, expected):
  if expected == "object":
    return isinstance(value, dict)
  if expected == "array":
    return isinstance(value, list)
  if expected == "string":
    return isinstance(value, str)
  if expected == "integer":
    return isinstance(value, int) and not isinstance(value, bool)
  if expected == "boolean":
    return isinstance(value, bool)
  if expected == "null":
    return value is None
  raise ContractError("unsupported schema type: " + expected)


def _validate_schema(value, schema, store, current_name, path="$"):
  if "$ref" in schema:
    target, target_name = store.resolve(schema["$ref"], current_name)
    _validate_schema(value, target, store, target_name, path)
    return

  if "const" in schema and value != schema["const"]:
    raise ContractError(f"{path}: expected constant {schema['const']!r}")
  if "enum" in schema and value not in schema["enum"]:
    raise ContractError(f"{path}: value {value!r} is not allowed")

  expected_type = schema.get("type")
  if expected_type and not _matches_type(value, expected_type):
    raise ContractError(f"{path}: expected {expected_type}, got {type(value).__name__}")

  if isinstance(value, dict):
    required = schema.get("required", [])
    for key in required:
      if key not in value:
        raise ContractError(f"{path}: missing required property {key}")
    properties = schema.get("properties", {})
    if schema.get("additionalProperties") is False:
      unknown = sorted(set(value) - set(properties))
      if unknown:
        raise ContractError(f"{path}: unknown properties: {', '.join(unknown)}")
    for key, item in value.items():
      if key in properties:
        _validate_schema(item, properties[key], store, current_name, f"{path}.{key}")

  if isinstance(value, list):
    minimum = schema.get("minItems")
    if minimum is not None and len(value) < minimum:
      raise ContractError(f"{path}: expected at least {minimum} items")
    item_schema = schema.get("items")
    if item_schema:
      for index, item in enumerate(value):
        _validate_schema(item, item_schema, store, current_name, f"{path}[{index}]")

  if isinstance(value, str):
    minimum = schema.get("minLength")
    if minimum is not None and len(value) < minimum:
      raise ContractError(f"{path}: string is shorter than {minimum}")
    pattern = schema.get("pattern")
    if pattern and re.search(pattern, value) is None:
      raise ContractError(f"{path}: value does not match {pattern}")

  if isinstance(value, int) and not isinstance(value, bool):
    minimum = schema.get("minimum")
    if minimum is not None and value < minimum:
      raise ContractError(f"{path}: value is less than {minimum}")


def _validate_relative_path(value, path):
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
    raise ContractError(f"{path}: path must be normalized and relative")


def _validate_https(value, path):
  parsed = urlparse(value)
  if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
    raise ContractError(f"{path}: expected credential-free HTTPS URL")


def _validate_sorted_unique(items, key, path):
  values = [key(item) for item in items]
  if values != sorted(values):
    raise ContractError(f"{path}: items must be sorted")
  if len(values) != len(set(values)):
    raise ContractError(f"{path}: item keys must be unique")


def _validate_environment(environment, path):
  if environment != EXPECTED_ENVIRONMENT:
    raise ContractError(f"{path}: environment does not match the release profile")


def _validate_source_lock(value):
  repositories = value["repositories"]
  _validate_sorted_unique(repositories, lambda item: item["id"], "$.repositories")
  repository_ids = {item["id"] for item in repositories}
  checkout_paths = [item["checkoutPath"] for item in repositories]
  if len(checkout_paths) != len(set(checkout_paths)):
    raise ContractError("$.repositories: checkoutPath values must be unique")
  for index, repository in enumerate(repositories):
    prefix = f"$.repositories[{index}]"
    _validate_relative_path(repository["checkoutPath"], prefix + ".checkoutPath")
    _validate_relative_path(repository["license"]["path"], prefix + ".license.path")
    _validate_https(repository["origin"], prefix + ".origin")
    _validate_https(repository["upstream"], prefix + ".upstream")
    if repository["license"]["spdx"] not in SOURCE_LICENSE_EXPRESSIONS:
      raise ContractError(prefix + ".license.spdx: expression is not in the reviewed source set")
    _validate_sorted_unique(
      repository["lfsObjects"],
      lambda item: item["oid"],
      prefix + ".lfsObjects",
    )
    lfs_paths = []
    for object_index, lfs_object in enumerate(repository["lfsObjects"]):
      object_prefix = f"{prefix}.lfsObjects[{object_index}]"
      _validate_sorted_unique(lfs_object["paths"], lambda path: path, object_prefix + ".paths")
      for lfs_path in lfs_object["paths"]:
        _validate_relative_path(lfs_path, object_prefix + ".paths")
      lfs_paths.extend(lfs_object["paths"])
    if len(lfs_paths) != len(set(lfs_paths)):
      raise ContractError(prefix + ".lfsObjects: paths must be unique across objects")
  maximum_commit_time = max(item["commitTime"] for item in repositories)
  if value["sourceDateEpoch"] != maximum_commit_time:
    raise ContractError("$.sourceDateEpoch: must equal the maximum repository commitTime")
  baseline_id = value["baseline"]["repository"]
  baseline = next((item for item in repositories if item["id"] == baseline_id), None)
  if baseline is None:
    raise ContractError("$.baseline.repository: repository is not locked")
  if baseline["commit"] != value["baseline"]["commit"]:
    raise ContractError("$.baseline.commit: does not match the locked repository")
  relationships = value["relationships"]
  _validate_sorted_unique(
    relationships,
    lambda item: (item["parent"], item["path"], item["child"]),
    "$.relationships",
  )
  for index, relationship in enumerate(relationships):
    prefix = f"$.relationships[{index}]"
    if relationship["parent"] not in repository_ids:
      raise ContractError(prefix + ".parent: repository is not locked")
    if relationship["child"] not in repository_ids:
      raise ContractError(prefix + ".child: repository is not locked")
    _validate_relative_path(relationship["path"], prefix + ".path")


def _validate_toolchain_lock(value):
  _validate_environment(value["environment"], "$.environment")
  tools = value["tools"]
  _validate_sorted_unique(tools, lambda item: item["id"], "$.tools")
  for index, tool in enumerate(tools):
    _validate_https(tool["sourceUrl"], f"$.tools[{index}].sourceUrl")


def _validate_image_lock(value):
  images = value["images"]
  _validate_sorted_unique(images, lambda item: item["id"], "$.images")
  required_roles = {"builder", "runtime", "buildkit", "dockerfile-frontend"}
  roles = {item["role"] for item in images}
  missing = sorted(required_roles - roles)
  if missing:
    raise ContractError("$.images: missing required roles: " + ", ".join(missing))
  for index, image in enumerate(images):
    _validate_https(image["sourceUrl"], f"$.images[{index}].sourceUrl")


def _validate_build_manifest(value):
  _validate_environment(value["environment"], "$.environment")
  files = value["files"]
  _validate_sorted_unique(files, lambda item: item["path"], "$.files")
  for index, item in enumerate(files):
    _validate_relative_path(item["path"], f"$.files[{index}].path")


def _validate_artifact_manifest(value):
  artifacts = value["artifacts"]
  _validate_sorted_unique(artifacts, lambda item: item["id"], "$.artifacts")
  artifact_ids = {item["id"] for item in artifacts}
  paths = [item["path"] for item in artifacts]
  if len(paths) != len(set(paths)):
    raise ContractError("$.artifacts: paths must be unique")
  required_types = {
    "deb",
    "rootfs",
    "oci",
    "source",
    "spdx",
    "cyclonedx",
    "provenance",
    "checksums",
  }
  types = {item["type"] for item in artifacts}
  missing = sorted(required_types - types)
  if missing:
    raise ContractError("$.artifacts: missing required types: " + ", ".join(missing))
  for index, item in enumerate(artifacts):
    _validate_relative_path(item["path"], f"$.artifacts[{index}].path")
    if item["subjects"] != sorted(set(item["subjects"])):
      raise ContractError(f"$.artifacts[{index}].subjects: values must be sorted and unique")
    unknown_subjects = sorted(set(item["subjects"]) - artifact_ids)
    if unknown_subjects:
      raise ContractError(
        f"$.artifacts[{index}].subjects: unknown artifact ids: "
        + ", ".join(unknown_subjects)
      )
    if item["id"] in item["subjects"]:
      raise ContractError(f"$.artifacts[{index}].subjects: artifact cannot reference itself")
    if item["type"] == "oci" and "ociDigest" not in item:
      raise ContractError(f"$.artifacts[{index}].ociDigest: required for OCI artifacts")
    if item["type"] != "oci" and "ociDigest" in item:
      raise ContractError(f"$.artifacts[{index}].ociDigest: allowed only for OCI artifacts")

  carrier_ids = {
    item["id"] for item in artifacts if item["type"] in {"deb", "rootfs", "oci"}
  }
  for evidence_type in ("spdx", "cyclonedx", "provenance"):
    covered = {
      subject
      for item in artifacts
      if item["type"] == evidence_type
      for subject in item["subjects"]
    }
    missing_coverage = sorted(carrier_ids - covered)
    if missing_coverage:
      raise ContractError(
        f"$.artifacts: {evidence_type} does not cover: " + ", ".join(missing_coverage)
      )


def _validate_command_catalog(value):
  commands = value["commands"]
  _validate_sorted_unique(commands, lambda item: item["id"], "$.commands")
  if len(commands) != value["inventoryCount"]:
    raise ContractError("$.commands: length does not match inventoryCount")
  editor_prefix = value["editor"] + "."
  for index, command in enumerate(commands):
    prefix = f"$.commands[{index}]"
    if not command["id"].startswith(editor_prefix):
      raise ContractError(prefix + ".id: must use the catalog editor prefix")
    _validate_relative_path(command["desktop"]["path"], prefix + ".desktop.path")
    for field in ("contexts", "permissions", "tests"):
      if command[field] != sorted(set(command[field])):
        raise ContractError(f"{prefix}.{field}: values must be sorted and unique")
    if command["disposition"] == "mapped":
      if "mobile" not in command:
        raise ContractError(prefix + ".mobile: mobile mapping is required")
      if "adr" in command:
        raise ContractError(prefix + ".adr: mapped commands cannot be excluded")
      entrypoints = command["mobile"]["entrypoints"]
      if entrypoints != sorted(set(entrypoints)):
        raise ContractError(prefix + ".mobile.entrypoints: values must be sorted and unique")
    else:
      if "adr" not in command:
        raise ContractError(prefix + ".adr: ADR is required for excluded commands")
      if "mobile" in command:
        raise ContractError(prefix + ".mobile: excluded commands cannot have a mapping")
      _validate_relative_path(command["adr"], prefix + ".adr")
      if not command["adr"].startswith("docs/adr/"):
        raise ContractError(prefix + ".adr: exclusions must reference docs/adr")


def _validate_corpus_manifest(value):
  entries = value["entries"]
  _validate_sorted_unique(entries, lambda item: item["id"], "$.entries")
  paths = [item["path"] for item in entries]
  if len(paths) != len(set(paths)):
    raise ContractError("$.entries: paths must be unique")
  editor_by_format = {
    "docx": "word",
    "odt": "word",
    "xlsx": "spreadsheet",
    "ods": "spreadsheet",
    "pptx": "presentation",
    "odp": "presentation",
    "pdf": "pdf",
  }
  for index, entry in enumerate(entries):
    prefix = f"$.entries[{index}]"
    _validate_relative_path(entry["path"], prefix + ".path")
    if entry["editor"] != editor_by_format[entry["format"]]:
      raise ContractError(prefix + ".editor: does not match format")
    for field in ("purposes", "features"):
      if entry[field] != sorted(set(entry[field])):
        raise ContractError(f"{prefix}.{field}: values must be sorted and unique")
  release_formats = set(editor_by_format)
  present_formats = {item["format"] for item in entries}
  missing_release = sorted(release_formats - present_formats)
  if missing_release:
    raise ContractError("$.entries: missing release formats: " + ", ".join(missing_release))
  required_performance = {"docx", "xlsx", "pptx", "pdf"}
  performance_formats = {
    item["format"] for item in entries if "performance" in item["purposes"]
  }
  missing_performance = sorted(required_performance - performance_formats)
  if missing_performance:
    if value["readiness"] != "INFRA_INCOMPLETE":
      raise ContractError(
        "$.readiness: READY with missing performance formats: "
        + ", ".join(missing_performance)
      )
  elif value["readiness"] != "READY":
    raise ContractError("$.readiness: must be READY when performance corpus is complete")
  if value["missingPerformanceFormats"] != missing_performance:
    raise ContractError(
      "$.missingPerformanceFormats: must exactly match missing performance formats"
    )


def _validate_gate_result(value):
  if value["finishedAt"] < value["startedAt"]:
    raise ContractError("$.finishedAt: must not precede startedAt")
  status = value["status"]
  if status == "PASS" and "errorCode" in value:
    raise ContractError("$.errorCode: successful gates cannot have an errorCode")
  if status != "PASS" and "errorCode" not in value:
    raise ContractError("$.errorCode: errorCode is required for non-passing gates")
  dimensions = value["environment"]["dimensions"]
  _validate_sorted_unique(dimensions, lambda item: item["name"], "$.environment.dimensions")
  metrics = value["metrics"]
  _validate_sorted_unique(metrics, lambda item: item["name"], "$.metrics")
  evidence = value["evidence"]
  _validate_sorted_unique(evidence, lambda item: item["path"], "$.evidence")
  evidence_prefix = f'evidence/raw/{value["runId"]}/{value["gateId"]}/'
  for index, item in enumerate(evidence):
    path = item["path"]
    _validate_relative_path(path, f"$.evidence[{index}].path")
    if not path.startswith(evidence_prefix):
      raise ContractError(
        f"$.evidence[{index}].path: must use immutable raw evidence prefix {evidence_prefix}"
      )


def _validate_performance_samples(value):
  if value["finishedAt"] < value["startedAt"]:
    raise ContractError("$.finishedAt: must not precede startedAt")
  _validate_sorted_unique(
    value["environment"]["dimensions"],
    lambda item: item["name"],
    "$.environment.dimensions",
  )

  policy = MOBILE_PERFORMANCE_POLICY[value["gateId"]]
  expected_field = policy["field"]
  present_fields = {
    item["field"]
    for item in MOBILE_PERFORMANCE_POLICY.values()
    if item["field"] in value
  }
  if value["collectionStatus"] == "INFRA_INCOMPLETE":
    if "errorCode" not in value:
      raise ContractError(
        "$.errorCode: infrastructure-incomplete samples require an error"
      )
    if present_fields or "attestation" in value:
      raise ContractError(
        "$: infrastructure-incomplete samples cannot contain measurements or attestation"
      )
    return

  if "errorCode" in value:
    raise ContractError("$.errorCode: complete samples cannot have an error")
  if "attestation" not in value:
    raise ContractError("$.attestation: complete samples require locked runtime evidence")
  if present_fields != {expected_field}:
    raise ContractError(
      f"$: complete {value['gateId']} samples require only {expected_field}"
    )

  attestation = value["attestation"]
  if attestation["warmupFormats"] != list(MOBILE_PERFORMANCE_FORMATS):
    raise ContractError(
      "$.attestation.warmupFormats: docx, pdf, pptx and xlsx are required"
    )
  records = [
    attestation["androidTargets"],
    attestation["deviceFacts"],
    *attestation["traces"],
  ]
  _validate_sorted_unique(records, lambda item: item["path"], "$.attestation evidence")
  for index, item in enumerate(records):
    _validate_relative_path(item["path"], f"$.attestation evidence[{index}].path")

  required_formats = set(MOBILE_PERFORMANCE_FORMATS)
  if expected_field == "openTime":
    _validate_sorted_unique(
      value[expected_field],
      lambda item: item["format"],
      "$.openTime",
    )
    formats = {item["format"] for item in value[expected_field]}
    if formats != required_formats:
      raise ContractError("$.openTime: must contain docx, pdf, pptx and xlsx")
    for index, item in enumerate(value[expected_field]):
      if len(item["milliseconds"]) != policy["sample_count"]:
        raise ContractError(
          f"$.openTime[{index}].milliseconds: exactly "
          f"{policy['sample_count']} samples are required"
        )
  elif expected_field == "commands":
    _validate_sorted_unique(
      value[expected_field],
      lambda item: item["id"],
      "$.commands",
    )
    for index, item in enumerate(value[expected_field]):
      if len(item["milliseconds"]) < policy["minimum_samples"]:
        raise ContractError(
          f"$.commands[{index}].milliseconds: at least "
          f"{policy['minimum_samples']} samples are required"
        )
  else:
    _validate_sorted_unique(
      value[expected_field],
      lambda item: item["format"],
      "$.gestures",
    )
    formats = {item["format"] for item in value[expected_field]}
    if formats != required_formats:
      raise ContractError("$.gestures: must contain docx, pdf, pptx and xlsx")
    for format_index, item in enumerate(value[expected_field]):
      rounds = item["rounds"]
      _validate_sorted_unique(
        rounds,
        lambda round_item: round_item["round"],
        f"$.gestures[{format_index}].rounds",
      )
      if tuple(round_item["round"] for round_item in rounds) != policy["rounds"]:
        raise ContractError(
          f"$.gestures[{format_index}].rounds: rounds 1, 2 and 3 are required"
        )


def _validate_blocking_matrix(gates, path):
  for index, gate in enumerate(gates):
    should_block = gate["category"] != "ios"
    if gate["blocking"] != should_block:
      raise ContractError(
        f"{path}[{index}].blocking: only iOS evidence may be non-blocking"
      )


def _validate_release_policy(value):
  gates = value["gates"]
  _validate_sorted_unique(gates, lambda item: item["id"], "$.gates")
  if not any(item["blocking"] for item in gates):
    raise ContractError("$.gates: at least one blocking gate is required")
  _validate_blocking_matrix(gates, "$.gates")


def _validate_release_evidence(value):
  gates = value["gates"]
  _validate_sorted_unique(gates, lambda item: item["gateId"], "$.gates")
  gate_by_id = {item["gateId"]: item for item in gates}
  for index, gate in enumerate(gates):
    if gate["status"] == "PASS" and "errorCode" in gate:
      raise ContractError(f"$.gates[{index}].errorCode: successful gate cannot have an error")
    if gate["status"] != "PASS" and "errorCode" not in gate:
      raise ContractError(f"$.gates[{index}].errorCode: non-passing gate requires an error")
  for field in ("blockers", "nonBlockingIssues"):
    _validate_sorted_unique(value[field], lambda item: item["gateId"], f"$.{field}")
  blocker_by_id = {item["gateId"]: item for item in value["blockers"]}
  advisory_by_id = {item["gateId"]: item for item in value["nonBlockingIssues"]}
  if set(blocker_by_id) & set(advisory_by_id):
    raise ContractError("$.blockers: a gate cannot be blocking and non-blocking")
  for gate_id, gate in gate_by_id.items():
    issue = blocker_by_id.get(gate_id) if gate["blocking"] else advisory_by_id.get(gate_id)
    if gate["status"] == "PASS":
      if issue:
        raise ContractError(f"$.gates: passing gate is reported as an issue: {gate_id}")
    elif issue is None:
      classification = "blocking" if gate["blocking"] else "non-blocking"
      raise ContractError(
        f"$.gates: unreported non-passing {classification} gate: {gate_id}"
      )
    elif issue["reason"] != gate["status"]:
      raise ContractError(f"$.gates: issue reason does not match status: {gate_id}")
  for gate_id, issue in blocker_by_id.items():
    gate = gate_by_id.get(gate_id)
    if gate and not gate["blocking"]:
      raise ContractError(f"$.blockers: non-blocking gate is classified as blocking: {gate_id}")
    if gate and issue["reason"] == "MISSING":
      raise ContractError(f"$.blockers: present gate cannot be missing: {gate_id}")
  for gate_id, issue in advisory_by_id.items():
    gate = gate_by_id.get(gate_id)
    if gate and gate["blocking"]:
      raise ContractError(f"$.nonBlockingIssues: blocking gate is classified as non-blocking: {gate_id}")
    if gate and issue["reason"] == "MISSING":
      raise ContractError(f"$.nonBlockingIssues: present gate cannot be missing: {gate_id}")
  expected_outcome = "BLOCKED" if value["blockers"] else "PASS"
  if value["outcome"] != expected_outcome:
    raise ContractError("$.outcome: does not match blocking gate results")


def _validate_gate_catalog(value):
  gates = value["gates"]
  _validate_sorted_unique(gates, lambda item: item["id"], "$.gates")
  _validate_blocking_matrix(gates, "$.gates")


SEMANTIC_VALIDATORS = {
  "source-lock": _validate_source_lock,
  "toolchain-lock": _validate_toolchain_lock,
  "image-lock": _validate_image_lock,
  "build-manifest": _validate_build_manifest,
  "artifact-manifest": _validate_artifact_manifest,
  "command-catalog": _validate_command_catalog,
  "corpus-manifest": _validate_corpus_manifest,
  "performance-samples": _validate_performance_samples,
  "gate-result": _validate_gate_result,
  "release-policy": _validate_release_policy,
  "release-evidence": _validate_release_evidence,
  "gate-catalog": _validate_gate_catalog,
}


def validate_contract(value, contract, schema_dir):
  try:
    schema_name = CONTRACT_SCHEMAS[contract]
  except KeyError as error:
    raise ContractError("unknown contract: " + contract) from error
  store = SchemaStore(schema_dir)
  schema = store.load(schema_name)
  _check_canonical_value(value)
  _validate_schema(value, schema, store, schema_name)
  SEMANTIC_VALIDATORS[contract](value)


def validate_entrypoints(value):
  _check_canonical_value(value)
  if not isinstance(value, dict):
    raise ContractError("entrypoint contract must be an object")
  expected_top_level = {"schemaVersion", "entrypoints", "exitCodes"}
  unknown_top_level = sorted(set(value) - expected_top_level)
  if unknown_top_level:
    raise ContractError("entrypoint contract has unknown properties: " + ", ".join(unknown_top_level))
  if value.get("schemaVersion") != 1:
    raise ContractError("entrypoint schemaVersion must be 1")
  entrypoints = value.get("entrypoints")
  if not isinstance(entrypoints, list):
    raise ContractError("entrypoints must be an array")
  expected_entrypoint_keys = {"id", "path", "networkPolicy", "inputs", "outputs"}
  for index, item in enumerate(entrypoints):
    if not isinstance(item, dict):
      raise ContractError(f"$.entrypoints[{index}]: expected object")
    missing = sorted(expected_entrypoint_keys - set(item))
    if missing:
      raise ContractError(f"$.entrypoints[{index}]: missing properties: " + ", ".join(missing))
    unknown = sorted(set(item) - expected_entrypoint_keys)
    if unknown:
      raise ContractError(f"$.entrypoints[{index}]: unknown properties: " + ", ".join(unknown))
  expected_ids = ["bootstrap-source", "build", "package", "verify"]
  ids = [item.get("id") for item in entrypoints]
  if ids != expected_ids:
    raise ContractError("entrypoints must use the stable execution order")
  expected_network = ["online-only", "none", "none", "none"]
  if [item.get("networkPolicy") for item in entrypoints] != expected_network:
    raise ContractError("entrypoint network policies are not fail-closed")
  for index, item in enumerate(entrypoints):
    _validate_relative_path(item.get("path", ""), f"$.entrypoints[{index}].path")
    for field in ("inputs", "outputs"):
      paths = item[field]
      if not isinstance(paths, list) or not paths:
        raise ContractError(f"$.entrypoints[{index}].{field}: expected non-empty array")
      if not all(isinstance(path, str) for path in paths):
        raise ContractError(f"$.entrypoints[{index}].{field}: paths must be strings")
      if len(paths) != len(set(paths)):
        raise ContractError(f"$.entrypoints[{index}].{field}: paths must be unique")
      for path_index, path in enumerate(paths):
        _validate_relative_path(path, f"$.entrypoints[{index}].{field}[{path_index}]")
  expected_exit_codes = {
    "0": "success",
    "2": "contract or invocation error",
    "3": "locked input missing or mismatched",
    "4": "build package or verification failure",
  }
  if value.get("exitCodes") != expected_exit_codes:
    raise ContractError("entrypoint exitCodes do not match the stable contract")


def _schema_dir_from_script():
  return Path(__file__).resolve().parents[2] / "schemas"


def _write_sidecar(path, digest):
  path = Path(path)
  path.write_text(digest + "\n", encoding="ascii", newline="\n")


def main(argv=None):
  parser = argparse.ArgumentParser(description="Validate and canonicalize JetOnlyOffice contracts")
  subparsers = parser.add_subparsers(dest="command", required=True)

  validate_parser = subparsers.add_parser("validate")
  validate_parser.add_argument("--contract", required=True, choices=sorted(CONTRACT_SCHEMAS))
  validate_parser.add_argument("path")
  validate_parser.add_argument("--schema-dir", default=str(_schema_dir_from_script()))

  entrypoint_parser = subparsers.add_parser("validate-entrypoints")
  entrypoint_parser.add_argument("path")

  canonicalize_parser = subparsers.add_parser("canonicalize")
  canonicalize_parser.add_argument("path")
  canonicalize_parser.add_argument("--output")

  digest_parser = subparsers.add_parser("digest")
  digest_parser.add_argument("path")
  digest_parser.add_argument("--sidecar")

  args = parser.parse_args(argv)
  try:
    value = load_json(args.path)
    if args.command == "validate":
      validate_contract(value, args.contract, args.schema_dir)
    elif args.command == "validate-entrypoints":
      validate_entrypoints(value)
    elif args.command == "canonicalize":
      output = canonical_json_bytes(value) + b"\n"
      if args.output:
        Path(args.output).write_bytes(output)
      else:
        sys.stdout.buffer.write(output)
    elif args.command == "digest":
      digest = canonical_sha256(value)
      if args.sidecar:
        _write_sidecar(args.sidecar, digest)
      print(digest)
    return 0
  except ContractError as error:
    print("contract error: " + str(error), file=sys.stderr)
    return 2


if __name__ == "__main__":
  sys.exit(main())
