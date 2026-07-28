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
}

EXPECTED_ENVIRONMENT = {
  "timezone": "UTC",
  "locale": "C.UTF-8",
  "umask": "022",
  "pythonHashSeed": "0",
  "buildPath": "/work",
  "concurrency": 4,
}

MAX_SAFE_INTEGER = 9007199254740991


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
  if (
    candidate.is_absolute()
    or value in ("", ".")
    or "\\" in value
    or "//" in value
    or any(part in ("", ".", "..") for part in value.split("/"))
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


SEMANTIC_VALIDATORS = {
  "source-lock": _validate_source_lock,
  "toolchain-lock": _validate_toolchain_lock,
  "image-lock": _validate_image_lock,
  "build-manifest": _validate_build_manifest,
  "artifact-manifest": _validate_artifact_manifest,
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
