#!/usr/bin/env python3

import argparse
import hashlib
from pathlib import Path
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.contracts.contract_tool import (
  ContractError,
  canonical_json_bytes,
  canonical_sha256,
  load_json,
  validate_contract,
)


def verify_corpus(manifest, root, schema_dir):
  validate_contract(manifest, "corpus-manifest", schema_dir)
  root = Path(root).resolve()
  verified = 0
  total_bytes = 0
  for entry in manifest["entries"]:
    path = (root / Path(entry["path"])).resolve()
    try:
      path.relative_to(root)
    except ValueError as error:
      raise ContractError(f'{entry["id"]}: corpus path escapes root') from error
    try:
      size = path.stat().st_size
    except OSError as error:
      raise ContractError(f'{entry["id"]}: corpus file is missing: {path}') from error
    if size != entry["size"]:
      raise ContractError(
        f'{entry["id"]}: size mismatch: expected {entry["size"]}, got {size}'
      )
    digest = hashlib.sha256()
    try:
      with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
          digest.update(chunk)
    except OSError as error:
      raise ContractError(f'{entry["id"]}: cannot read corpus file: {path}') from error
    actual_digest = digest.hexdigest()
    if actual_digest != entry["sha256"]:
      raise ContractError(
        f'{entry["id"]}: SHA-256 mismatch: expected {entry["sha256"]}, got {actual_digest}'
      )
    verified += 1
    total_bytes += size
  return {
    "verified": verified,
    "bytes": total_bytes,
    "readiness": manifest["readiness"],
    "missingPerformanceFormats": manifest["missingPerformanceFormats"],
  }


def check_command_coverage(catalogs, required_editors, schema_dir):
  required = set(required_editors)
  allowed = {"word", "spreadsheet", "presentation", "pdf"}
  unknown_required = sorted(required - allowed)
  if unknown_required:
    raise ContractError("unknown required editors: " + ", ".join(unknown_required))
  by_editor = {}
  product_versions = set()
  for catalog in catalogs:
    validate_contract(catalog, "command-catalog", schema_dir)
    editor = catalog["editor"]
    if editor in by_editor:
      raise ContractError("duplicate editor catalog: " + editor)
    by_editor[editor] = catalog
    product_versions.add(catalog["productVersion"])
  missing = sorted(required - set(by_editor))
  if missing:
    raise ContractError("missing editor catalogs: " + ", ".join(missing))
  if len(product_versions) > 1:
    raise ContractError("command catalogs use different product versions")

  editors = []
  for editor in sorted(required):
    commands = by_editor[editor]["commands"]
    mapped = sum(item["disposition"] == "mapped" for item in commands)
    excluded = sum(item["disposition"] == "excluded" for item in commands)
    editors.append({
      "editor": editor,
      "total": len(commands),
      "mapped": mapped,
      "excluded": excluded,
    })
  return {
    "total": sum(item["total"] for item in editors),
    "mapped": sum(item["mapped"] for item in editors),
    "excluded": sum(item["excluded"] for item in editors),
    "editors": editors,
  }


def bind_release_policy(
  gate_catalog,
  release_id,
  product_version,
  source_lock_sha256,
  schema_dir,
):
  validate_contract(gate_catalog, "gate-catalog", schema_dir)
  policy = {
    "schemaVersion": 1,
    "policyType": "release-gates",
    "releaseId": release_id,
    "productVersion": product_version,
    "sourceLockSha256": source_lock_sha256,
    "gateCatalogSha256": canonical_sha256(gate_catalog),
    "gates": [
      {
        "id": item["id"],
        "category": item["category"],
        "blocking": item["blocking"],
      }
      for item in gate_catalog["gates"]
    ],
  }
  validate_contract(policy, "release-policy", schema_dir)
  return policy


def aggregate_release_evidence(
  policy,
  gate_results,
  run_id,
  artifact_manifest_sha256,
  schema_dir,
):
  validate_contract(policy, "release-policy", schema_dir)
  by_id = {}
  policy_by_id = {item["id"]: item for item in policy["gates"]}
  for result in gate_results:
    validate_contract(result, "gate-result", schema_dir)
    gate_id = result["gateId"]
    if gate_id in by_id:
      raise ContractError("duplicate gate result: " + gate_id)
    expected = policy_by_id.get(gate_id)
    if expected is None:
      raise ContractError("gate result is not declared by policy: " + gate_id)
    if result["releaseId"] != policy["releaseId"]:
      raise ContractError(f"{gate_id}: releaseId does not match policy")
    if result["runId"] != run_id:
      raise ContractError(f"{gate_id}: runId does not match aggregation")
    if result["sourceLockSha256"] != policy["sourceLockSha256"]:
      raise ContractError(f"{gate_id}: source lock does not match policy")
    if result["blocking"] != expected["blocking"]:
      raise ContractError(f"{gate_id}: blocking classification does not match policy")
    if result["category"] != expected["category"]:
      raise ContractError(f"{gate_id}: category does not match policy")
    by_id[gate_id] = result

  gates = []
  blockers = []
  non_blocking_issues = []
  for expected in policy["gates"]:
    gate_id = expected["id"]
    result = by_id.get(gate_id)
    if result is None:
      issue = {"gateId": gate_id, "reason": "MISSING"}
      (blockers if expected["blocking"] else non_blocking_issues).append(issue)
      continue
    gate = {
      "gateId": gate_id,
      "category": result["category"],
      "blocking": result["blocking"],
      "status": result["status"],
      "resultSha256": canonical_sha256(result),
    }
    if "errorCode" in result:
      gate["errorCode"] = result["errorCode"]
    gates.append(gate)
    if result["status"] != "PASS":
      issue = {"gateId": gate_id, "reason": result["status"]}
      (blockers if expected["blocking"] else non_blocking_issues).append(issue)

  evidence = {
    "schemaVersion": 1,
    "evidenceType": "release",
    "releaseId": policy["releaseId"],
    "productVersion": policy["productVersion"],
    "runId": run_id,
    "sourceLockSha256": policy["sourceLockSha256"],
    "artifactManifestSha256": artifact_manifest_sha256,
    "policySha256": canonical_sha256(policy),
    "outcome": "BLOCKED" if blockers else "PASS",
    "gates": gates,
    "blockers": blockers,
    "nonBlockingIssues": non_blocking_issues,
  }
  validate_contract(evidence, "release-evidence", schema_dir)
  return evidence


def _default_schema_dir():
  return REPOSITORY_ROOT / "schemas"


def _write_json(value, output):
  payload = canonical_json_bytes(value) + b"\n"
  if output:
    Path(output).write_bytes(payload)
  else:
    sys.stdout.buffer.write(payload)


def main(argv=None):
  parser = argparse.ArgumentParser(description="Run JetOnlyOffice release QA contracts")
  subparsers = parser.add_subparsers(dest="command", required=True)

  aggregate_parser = subparsers.add_parser("aggregate")
  aggregate_parser.add_argument("--policy", required=True)
  aggregate_parser.add_argument("--gate-result", action="append", default=[])
  aggregate_parser.add_argument("--run-id", required=True)
  aggregate_parser.add_argument("--artifact-manifest-sha256", required=True)
  aggregate_parser.add_argument("--schema-dir", default=str(_default_schema_dir()))
  aggregate_parser.add_argument("--output")

  bind_parser = subparsers.add_parser("bind-policy")
  bind_parser.add_argument("--gate-catalog", required=True)
  bind_parser.add_argument("--release-id", required=True)
  bind_parser.add_argument("--product-version", required=True)
  bind_parser.add_argument("--source-lock-sha256", required=True)
  bind_parser.add_argument("--schema-dir", default=str(_default_schema_dir()))
  bind_parser.add_argument("--output")

  corpus_parser = subparsers.add_parser("verify-corpus")
  corpus_parser.add_argument("--manifest", required=True)
  corpus_parser.add_argument("--root", required=True)
  corpus_parser.add_argument("--schema-dir", default=str(_default_schema_dir()))
  corpus_parser.add_argument("--output")

  commands_parser = subparsers.add_parser("check-commands")
  commands_parser.add_argument("--catalog", action="append", required=True)
  commands_parser.add_argument("--required-editor", action="append", required=True)
  commands_parser.add_argument("--schema-dir", default=str(_default_schema_dir()))
  commands_parser.add_argument("--output")

  args = parser.parse_args(argv)
  try:
    if args.command == "aggregate":
      value = aggregate_release_evidence(
        load_json(args.policy),
        [load_json(path) for path in args.gate_result],
        args.run_id,
        args.artifact_manifest_sha256,
        args.schema_dir,
      )
    elif args.command == "bind-policy":
      value = bind_release_policy(
        load_json(args.gate_catalog),
        args.release_id,
        args.product_version,
        args.source_lock_sha256,
        args.schema_dir,
      )
    elif args.command == "verify-corpus":
      value = verify_corpus(load_json(args.manifest), args.root, args.schema_dir)
    else:
      value = check_command_coverage(
        [load_json(path) for path in args.catalog],
        args.required_editor,
        args.schema_dir,
      )
    _write_json(value, args.output)
    return 0
  except (ContractError, OSError) as error:
    print("qa error: " + str(error), file=sys.stderr)
    return 2


if __name__ == "__main__":
  sys.exit(main())
