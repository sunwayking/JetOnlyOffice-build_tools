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


def evaluate_performance_samples(samples, evidence, schema_dir):
  validate_contract(samples, "performance-samples", schema_dir)
  gate_id = samples["gateId"]
  result = {
    "schemaVersion": 1,
    "resultType": "gate",
    "releaseId": samples["releaseId"],
    "runId": samples["runId"],
    "gateId": gate_id,
    "category": "performance",
    "blocking": True,
    "status": "PASS",
    "attempt": 1,
    "startedAt": samples["startedAt"],
    "finishedAt": samples["finishedAt"],
    "sourceLockSha256": samples["sourceLockSha256"],
    "environment": {
      "kind": samples["environment"]["kind"],
      "fingerprint": samples["environment"]["fingerprint"],
      "dimensions": [dict(item) for item in samples["environment"]["dimensions"]],
    },
    "metrics": [],
    "evidence": [dict(evidence)],
  }

  if samples["collectionStatus"] == "INFRA_INCOMPLETE":
    result["status"] = "INFRA_INCOMPLETE"
    result["errorCode"] = samples["errorCode"]
  elif gate_id == "performance.xiaomi.open-time":
    measurements = [
      value
      for format_samples in samples["openTime"]
      for value in format_samples["milliseconds"]
    ]
    maximum = max(measurements)
    result["metrics"] = [
      {"name": "maximum-open-milliseconds", "unit": "milliseconds", "value": maximum},
      {"name": "measured-open-count", "unit": "count", "value": len(measurements)},
    ]
    if maximum > 8000:
      result["status"] = "FAIL"
      result["errorCode"] = "PERFORMANCE_OPEN_TIME_EXCEEDED"
  elif gate_id == "performance.xiaomi.command-p95":
    p95_values = []
    sample_count = 0
    for command in samples["commands"]:
      values = sorted(command["milliseconds"])
      rank = (95 * len(values) + 99) // 100
      p95_values.append(values[rank - 1])
      sample_count += len(values)
    maximum_p95 = max(p95_values)
    result["metrics"] = [
      {"name": "command-count", "unit": "count", "value": len(p95_values)},
      {
        "name": "maximum-command-p95-milliseconds",
        "unit": "milliseconds",
        "value": maximum_p95,
      },
      {"name": "measured-command-sample-count", "unit": "count", "value": sample_count},
    ]
    if maximum_p95 > 250:
      result["status"] = "FAIL"
      result["errorCode"] = "PERFORMANCE_COMMAND_P95_EXCEEDED"
  else:
    rounds = [
      round_result
      for format_samples in samples["gestures"]
      for round_result in format_samples["rounds"]
    ]
    minimum_fps = min(item["medianMilliFps"] for item in rounds)
    maximum_freeze = max(item["maxFreezeMilliseconds"] for item in rounds)
    result["metrics"] = [
      {"name": "gesture-round-count", "unit": "count", "value": len(rounds)},
      {
        "name": "maximum-freeze-milliseconds",
        "unit": "milliseconds",
        "value": maximum_freeze,
      },
      {"name": "minimum-median-milli-fps", "unit": "milli-fps", "value": minimum_fps},
    ]
    if minimum_fps < 45000 or maximum_freeze > 1000:
      result["status"] = "FAIL"
      result["errorCode"] = "PERFORMANCE_GESTURE_BUDGET_EXCEEDED"

  validate_contract(result, "gate-result", schema_dir)
  return result


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

  performance_parser = subparsers.add_parser("evaluate-performance")
  performance_parser.add_argument("--samples", required=True)
  performance_parser.add_argument("--repository-root", default=str(REPOSITORY_ROOT))
  performance_parser.add_argument("--schema-dir", default=str(_default_schema_dir()))
  performance_parser.add_argument("--output")

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
    elif args.command == "check-commands":
      value = check_command_coverage(
        [load_json(path) for path in args.catalog],
        args.required_editor,
        args.schema_dir,
      )
    else:
      samples_path = Path(args.samples).resolve()
      repository_root = Path(args.repository_root).resolve()
      try:
        relative_path = samples_path.relative_to(repository_root).as_posix()
      except ValueError as error:
        raise ContractError("performance samples must be inside repository root") from error
      payload = samples_path.read_bytes()
      evidence = {
        "path": relative_path,
        "mode": "0644",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "mediaType": "application/json",
      }
      value = evaluate_performance_samples(
        load_json(samples_path),
        evidence,
        args.schema_dir,
      )
    _write_json(value, args.output)
    return 0
  except (ContractError, OSError) as error:
    print("qa error: " + str(error), file=sys.stderr)
    return 2


if __name__ == "__main__":
  sys.exit(main())
