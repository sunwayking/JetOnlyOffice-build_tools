#!/usr/bin/env python3

import argparse
import hashlib
from pathlib import Path
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.contracts.contract_tool import (
  ContractError,
  MOBILE_PERFORMANCE_POLICY,
  canonical_json_bytes,
  canonical_sha256,
  load_json,
  load_json_bytes,
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


def _verify_evidence_payload(record, payload):
  if len(payload) != record["size"]:
    raise ContractError(f"release evidence size mismatch: {record['path']}")
  if hashlib.sha256(payload).hexdigest() != record["sha256"]:
    raise ContractError(f"release evidence SHA-256 mismatch: {record['path']}")


def _verify_evidence_file(record, repository_root):
  root = Path(repository_root).resolve()
  path = (root / Path(record["path"])).resolve()
  try:
    path.relative_to(root)
  except ValueError as error:
    raise ContractError(f"evidence path escapes repository root: {record['path']}") from error
  try:
    payload = path.read_bytes()
  except OSError as error:
    raise ContractError(f"cannot read release evidence: {path}") from error
  _verify_evidence_payload(record, payload)
  return path, payload


def _performance_evidence_paths(repository_root, run_id, gate_id):
  root = Path(repository_root).resolve()
  return {
    "samples": root / "evidence" / "raw" / run_id / gate_id / "samples.json",
    "receipt": root / "evidence" / "raw" / run_id / gate_id / "first-attempt.json",
    "result": root / "evidence" / "results" / run_id / gate_id / "result.json",
  }


def _performance_attestation_records(samples, repository_root):
  attestation = samples["attestation"]
  records = [
    attestation["androidTargets"],
    attestation["deviceFacts"],
    *attestation["traces"],
  ]
  verified_evidence = {
    record["path"]: _verify_evidence_file(record, repository_root)
    for record in records
  }
  targets_path, targets_payload = verified_evidence[
    attestation["androidTargets"]["path"]
  ]
  facts_path, facts_payload = verified_evidence[attestation["deviceFacts"]["path"]]
  targets = load_json_bytes(targets_payload, str(targets_path))
  facts = load_json_bytes(facts_payload, str(facts_path))
  canonical_targets_path = Path(repository_root).resolve() / "qa" / "android-targets.v1.json"
  canonical_targets = load_json(canonical_targets_path)
  if targets != canonical_targets:
    raise ContractError(
      "performance Android target snapshot does not match qa/android-targets.v1.json"
    )

  try:
    floor = targets["performanceFloor"]
    chrome_target = floor["chrome"]
    webview_target = floor["systemWebView"]
    chrome_facts = facts["chrome"]
    webview_facts = facts["systemWebView"]
    android_api_levels = {item["apiLevel"] for item in targets["androidVersions"]}
  except (KeyError, TypeError) as error:
    raise ContractError("Android target or device facts are incomplete") from error

  if facts.get("model") != floor.get("model") or facts.get("device") != floor.get("device"):
    raise ContractError("performance device does not match the locked Xiaomi target")
  if facts.get("apiLevel") not in android_api_levels:
    raise ContractError("performance device Android API is not in the locked target matrix")
  if facts.get("memoryKiB", 0) < floor.get("minimumRamMiB", 0) * 1024:
    raise ContractError("performance device memory is below the locked floor")
  if chrome_target.get("channel") != "stable":
    raise ContractError("performance Chrome target must use the stable channel")

  runtime_pairs = (
    ("chrome", chrome_target, chrome_facts),
    ("system-webview", webview_target, webview_facts),
  )
  infrastructure_codes = {
    "chrome": ("OFFICIAL_CHROME_UNLOCKED", "OFFICIAL_CHROME_LOCK_INCOMPLETE"),
    "system-webview": (
      "SYSTEM_WEBVIEW_UNLOCKED",
      "SYSTEM_WEBVIEW_LOCK_INCOMPLETE",
    ),
  }
  for name, target, _ in runtime_pairs:
    unlocked_code, incomplete_code = infrastructure_codes[name]
    if target.get("state") != "LOCKED":
      return [dict(record) for record in records], unlocked_code
    if any(
      not target.get(field)
      for field in ("package", "version", "signingCertificateSha256")
    ):
      return [dict(record) for record in records], incomplete_code

  for name, target, actual in runtime_pairs:
    for field in ("package", "version", "signingCertificateSha256"):
      if actual.get(field) != target[field]:
        raise ContractError(f"device {name} {field} does not match its lock")

  runtime_name = attestation["runtime"]
  runtime_facts = chrome_facts if runtime_name == "chrome" else webview_facts
  expected_dimensions = {
    "android-api": str(facts["apiLevel"]),
    "browser": "chrome-stable" if runtime_name == "chrome" else "system-webview",
    "browser-package": runtime_facts["package"],
    "browser-signing-certificate-sha256": runtime_facts["signingCertificateSha256"],
    "browser-version": runtime_facts["version"],
    "model": facts["model"],
    "system-webview-package": webview_facts["package"],
    "system-webview-signing-certificate-sha256": webview_facts[
      "signingCertificateSha256"
    ],
    "system-webview-version": webview_facts["version"],
  }
  actual_dimensions = {
    item["name"]: item["value"]
    for item in samples["environment"]["dimensions"]
  }
  if actual_dimensions != expected_dimensions:
    raise ContractError("performance environment does not match attested runtime facts")
  if samples["environment"]["fingerprint"] != facts.get("buildFingerprint"):
    raise ContractError("performance environment fingerprint does not match device facts")
  return [dict(record) for record in records], None


def _validate_open_sequence_trace(samples, schema_dir, repository_root):
  trace_record = samples["attestation"]["traces"][0]
  trace_path, trace_payload = _verify_evidence_file(trace_record, repository_root)
  trace = load_json_bytes(trace_payload, str(trace_path))
  validate_contract(trace, "performance-open-trace", schema_dir)

  for field in ("releaseId", "runId", "gateId", "sourceLockSha256"):
    if trace[field] != samples[field]:
      raise ContractError(f"raw open trace {field} does not match performance samples")

  raw_trace_record = trace["rawTrace"]
  raw_trace_path, raw_trace_payload = _verify_evidence_file(
    raw_trace_record,
    repository_root,
  )
  raw_trace = load_json_bytes(raw_trace_payload, str(raw_trace_path))
  validate_contract(raw_trace, "performance-browser-trace", schema_dir)
  for field in ("releaseId", "runId", "gateId", "sourceLockSha256"):
    if raw_trace[field] != samples[field]:
      raise ContractError(f"raw browser trace {field} does not match performance samples")
  if raw_trace["runtime"] != samples["attestation"]["runtime"]:
    raise ContractError("raw browser trace runtime does not match performance samples")

  collector_record = raw_trace["collector"]["executable"]
  _verify_evidence_file(collector_record, repository_root)
  raw_events = {item["id"]: item for item in raw_trace["events"]}
  referenced_ids = set()
  previous_ready = None
  traced_measurements = {}
  for sequence_event in trace["events"]:
    references = (
      (sequence_event["connectionEventId"], "connection-start"),
      (sequence_event["interactiveEventId"], "first-interactive-frame"),
      (sequence_event["collaborationEventId"], "collaboration-initialized"),
    )
    resolved = []
    for event_id, expected_type in references:
      raw_event = raw_events.get(event_id)
      if raw_event is None or raw_event["type"] != expected_type:
        raise ContractError(
          f"open sequence reference {event_id} is missing or has the wrong type"
        )
      referenced_ids.add(event_id)
      resolved.append(raw_event["timestampMilliseconds"])
    started, interactive, collaboration = resolved
    ready = max(interactive, collaboration)
    if interactive <= started or collaboration <= started:
      raise ContractError(
        "raw interactive and collaboration events must follow connection start"
      )
    if previous_ready is not None and started < previous_ready:
      raise ContractError("raw open events overlap or are out of order")
    previous_ready = ready
    if sequence_event["phase"] == "measured":
      traced_measurements.setdefault(sequence_event["format"], []).append(
        ready - started
      )
  if referenced_ids != set(raw_events):
    raise ContractError("raw browser trace must contain only referenced open events")
  sample_measurements = {
    item["format"]: item["milliseconds"]
    for item in samples["openTime"]
  }
  if traced_measurements != sample_measurements:
    raise ContractError("open-time measurements do not match raw open trace")
  return [dict(raw_trace_record), dict(collector_record)]


def _load_interaction_trace(samples, schema_dir, repository_root, contract):
  trace_record = samples["attestation"]["traces"][0]
  trace_path, trace_payload = _verify_evidence_file(trace_record, repository_root)
  trace = load_json_bytes(trace_payload, str(trace_path))
  validate_contract(trace, contract, schema_dir)
  for field in ("releaseId", "runId", "gateId", "sourceLockSha256"):
    if trace[field] != samples[field]:
      raise ContractError(f"raw interaction trace {field} does not match samples")
  if trace["runtime"] != samples["attestation"]["runtime"]:
    raise ContractError("raw interaction trace runtime does not match samples")
  collector_record = trace["collector"]["executable"]
  _verify_evidence_file(collector_record, repository_root)
  return trace, dict(collector_record)


def _validate_command_trace(samples, schema_dir, repository_root):
  trace, collector_record = _load_interaction_trace(
    samples,
    schema_dir,
    repository_root,
    "performance-command-trace",
  )
  traced = {}
  for event in trace["events"]:
    traced.setdefault(event["commandId"], []).append(
      event["effectTimestampMilliseconds"] - event["inputTimestampMilliseconds"]
    )
  traced_commands = [
    {"id": command_id, "milliseconds": milliseconds}
    for command_id, milliseconds in sorted(traced.items())
  ]
  if traced_commands != samples["commands"]:
    raise ContractError("command measurements do not match raw command trace")
  return [collector_record]


def _validate_gesture_trace(samples, schema_dir, repository_root):
  trace, collector_record = _load_interaction_trace(
    samples,
    schema_dir,
    repository_root,
    "performance-gesture-trace",
  )
  traced = {}
  for round_trace in trace["rounds"]:
    timestamps = round_trace["frameTimestampsMicroseconds"]
    intervals = [
      current - previous
      for previous, current in zip(timestamps, timestamps[1:])
    ]
    frame_rates = sorted(1000000000 // interval for interval in intervals)
    median_milli_fps = frame_rates[(len(frame_rates) - 1) // 2]
    max_freeze_milliseconds = (max(intervals) + 999) // 1000
    traced.setdefault(round_trace["format"], []).append({
      "round": round_trace["round"],
      "medianMilliFps": median_milli_fps,
      "maxFreezeMilliseconds": max_freeze_milliseconds,
    })
  traced_gestures = [
    {"format": file_format, "rounds": rounds}
    for file_format, rounds in sorted(traced.items())
  ]
  if traced_gestures != samples["gestures"]:
    raise ContractError("gesture measurements do not match raw gesture trace")
  return [collector_record]


def _evaluate_open_time(samples, policy):
  measurements = [
    value
    for format_samples in samples["openTime"]
    for value in format_samples["milliseconds"]
  ]
  maximum = max(measurements)
  metrics = [
    {"name": "maximum-open-milliseconds", "unit": "milliseconds", "value": maximum},
    {"name": "measured-open-count", "unit": "count", "value": len(measurements)},
  ]
  return metrics, policy["error_code"] if maximum > policy["maximum_milliseconds"] else None


def _evaluate_command_p95(samples, policy):
  p95_values = []
  sample_count = 0
  for command in samples["commands"]:
    values = sorted(command["milliseconds"])
    rank = (
      policy["percentile_numerator"] * len(values)
      + policy["percentile_denominator"] - 1
    ) // policy["percentile_denominator"]
    p95_values.append(values[rank - 1])
    sample_count += len(values)
  maximum_p95 = max(p95_values)
  metrics = [
    {"name": "command-count", "unit": "count", "value": len(p95_values)},
    {
      "name": "maximum-command-p95-milliseconds",
      "unit": "milliseconds",
      "value": maximum_p95,
    },
    {"name": "measured-command-sample-count", "unit": "count", "value": sample_count},
  ]
  return metrics, policy["error_code"] if maximum_p95 > policy["maximum_milliseconds"] else None


def _evaluate_gestures(samples, policy):
  rounds = [
    round_result
    for format_samples in samples["gestures"]
    for round_result in format_samples["rounds"]
  ]
  minimum_fps = min(item["medianMilliFps"] for item in rounds)
  maximum_freeze = max(item["maxFreezeMilliseconds"] for item in rounds)
  metrics = [
    {"name": "gesture-round-count", "unit": "count", "value": len(rounds)},
    {
      "name": "maximum-freeze-milliseconds",
      "unit": "milliseconds",
      "value": maximum_freeze,
    },
    {"name": "minimum-median-milli-fps", "unit": "milli-fps", "value": minimum_fps},
  ]
  exceeded = (
    minimum_fps < policy["minimum_milli_fps"]
    or maximum_freeze > policy["maximum_freeze_milliseconds"]
  )
  return metrics, policy["error_code"] if exceeded else None


PERFORMANCE_EVALUATORS = {
  "commands": _evaluate_command_p95,
  "gestures": _evaluate_gestures,
  "openTime": _evaluate_open_time,
}


def _evaluate_performance_payload(
  samples,
  evidence,
  schema_dir,
  repository_root,
  samples_payload,
):
  _verify_evidence_payload(evidence, samples_payload)
  evidence_samples = load_json_bytes(samples_payload, evidence["path"])
  if evidence_samples != samples:
    raise ContractError("performance samples do not match their hashed evidence bytes")
  validate_contract(samples, "performance-samples", schema_dir)
  gate_id = samples["gateId"]
  policy = MOBILE_PERFORMANCE_POLICY[gate_id]
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
  else:
    attestation_records, infrastructure_error = _performance_attestation_records(
      samples,
      repository_root,
    )
    result["evidence"].extend(attestation_records)
    result["evidence"].sort(key=lambda item: item["path"])
    if infrastructure_error:
      result["status"] = "INFRA_INCOMPLETE"
      result["errorCode"] = infrastructure_error
    else:
      trace_validators = {
        "commands": _validate_command_trace,
        "gestures": _validate_gesture_trace,
        "openTime": _validate_open_sequence_trace,
      }
      result["evidence"].extend(
        trace_validators[policy["field"]](samples, schema_dir, repository_root)
      )
      result["evidence"].sort(key=lambda item: item["path"])
      metrics, error_code = PERFORMANCE_EVALUATORS[policy["field"]](samples, policy)
      result["metrics"] = metrics
      if error_code:
        result["status"] = "FAIL"
        result["errorCode"] = error_code

  validate_contract(result, "gate-result", schema_dir)
  return result


def evaluate_performance_samples(samples, evidence, schema_dir, repository_root):
  _, samples_payload = _verify_evidence_file(evidence, repository_root)
  return _evaluate_performance_payload(
    samples,
    evidence,
    schema_dir,
    repository_root,
    samples_payload,
  )


def aggregate_release_evidence(
  policy,
  gate_results,
  run_id,
  artifact_manifest_sha256,
  schema_dir,
  repository_root,
):
  validate_contract(policy, "release-policy", schema_dir)
  by_id = {}
  policy_by_id = {item["id"]: item for item in policy["gates"]}
  for result in gate_results:
    validate_contract(result, "gate-result", schema_dir)
    for record in result["evidence"]:
      _verify_evidence_file(record, repository_root)
    if result["category"] == "performance":
      expected_sample_path = _performance_evidence_paths(
        repository_root,
        result["runId"],
        result["gateId"],
      )["samples"].relative_to(Path(repository_root).resolve()).as_posix()
      sample_records = [
        record
        for record in result["evidence"]
        if record["path"] == expected_sample_path
      ]
      if len(sample_records) != 1:
        raise ContractError(
          f"{result['gateId']}: exactly one canonical performance sample is required"
        )
      sample_record = sample_records[0]
      _, sample_payload = _verify_evidence_file(sample_record, repository_root)
      samples = load_json_bytes(sample_payload, sample_record["path"])
      recomputed = _evaluate_performance_payload(
        samples,
        sample_record,
        schema_dir,
        repository_root,
        sample_payload,
      )
      if canonical_sha256(recomputed) != canonical_sha256(result):
        raise ContractError(
          f"{result['gateId']}: result does not match machine recomputation"
        )

      receipt_path = _performance_evidence_paths(
        repository_root,
        result["runId"],
        result["gateId"],
      )["receipt"]
      receipt = load_json(receipt_path)
      validate_contract(receipt, "performance-attempt", schema_dir)
      expected_receipt = {
        "schemaVersion": 1,
        "attemptType": "performance-first-attempt",
        "releaseId": result["releaseId"],
        "runId": result["runId"],
        "gateId": result["gateId"],
        "sourceLockSha256": result["sourceLockSha256"],
        "samplesSha256": sample_record["sha256"],
        "resultSha256": canonical_sha256(result),
        "status": result["status"],
      }
      if receipt != expected_receipt:
        raise ContractError(
          f"{result['gateId']}: first-attempt receipt does not match result"
        )
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


def _write_json(value, output, exclusive=False):
  payload = canonical_json_bytes(value) + b"\n"
  if output:
    output_path = Path(output)
    if exclusive:
      output_path.parent.mkdir(parents=True, exist_ok=True)
      with output_path.open("xb") as stream:
        stream.write(payload)
    else:
      output_path.write_bytes(payload)
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
  aggregate_parser.add_argument("--repository-root", default=str(REPOSITORY_ROOT))
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
  performance_parser.add_argument("--output", required=True)

  args = parser.parse_args(argv)
  first_attempt_receipt = None
  receipt_path = None
  try:
    if args.command == "aggregate":
      repository_root = Path(args.repository_root).resolve()
      gate_results = []
      for path in args.gate_result:
        result_path = Path(path).resolve()
        result = load_json(result_path)
        if result.get("category") == "performance":
          canonical_path = _performance_evidence_paths(
            repository_root,
            result["runId"],
            result["gateId"],
          )["result"]
          if result_path != canonical_path:
            raise ContractError(
              f"performance gate result must use canonical first-attempt path: {canonical_path}"
            )
        gate_results.append(result)
      value = aggregate_release_evidence(
        load_json(args.policy),
        gate_results,
        args.run_id,
        args.artifact_manifest_sha256,
        args.schema_dir,
        repository_root,
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
      path_parts = relative_path.split("/")
      if (
        len(path_parts) != 5
        or path_parts[0:2] != ["evidence", "raw"]
        or path_parts[4] != "samples.json"
      ):
        raise ContractError(
          "performance samples must use evidence/raw/<run-id>/<gate-id>/samples.json"
        )
      path_run_id, path_gate_id = path_parts[2:4]
      evidence_paths = _performance_evidence_paths(
        repository_root,
        path_run_id,
        path_gate_id,
      )
      canonical_output = evidence_paths["result"]
      output_path = Path(args.output).resolve()
      if output_path != canonical_output:
        raise ContractError(
          f"performance gate result must use canonical first-attempt result path: {canonical_output}"
        )
      receipt_path = evidence_paths["receipt"]
      if output_path.exists() or receipt_path.exists():
        raise ContractError(
          "first-attempt gate result or receipt already exists: "
          f"{canonical_output}"
        )
      payload = samples_path.read_bytes()
      samples = load_json_bytes(payload, str(samples_path))
      if samples.get("runId") != path_run_id or samples.get("gateId") != path_gate_id:
        raise ContractError("performance sample identity does not match its immutable path")
      evidence = {
        "path": relative_path,
        "mode": "0644",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "mediaType": "application/json",
      }
      value = _evaluate_performance_payload(
        samples,
        evidence,
        args.schema_dir,
        repository_root,
        payload,
      )
      first_attempt_receipt = {
        "schemaVersion": 1,
        "attemptType": "performance-first-attempt",
        "releaseId": value["releaseId"],
        "runId": value["runId"],
        "gateId": value["gateId"],
        "sourceLockSha256": value["sourceLockSha256"],
        "samplesSha256": evidence["sha256"],
        "resultSha256": canonical_sha256(value),
        "status": value["status"],
      }
      validate_contract(first_attempt_receipt, "performance-attempt", args.schema_dir)
    if first_attempt_receipt is not None:
      _write_json(first_attempt_receipt, receipt_path, exclusive=True)
    _write_json(
      value,
      args.output,
      exclusive=args.command == "evaluate-performance" and bool(args.output),
    )
    return 0
  except (ContractError, OSError) as error:
    print("qa error: " + str(error), file=sys.stderr)
    return 2


if __name__ == "__main__":
  sys.exit(main())
