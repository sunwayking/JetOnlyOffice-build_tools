import copy
from contextlib import contextmanager, redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.contracts.contract_tool import ContractError, load_json, validate_contract
from scripts.qa.qa_tool import (
  aggregate_release_evidence,
  bind_release_policy,
  check_command_coverage,
  evaluate_performance_samples,
  main,
  verify_corpus,
)


SHA1 = "a" * 40
SHA256 = "b" * 64


def command_catalog():
  return {
    "schemaVersion": 1,
    "catalogType": "command",
    "productVersion": "9.4.0",
    "editor": "word",
    "sourceCommit": SHA1,
    "inventorySha256": SHA256,
    "inventoryCount": 2,
    "commands": [
      {
        "id": "word.extension.macros",
        "disposition": "excluded",
        "desktop": {
          "path": "apps/documenteditor/main/app/controller/Toolbar.js",
          "symbol": "onMacros",
        },
        "contexts": ["document"],
        "permissions": ["edit"],
        "adr": "docs/adr/0067-mobile-command-exclusions.md",
        "tests": ["word.macros.excluded-by-adr"],
      },
      {
        "id": "word.text.bold",
        "disposition": "mapped",
        "desktop": {
          "path": "apps/documenteditor/main/app/controller/Toolbar.js",
          "symbol": "onBold",
        },
        "contexts": ["text"],
        "permissions": ["edit"],
        "mobile": {
          "provider": "word",
          "entrypoints": ["edit.text.bold"],
        },
        "tests": ["word.bold.mobile-and-desktop"],
      },
    ],
  }


def corpus_manifest():
  formats = [
    ("docx", "word", ["functional", "performance"]),
    ("odp", "presentation", ["functional"]),
    ("ods", "spreadsheet", ["functional"]),
    ("odt", "word", ["functional"]),
    ("pdf", "pdf", ["functional", "performance"]),
    ("pptx", "presentation", ["functional", "performance"]),
    ("xlsx", "spreadsheet", ["functional", "performance"]),
  ]
  return {
    "schemaVersion": 1,
    "manifestType": "corpus",
    "corpusId": "jetonlyoffice-9.4-v1",
    "productVersion": "9.4.0",
    "readiness": "READY",
    "missingPerformanceFormats": [],
    "entries": [
      {
        "id": "standard-" + file_format,
        "editor": editor,
        "format": file_format,
        "path": f"qa/corpora/standard.{file_format}",
        "sha256": SHA256,
        "size": 1024,
        "license": "CC0-1.0",
        "provenance": "Deterministic JetOnlyOffice QA generator",
        "purposes": purposes,
        "features": ["open", "reopen", "save"],
      }
      for file_format, editor, purposes in formats
    ],
  }


def gate_result(status="PASS", blocking=True):
  value = {
    "schemaVersion": 1,
    "resultType": "gate",
    "releaseId": "jetonlyoffice-v9.4.0",
    "runId": "release-run-001",
    "gateId": "browser.desktop.chromium",
    "category": "browser",
    "blocking": blocking,
    "status": status,
    "attempt": 1,
    "startedAt": 1785196800,
    "finishedAt": 1785196860,
    "sourceLockSha256": SHA256,
    "environment": {
      "kind": "browser",
      "fingerprint": "chromium-138-linux-amd64",
      "dimensions": [
        {"name": "browser", "value": "chromium"},
        {"name": "platform", "value": "linux-amd64"},
      ],
    },
    "metrics": [
      {"name": "failed-tests", "unit": "count", "value": 0},
      {"name": "passed-tests", "unit": "count", "value": 42},
    ],
    "evidence": [
      {
        "path": "evidence/raw/release-run-001/browser.desktop.chromium/results.json",
        "mode": "0644",
        "sha256": SHA256,
        "size": 42,
        "mediaType": "application/json",
      }
    ],
  }
  if status != "PASS":
    value["errorCode"] = "BROWSER_TEST_FAILED"
  return value


def release_policy():
  return {
    "schemaVersion": 1,
    "policyType": "release-gates",
    "releaseId": "jetonlyoffice-v9.4.0",
    "productVersion": "9.4.0",
    "sourceLockSha256": SHA256,
    "gateCatalogSha256": "d" * 64,
    "gates": [
      {
        "id": "browser.desktop.chromium",
        "category": "browser",
        "blocking": True,
      },
      {
        "id": "ios.safari",
        "category": "ios",
        "blocking": False,
      },
    ],
  }


def performance_samples(gate_id):
  value = {
    "schemaVersion": 1,
    "sampleType": "mobile-performance",
    "releaseId": "jetonlyoffice-v9.4.0",
    "runId": "release-run-001",
    "gateId": gate_id,
    "sourceLockSha256": SHA256,
    "startedAt": 1785196800,
    "finishedAt": 1785196860,
    "collectionStatus": "COMPLETE",
    "environment": {
      "kind": "device",
      "fingerprint": "xiaomi-pond-android-16-chrome-138",
      "dimensions": [
        {"name": "android-api", "value": "36"},
        {"name": "browser", "value": "chrome-stable"},
        {"name": "model", "value": "2409BRN2CC"},
      ],
    },
  }
  if gate_id == "performance.xiaomi.open-time":
    value["openTime"] = [
      {"format": file_format, "milliseconds": [8000] * 10}
      for file_format in ("docx", "pdf", "pptx", "xlsx")
    ]
  elif gate_id == "performance.xiaomi.command-p95":
    value["commands"] = [
      {"id": "spreadsheet.cell.bold", "milliseconds": [250] * 30},
      {"id": "word.text.bold", "milliseconds": list(range(1, 31))},
    ]
  else:
    value["gestures"] = [
      {
        "format": file_format,
        "rounds": [
          {"round": index, "medianMilliFps": 45000, "maxFreezeMilliseconds": 1000}
          for index in range(1, 4)
        ],
      }
      for file_format in ("docx", "pdf", "pptx", "xlsx")
    ]
  return value


def performance_evidence(gate_id):
  return {
    "path": f"evidence/raw/release-run-001/{gate_id}/samples.json",
    "mode": "0644",
    "sha256": SHA256,
    "size": 1024,
    "mediaType": "application/json",
  }


def _write_evidence_record(root, relative_path, value):
  path = root / Path(relative_path)
  path.parent.mkdir(parents=True, exist_ok=True)
  payload = json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"
  path.write_bytes(payload)
  return {
    "path": Path(relative_path).as_posix(),
    "mode": "0644",
    "sha256": hashlib.sha256(payload).hexdigest(),
    "size": len(payload),
    "mediaType": "application/json",
  }


@contextmanager
def attested_performance_samples(gate_id):
  with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    samples = performance_samples(gate_id)
    evidence_prefix = f"evidence/raw/release-run-001/{gate_id}"
    chrome_sha256 = "c" * 64
    webview_sha256 = "d" * 64
    targets = {
      "schemaVersion": 1,
      "androidVersions": [{"version": "16", "apiLevel": 36}],
      "performanceFloor": {
        "model": "2409BRN2CC",
        "device": "pond",
        "minimumRamMiB": 3500,
        "chrome": {
          "package": "com.android.chrome",
          "channel": "stable",
          "version": "138.0.7204.157",
          "signingCertificateSha256": chrome_sha256,
        },
        "systemWebView": {
          "package": "com.google.android.webview",
          "version": "143.0.7499.192",
          "signingCertificateSha256": webview_sha256,
        },
      },
    }
    canonical_targets_path = root / "qa" / "android-targets.v1.json"
    canonical_targets_path.parent.mkdir(parents=True)
    canonical_targets_path.write_text(json.dumps(targets), encoding="utf-8")
    facts = {
      "schemaVersion": 1,
      "model": "2409BRN2CC",
      "device": "pond",
      "apiLevel": 36,
      "buildFingerprint": "xiaomi/pond/pond:16/test/release-keys",
      "memoryKiB": 3735552,
      "chrome": {
        "package": "com.android.chrome",
        "version": "138.0.7204.157",
        "signingCertificateSha256": chrome_sha256,
      },
      "systemWebView": {
        "package": "com.google.android.webview",
        "version": "143.0.7499.192",
        "signingCertificateSha256": webview_sha256,
      },
    }
    target_record = _write_evidence_record(
      root,
      f"{evidence_prefix}/android-targets.json",
      targets,
    )
    facts_record = _write_evidence_record(
      root,
      f"{evidence_prefix}/device-facts.json",
      facts,
    )
    trace_record = _write_evidence_record(
      root,
      f"{evidence_prefix}/trace.json",
      {"traceEvents": []},
    )
    samples["environment"] = {
      "kind": "device",
      "fingerprint": facts["buildFingerprint"],
      "dimensions": [
        {"name": "android-api", "value": "36"},
        {"name": "browser", "value": "chrome-stable"},
        {"name": "browser-package", "value": "com.android.chrome"},
        {"name": "browser-signing-certificate-sha256", "value": chrome_sha256},
        {"name": "browser-version", "value": "138.0.7204.157"},
        {"name": "model", "value": "2409BRN2CC"},
        {"name": "system-webview-package", "value": "com.google.android.webview"},
        {
          "name": "system-webview-signing-certificate-sha256",
          "value": webview_sha256,
        },
        {"name": "system-webview-version", "value": "143.0.7499.192"},
      ],
    }
    samples["attestation"] = {
      "runtime": "chrome",
      "releaseBuild": True,
      "localNetwork": True,
      "staticAssetsWarmed": True,
      "warmupFormats": ["docx", "pdf", "pptx", "xlsx"],
      "androidTargets": target_record,
      "deviceFacts": facts_record,
      "traces": [trace_record],
    }
    yield samples, performance_evidence(gate_id), root


class QaContractTests(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.schema_dir = REPOSITORY_ROOT / "schemas"

  def test_command_catalog_records_every_command_as_mapped_or_adr_excluded(self):
    validate_contract(command_catalog(), "command-catalog", self.schema_dir)

    missing_mobile = command_catalog()
    del missing_mobile["commands"][1]["mobile"]
    with self.assertRaisesRegex(ContractError, "mobile mapping is required"):
      validate_contract(missing_mobile, "command-catalog", self.schema_dir)

    missing_adr = command_catalog()
    del missing_adr["commands"][0]["adr"]
    with self.assertRaisesRegex(ContractError, "ADR is required"):
      validate_contract(missing_adr, "command-catalog", self.schema_dir)

    incomplete = command_catalog()
    incomplete["commands"].pop()
    with self.assertRaisesRegex(ContractError, "does not match inventoryCount"):
      validate_contract(incomplete, "command-catalog", self.schema_dir)

  def test_corpus_manifest_covers_release_and_performance_formats(self):
    validate_contract(corpus_manifest(), "corpus-manifest", self.schema_dir)

    missing_pdf = corpus_manifest()
    missing_pdf["entries"] = [
      item for item in missing_pdf["entries"] if item["format"] != "pdf"
    ]
    with self.assertRaisesRegex(ContractError, "missing release formats: pdf"):
      validate_contract(missing_pdf, "corpus-manifest", self.schema_dir)

    no_performance_xlsx = corpus_manifest()
    xlsx = next(item for item in no_performance_xlsx["entries"] if item["format"] == "xlsx")
    xlsx["purposes"].remove("performance")
    with self.assertRaisesRegex(ContractError, "missing performance formats: xlsx"):
      validate_contract(no_performance_xlsx, "corpus-manifest", self.schema_dir)

    incomplete = corpus_manifest()
    for entry in incomplete["entries"]:
      if "performance" in entry["purposes"]:
        entry["purposes"].remove("performance")
    incomplete["readiness"] = "INFRA_INCOMPLETE"
    incomplete["missingPerformanceFormats"] = ["docx", "pdf", "pptx", "xlsx"]
    validate_contract(incomplete, "corpus-manifest", self.schema_dir)

    incomplete["missingPerformanceFormats"].pop()
    with self.assertRaisesRegex(ContractError, "must exactly match"):
      validate_contract(incomplete, "corpus-manifest", self.schema_dir)

  def test_gate_result_is_first_attempt_content_addressed_evidence(self):
    validate_contract(gate_result(), "gate-result", self.schema_dir)
    validate_contract(gate_result("INFRA_INCOMPLETE"), "gate-result", self.schema_dir)

    retried = gate_result()
    retried["attempt"] = 2
    with self.assertRaisesRegex(ContractError, "expected constant 1"):
      validate_contract(retried, "gate-result", self.schema_dir)

    unclassified = gate_result("FAIL")
    del unclassified["errorCode"]
    with self.assertRaisesRegex(ContractError, "errorCode is required"):
      validate_contract(unclassified, "gate-result", self.schema_dir)

    mutable_path = gate_result()
    mutable_path["evidence"][0]["path"] = "latest/results.json"
    with self.assertRaisesRegex(ContractError, "immutable raw evidence prefix"):
      validate_contract(mutable_path, "gate-result", self.schema_dir)

  def test_release_evidence_blocks_failures_and_incomplete_infrastructure(self):
    policy = release_policy()
    browser = gate_result()
    ios = gate_result("FAIL", blocking=False)
    ios["gateId"] = "ios.safari"
    ios["category"] = "ios"
    ios["environment"]["kind"] = "device"
    ios["environment"]["fingerprint"] = "ios-18-safari"
    ios["environment"]["dimensions"] = [
      {"name": "browser", "value": "safari"},
      {"name": "platform", "value": "ios-18"},
    ]
    ios["evidence"][0]["path"] = (
      "evidence/raw/release-run-001/ios.safari/results.json"
    )

    evidence = aggregate_release_evidence(
      policy,
      [browser, ios],
      "release-run-001",
      "c" * 64,
      self.schema_dir,
    )
    self.assertEqual("PASS", evidence["outcome"])
    self.assertEqual([], evidence["blockers"])
    self.assertEqual(
      [{"gateId": "ios.safari", "reason": "FAIL"}],
      evidence["nonBlockingIssues"],
    )
    validate_contract(evidence, "release-evidence", self.schema_dir)

    incomplete = copy.deepcopy(browser)
    incomplete["status"] = "INFRA_INCOMPLETE"
    incomplete["errorCode"] = "BROWSER_INFRA_MISSING"
    blocked = aggregate_release_evidence(
      policy,
      [incomplete, ios],
      "release-run-001",
      "c" * 64,
      self.schema_dir,
    )
    self.assertEqual("BLOCKED", blocked["outcome"])
    self.assertEqual(
      [{"gateId": "browser.desktop.chromium", "reason": "INFRA_INCOMPLETE"}],
      blocked["blockers"],
    )
    validate_contract(blocked, "release-evidence", self.schema_dir)
    hidden_failure = copy.deepcopy(blocked)
    hidden_failure["blockers"] = []
    hidden_failure["outcome"] = "PASS"
    with self.assertRaisesRegex(ContractError, "unreported non-passing blocking gate"):
      validate_contract(hidden_failure, "release-evidence", self.schema_dir)

    missing = aggregate_release_evidence(
      policy,
      [ios],
      "release-run-001",
      "c" * 64,
      self.schema_dir,
    )
    self.assertEqual(
      [{"gateId": "browser.desktop.chromium", "reason": "MISSING"}],
      missing["blockers"],
    )

  def test_corpus_verification_reads_exact_declared_bytes(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      manifest = corpus_manifest()
      payload = b"jetonlyoffice-corpus\n"
      digest = hashlib.sha256(payload).hexdigest()
      for entry in manifest["entries"]:
        path = root / Path(entry["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        entry["sha256"] = digest
        entry["size"] = len(payload)

      report = verify_corpus(manifest, root, self.schema_dir)
      self.assertEqual(7, report["verified"])
      self.assertEqual(7 * len(payload), report["bytes"])
      self.assertEqual("READY", report["readiness"])

      (root / Path(manifest["entries"][0]["path"])).write_bytes(b"drift")
      with self.assertRaisesRegex(ContractError, "size mismatch"):
        verify_corpus(manifest, root, self.schema_dir)

  def test_committed_odf_corpus_is_structurally_valid(self):
    expected = {
      "odt": "application/vnd.oasis.opendocument.text",
      "ods": "application/vnd.oasis.opendocument.spreadsheet",
      "odp": "application/vnd.oasis.opendocument.presentation",
    }
    for extension, media_type in expected.items():
      path = REPOSITORY_ROOT / "qa" / "corpus" / "generated" / f"basic.{extension}"
      with zipfile.ZipFile(path) as archive:
        self.assertEqual("mimetype", archive.infolist()[0].filename)
        self.assertEqual(zipfile.ZIP_STORED, archive.infolist()[0].compress_type)
        self.assertEqual(media_type.encode("ascii"), archive.read("mimetype"))
        for member in (
          "content.xml",
          "styles.xml",
          "meta.xml",
          "META-INF/manifest.xml",
        ):
          ET.fromstring(archive.read(member))

  def test_committed_corpus_manifest_matches_exact_bytes(self):
    manifest = load_json(REPOSITORY_ROOT / "qa" / "corpus-manifest.json")
    validate_contract(manifest, "corpus-manifest", self.schema_dir)
    report = verify_corpus(manifest, REPOSITORY_ROOT, self.schema_dir)
    self.assertEqual(7, report["verified"])
    self.assertGreater(report["bytes"], 0)
    self.assertEqual("INFRA_INCOMPLETE", report["readiness"])
    self.assertEqual(
      ["docx", "pdf", "pptx", "xlsx"],
      report["missingPerformanceFormats"],
    )

  def test_command_coverage_requires_one_complete_catalog_per_editor(self):
    catalogs = []
    for editor in ("pdf", "presentation", "spreadsheet", "word"):
      catalog = command_catalog()
      catalog["editor"] = editor
      for command in catalog["commands"]:
        command["id"] = command["id"].replace("word.", editor + ".", 1)
        if "mobile" in command:
          command["mobile"]["provider"] = editor
      catalogs.append(catalog)

    report = check_command_coverage(
      catalogs,
      ["word", "spreadsheet", "presentation", "pdf"],
      self.schema_dir,
    )
    self.assertEqual(8, report["total"])
    self.assertEqual(4, report["mapped"])
    self.assertEqual(4, report["excluded"])

    with self.assertRaisesRegex(ContractError, "missing editor catalogs: pdf"):
      check_command_coverage(catalogs[1:], ["pdf", "word"], self.schema_dir)

  def test_aggregate_cli_writes_canonical_release_evidence(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      policy_path = root / "policy.json"
      result_path = root / "browser.json"
      output_path = root / "release-evidence.json"
      policy_path.write_text(json.dumps(release_policy()), encoding="utf-8")
      result_path.write_text(json.dumps(gate_result()), encoding="utf-8")

      exit_code = main([
        "aggregate",
        "--policy",
        str(policy_path),
        "--gate-result",
        str(result_path),
        "--run-id",
        "release-run-001",
        "--artifact-manifest-sha256",
        "c" * 64,
        "--schema-dir",
        str(self.schema_dir),
        "--output",
        str(output_path),
      ])

      self.assertEqual(0, exit_code)
      raw = output_path.read_bytes()
      self.assertTrue(raw.endswith(b"\n"))
      self.assertNotIn(b" ", raw)
      output = json.loads(raw)
      self.assertEqual("PASS", output["outcome"])
      self.assertEqual(
        [{"gateId": "ios.safari", "reason": "MISSING"}],
        output["nonBlockingIssues"],
      )

  def test_committed_gate_catalog_covers_the_blocking_matrix(self):
    catalog = load_json(REPOSITORY_ROOT / "qa" / "gate-catalog.v1.json")
    validate_contract(catalog, "gate-catalog", self.schema_dir)
    gates = {item["id"]: item for item in catalog["gates"]}
    required = {
      "browser.desktop.chromium",
      "browser.desktop.firefox",
      "browser.desktop.webkit",
      "android.compat.android-10",
      "android.compat.android-16",
      "android.xiaomi.chrome-stable",
      "android.xiaomi.system-webview",
      "tablet.chrome.portrait",
      "tablet.chrome.landscape",
      "tablet.system-webview.portrait",
      "tablet.system-webview.landscape",
      "performance.xiaomi.open-time",
      "performance.xiaomi.command-p95",
      "performance.xiaomi.gesture-fps",
      "resilience.ime-composition",
      "resilience.rotation",
      "resilience.back-stack",
      "resilience.disconnect",
      "resilience.save-failure",
      "resilience.save-conflict",
      "resilience.fatal-recovery",
    }
    self.assertEqual(set(), required - set(gates))
    self.assertTrue(all(item["blocking"] for item in gates.values() if item["category"] != "ios"))
    self.assertTrue(all(not item["blocking"] for item in gates.values() if item["category"] == "ios"))

  def test_android_targets_lock_webview_without_promoting_missing_chrome(self):
    targets = load_json(REPOSITORY_ROOT / "qa" / "android-targets.v1.json")
    floor = targets["performanceFloor"]

    self.assertEqual("UNLOCKED", floor["chrome"]["state"])
    self.assertNotIn("version", floor["chrome"])
    self.assertNotIn("signingCertificateSha256", floor["chrome"])
    self.assertEqual("LOCKED", floor["systemWebView"]["state"])
    self.assertEqual("143.0.7499.192", floor["systemWebView"]["version"])
    self.assertEqual(
      "6faf3c4140407473400934d117815a21af1cfefc5c0bee61c858bc3d72ba6fe5",
      floor["systemWebView"]["signingCertificateSha256"],
    )
    self.assertEqual("UNLOCKED", targets["tablet"]["state"])

  def test_gate_catalog_binds_to_an_immutable_release_policy(self):
    catalog = load_json(REPOSITORY_ROOT / "qa" / "gate-catalog.v1.json")
    policy = bind_release_policy(
      catalog,
      "jetonlyoffice-v9.4.0",
      "9.4.0",
      SHA256,
      self.schema_dir,
    )
    validate_contract(policy, "release-policy", self.schema_dir)
    self.assertEqual(len(catalog["gates"]), len(policy["gates"]))
    self.assertEqual(
      {"id", "category", "blocking"},
      set(policy["gates"][0]),
    )
    weakened = copy.deepcopy(policy)
    browser = next(item for item in weakened["gates"] if item["category"] == "browser")
    browser["blocking"] = False
    with self.assertRaisesRegex(ContractError, "only iOS evidence may be non-blocking"):
      validate_contract(weakened, "release-policy", self.schema_dir)

  def test_performance_open_time_recomputes_all_ten_samples_per_format(self):
    with attested_performance_samples("performance.xiaomi.open-time") as fixture:
      samples, evidence, root = fixture
      result = evaluate_performance_samples(
        samples,
        evidence,
        self.schema_dir,
        root,
      )

      self.assertEqual("PASS", result["status"])
      self.assertEqual(40, next(
        metric["value"] for metric in result["metrics"]
        if metric["name"] == "measured-open-count"
      ))
      self.assertEqual(8000, next(
        metric["value"] for metric in result["metrics"]
        if metric["name"] == "maximum-open-milliseconds"
      ))
      self.assertEqual(4, len(result["evidence"]))
      validate_contract(result, "gate-result", self.schema_dir)

      samples["openTime"][0]["milliseconds"][-1] = 8001
      failed = evaluate_performance_samples(
        samples,
        evidence,
        self.schema_dir,
        root,
      )
      self.assertEqual("FAIL", failed["status"])
      self.assertEqual("PERFORMANCE_OPEN_TIME_EXCEEDED", failed["errorCode"])

  def test_performance_command_latency_uses_nearest_rank_p95(self):
    with attested_performance_samples("performance.xiaomi.command-p95") as fixture:
      samples, evidence, root = fixture
      samples["commands"][1]["milliseconds"] = [1] * 28 + [251, 1000]
      result = evaluate_performance_samples(
        samples,
        evidence,
        self.schema_dir,
        root,
      )

      self.assertEqual("FAIL", result["status"])
      self.assertEqual("PERFORMANCE_COMMAND_P95_EXCEEDED", result["errorCode"])
      self.assertEqual(251, next(
        metric["value"] for metric in result["metrics"]
        if metric["name"] == "maximum-command-p95-milliseconds"
      ))

  def test_performance_gestures_require_three_passing_rounds_per_format(self):
    with attested_performance_samples("performance.xiaomi.gesture-fps") as fixture:
      samples, evidence, root = fixture
      result = evaluate_performance_samples(
        samples,
        evidence,
        self.schema_dir,
        root,
      )
      self.assertEqual("PASS", result["status"])

      samples["gestures"][0]["rounds"][0]["medianMilliFps"] = 44999
      samples["gestures"][1]["rounds"][1]["maxFreezeMilliseconds"] = 1001
      failed = evaluate_performance_samples(
        samples,
        evidence,
        self.schema_dir,
        root,
      )
      self.assertEqual("FAIL", failed["status"])
      self.assertEqual("PERFORMANCE_GESTURE_BUDGET_EXCEEDED", failed["errorCode"])

  def test_performance_collection_can_fail_closed_as_infrastructure_incomplete(self):
    samples = performance_samples("performance.xiaomi.open-time")
    samples["collectionStatus"] = "INFRA_INCOMPLETE"
    samples["errorCode"] = "OFFICIAL_CHROME_MISSING"
    del samples["openTime"]

    result = evaluate_performance_samples(
      samples,
      performance_evidence(samples["gateId"]),
      self.schema_dir,
      REPOSITORY_ROOT,
    )
    self.assertEqual("INFRA_INCOMPLETE", result["status"])
    self.assertEqual("OFFICIAL_CHROME_MISSING", result["errorCode"])
    self.assertEqual([], result["metrics"])
    validate_contract(result, "gate-result", self.schema_dir)

  def test_performance_cli_hashes_samples_into_a_canonical_gate_result(self):
    gate_id = "performance.xiaomi.open-time"
    with attested_performance_samples(gate_id) as fixture:
      samples, _, root = fixture
      samples_path = root / "evidence" / "raw" / "release-run-001" / gate_id / "samples.json"
      output_path = root / "open-time.json"
      samples_path.parent.mkdir(parents=True, exist_ok=True)
      samples_path.write_text(
        json.dumps(samples),
        encoding="utf-8",
      )

      exit_code = main([
        "evaluate-performance",
        "--samples",
        str(samples_path),
        "--repository-root",
        str(root),
        "--schema-dir",
        str(self.schema_dir),
        "--output",
        str(output_path),
      ])

      self.assertEqual(0, exit_code)
      result = json.loads(output_path.read_bytes())
      self.assertEqual("PASS", result["status"])
      sample_record = next(
        item for item in result["evidence"] if item["path"].endswith("/samples.json")
      )
      self.assertEqual(samples_path.stat().st_size, sample_record["size"])
      self.assertEqual(
        hashlib.sha256(samples_path.read_bytes()).hexdigest(),
        sample_record["sha256"],
      )
      first_result = output_path.read_bytes()
      with redirect_stderr(io.StringIO()):
        self.assertEqual(2, main([
          "evaluate-performance",
          "--samples",
          str(samples_path),
          "--repository-root",
          str(root),
          "--schema-dir",
          str(self.schema_dir),
          "--output",
          str(output_path),
        ]))
      self.assertEqual(first_result, output_path.read_bytes())

  def test_performance_rejects_unlocked_or_mismatched_runtime_facts(self):
    with attested_performance_samples("performance.xiaomi.open-time") as fixture:
      samples, evidence, root = fixture
      target_path = root / samples["attestation"]["androidTargets"]["path"]
      targets = json.loads(target_path.read_bytes())
      del targets["performanceFloor"]["chrome"]["version"]
      canonical_target_path = root / "qa" / "android-targets.v1.json"
      canonical_target_path.write_text(json.dumps(targets), encoding="utf-8")
      target_path.write_text(json.dumps(targets), encoding="utf-8")
      samples["attestation"]["androidTargets"] = _write_evidence_record(
        root,
        samples["attestation"]["androidTargets"]["path"],
        targets,
      )

      with self.assertRaisesRegex(ContractError, "locked chrome version is missing"):
        evaluate_performance_samples(
          samples,
          evidence,
          self.schema_dir,
          root,
        )

      samples["environment"]["dimensions"][4]["value"] = "999.0"
      targets["performanceFloor"]["chrome"]["version"] = "138.0.7204.157"
      canonical_target_path.write_text(json.dumps(targets), encoding="utf-8")
      samples["attestation"]["androidTargets"] = _write_evidence_record(
        root,
        samples["attestation"]["androidTargets"]["path"],
        targets,
      )
      with self.assertRaisesRegex(ContractError, "does not match attested runtime facts"):
        evaluate_performance_samples(
          samples,
          evidence,
          self.schema_dir,
          root,
        )

  def test_performance_rejects_tampered_raw_trace_evidence(self):
    with attested_performance_samples("performance.xiaomi.open-time") as fixture:
      samples, evidence, root = fixture
      trace_path = root / samples["attestation"]["traces"][0]["path"]
      trace_path.write_bytes(trace_path.read_bytes().replace(b"[]", b"{}"))

      with self.assertRaisesRegex(ContractError, "SHA-256 mismatch"):
        evaluate_performance_samples(
          samples,
          evidence,
          self.schema_dir,
          root,
        )


if __name__ == "__main__":
  unittest.main()
