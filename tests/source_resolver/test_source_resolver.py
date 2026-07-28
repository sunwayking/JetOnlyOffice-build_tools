import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from contracts.contract_tool import validate_contract  # noqa: E402
from source_resolver import (  # noqa: E402
  ResolutionError,
  audit_report,
  materialize,
  policy_findings,
  repository_metadata,
  validate_inputs,
  verify_relationships,
)


SHA1_A = "a" * 40
SHA1_B = "b" * 40


def run_git(directory, *arguments):
  result = subprocess.run(
    ["git", *arguments],
    cwd=directory,
    capture_output=True,
    encoding="utf-8",
    errors="replace",
    check=False,
  )
  if result.returncode != 0:
    raise AssertionError(result.stderr or result.stdout)
  return result.stdout.strip()


def repository_input(identifier, commit=SHA1_A):
  return {
    "id": identifier,
    "role": "build-input",
    "checkoutPath": f"sources/{identifier}",
    "origin": f"https://github.com/sunwayking/JetOnlyOffice-{identifier}.git",
    "upstream": f"https://github.com/ONLYOFFICE/{identifier}.git",
    "commit": commit,
    "refHint": "fixed test commit",
    "projectFork": False,
    "buildInput": True,
    "active": True,
    "license": {
      "status": "declared",
      "path": "LICENSE",
      "spdx": "MIT",
    },
  }


def source_inputs():
  build_tools = repository_input("build-tools")
  del build_tools["commit"]
  build_tools["commitSource"] = "self"
  build_tools["role"] = "product-fork"
  build_tools["projectFork"] = True
  documentserver = repository_input("documentserver", SHA1_B)
  documentserver["role"] = "superproject"
  return {
    "schemaVersion": 1,
    "productVersion": "9.4.0",
    "releaseCutoff": 100,
    "baseline": {
      "repository": "documentserver",
      "commit": SHA1_B,
    },
    "repositories": [build_tools, documentserver],
    "relationships": [],
  }


def create_repository(root, name="source"):
  checkout = Path(root) / name
  checkout.mkdir()
  run_git(checkout, "init")
  run_git(checkout, "config", "user.name", "JetOnlyOffice tests")
  run_git(checkout, "config", "user.email", "tests@jetonlyoffice.invalid")
  (checkout / "LICENSE").write_text("test license\n", encoding="utf-8", newline="\n")
  (checkout / "content.txt").write_text("content\n", encoding="utf-8", newline="\n")
  run_git(checkout, "add", "LICENSE", "content.txt")
  run_git(checkout, "commit", "-m", "initial")
  commit = run_git(checkout, "rev-parse", "HEAD^{commit}")
  bare = Path(root) / (name + ".git")
  run_git(root, "clone", "--bare", str(checkout), str(bare))
  return checkout, bare, commit


class SourceResolverTests(unittest.TestCase):
  def test_repository_policy_is_strict_and_mirror_only(self):
    value = source_inputs()
    validate_inputs(value)
    value = source_inputs()
    value["repositories"][0]["origin"] = "https://github.com/ONLYOFFICE/build_tools.git"
    with self.assertRaisesRegex(ResolutionError, "sunwayking JetOnlyOffice mirror"):
      validate_inputs(value)
    value = source_inputs()
    value["repositories"][1]["branch"] = "develop"
    with self.assertRaisesRegex(ResolutionError, "unknown properties: branch"):
      validate_inputs(value)

  def test_current_policy_fails_closed_on_license_gaps(self):
    value = json.loads(
      (REPOSITORY_ROOT / "locks" / "source-inputs.v1.json").read_text(encoding="utf-8")
    )
    validate_inputs(value)
    findings = policy_findings(value)
    self.assertEqual(
      ["build-tools-data", "core-fonts", "dictionaries"],
      [finding["repository"] for finding in findings],
    )
    report = audit_report(value)
    self.assertEqual("failed", report["status"])
    self.assertTrue(all(finding["code"] == "LICENSE_INCOMPLETE" for finding in findings))

  def test_repository_metadata_uses_git_objects_and_license_bytes(self):
    with tempfile.TemporaryDirectory() as directory:
      _, bare, commit = create_repository(directory)
      repository = repository_input("source", commit)
      record = repository_metadata(repository, bare, commit)
      self.assertEqual(commit, record["commit"])
      self.assertEqual(run_git(bare, "rev-parse", commit + "^{tree}"), record["tree"])
      self.assertEqual(
        hashlib.sha256(b"test license\n").hexdigest(),
        record["license"]["sha256"],
      )

  def test_relationship_verification_rejects_gitlink_drift(self):
    with tempfile.TemporaryDirectory() as directory:
      child_checkout, child_bare, child_commit = create_repository(directory, "child")
      parent_checkout, _, _ = create_repository(directory, "parent")
      run_git(
        parent_checkout,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{child_commit},child",
      )
      run_git(parent_checkout, "commit", "-m", "add child gitlink")
      parent_commit = run_git(parent_checkout, "rev-parse", "HEAD^{commit}")
      parent_bare = Path(directory) / "parent-final.git"
      run_git(directory, "clone", "--bare", str(parent_checkout), str(parent_bare))
      inputs = {
        "relationships": [{
          "parent": "parent",
          "child": "child",
          "path": "child",
          "mode": "160000",
        }]
      }
      caches = {"parent": parent_bare, "child": child_bare}
      commits = {"parent": parent_commit, "child": child_commit}
      verify_relationships(inputs, caches, commits)
      commits["child"] = SHA1_A
      with self.assertRaisesRegex(ResolutionError, "gitlink does not match"):
        verify_relationships(inputs, caches, commits)
      self.assertTrue(child_checkout.is_dir())

  def test_materialize_produces_detached_clean_locked_checkout(self):
    with tempfile.TemporaryDirectory() as directory:
      _, bare, commit = create_repository(directory)
      repository = repository_input("source", commit)
      record = repository_metadata(repository, bare, commit)
      lock = {
        "schemaVersion": 1,
        "lockType": "source",
        "productVersion": "9.4.0",
        "baseline": {"repository": "source", "commit": commit},
        "sourceDateEpoch": record["commitTime"],
        "repositories": [record],
        "relationships": [],
      }
      validate_contract(lock, "source-lock", REPOSITORY_ROOT / "schemas")
      source_root = Path(directory) / "workspace"
      materialize(lock, {"source": bare}, source_root)
      checkout = source_root / "sources" / "source"
      self.assertEqual(commit, run_git(checkout, "rev-parse", "HEAD"))
      self.assertEqual("HEAD", run_git(checkout, "rev-parse", "--abbrev-ref", "HEAD"))
      self.assertEqual(repository["origin"], run_git(checkout, "remote", "get-url", "origin"))
      self.assertEqual("", run_git(checkout, "status", "--porcelain"))

  @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is not available")
  def test_powershell_audit_returns_incomplete_exit_code_and_report(self):
    with tempfile.TemporaryDirectory() as directory:
      report = Path(directory) / "audit.json"
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "resolve-sources.ps1"),
          "-Command",
          "Audit",
          "-AuditReport",
          str(report),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertEqual("failed", json.loads(report.read_text(encoding="utf-8"))["status"])

  @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is not available")
  def test_public_bootstrap_fails_closed_when_lock_asset_is_missing(self):
    with tempfile.TemporaryDirectory() as directory:
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "bootstrap-source.ps1"),
          "-Command",
          "Bootstrap",
          "-LockPath",
          str(Path(directory) / "missing.lock.json"),
          "-CacheDirectory",
          str(Path(directory) / "cache"),
          "-SourceDirectory",
          str(Path(directory) / "sources"),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertIn("locked source input is missing", result.stderr)


if __name__ == "__main__":
  unittest.main()
