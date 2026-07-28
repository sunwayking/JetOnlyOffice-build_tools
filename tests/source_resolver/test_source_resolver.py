import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from contracts.contract_tool import validate_contract  # noqa: E402
from source_resolver import (  # noqa: E402
  _download_anonymous_lfs_object,
  _fetch_anonymous_lfs_actions,
  LfsActionRefreshRequired,
  ResolutionError,
  audit_report,
  fetch_lfs_objects,
  license_inventory_report,
  lfs_public_audit_report,
  main,
  materialize,
  policy_findings,
  repository_license_inventory,
  repository_metadata,
  validate_inputs,
  verify_materialized,
  verify_public_mirror,
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


def add_lfs_object(root, checkout, name="asset.bin", content=b"locked lfs content\n"):
  oid = hashlib.sha256(content).hexdigest()
  (checkout / ".gitattributes").write_text(
    "*.bin filter=lfs diff=lfs merge=lfs -text\n",
    encoding="utf-8",
    newline="\n",
  )
  (checkout / name).write_text(
    "version https://git-lfs.github.com/spec/v1\n"
    f"oid sha256:{oid}\n"
    f"size {len(content)}\n",
    encoding="utf-8",
    newline="\n",
  )
  run_git(checkout, "add", ".gitattributes", name)
  run_git(checkout, "commit", "-m", "add lfs pointer")
  commit = run_git(checkout, "rev-parse", "HEAD^{commit}")
  bare = Path(root) / "lfs-source.git"
  run_git(root, "clone", "--bare", str(checkout), str(bare))
  object_path = bare / "lfs" / "objects" / oid[:2] / oid[2:4] / oid
  object_path.parent.mkdir(parents=True)
  object_path.write_bytes(content)
  return bare, commit, oid, content


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

    for invalid_expression in ("NOASSERTION", "TBD", "MIT OR", " "):
      value = source_inputs()
      value["repositories"][0]["license"]["spdx"] = invalid_expression
      with self.assertRaisesRegex(ResolutionError, "reviewed source set"):
        validate_inputs(value)

    value = source_inputs()
    value["repositories"][1]["checkoutPath"] = "C:/outside"
    with self.assertRaisesRegex(ResolutionError, "normalized and relative"):
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
    self.assertEqual(
      ["az_Latn_AZ", "ru_RU"],
      next(
        finding["unresolvedComponents"]
        for finding in findings
        if finding["repository"] == "dictionaries"
      ),
    )

  def test_incomplete_license_inventory_requires_precise_sorted_components(self):
    value = source_inputs()
    value["repositories"][1]["license"] = {
      "status": "component-scoped",
      "payloadPatterns": ["**/*.ttf"],
      "patterns": ["**/LICENSE*"],
      "reason": "A reviewed mapping is incomplete.",
      "unresolvedComponents": ["missing-font"],
    }
    validate_inputs(value)
    finding = policy_findings(value)[0]
    self.assertEqual(["missing-font"], finding["unresolvedComponents"])

    value["repositories"][1]["license"]["unresolvedComponents"] = []
    with self.assertRaisesRegex(ResolutionError, "sorted unique non-empty strings"):
      validate_inputs(value)

    value["repositories"][1]["license"]["unresolvedComponents"] = ["z", "a"]
    with self.assertRaisesRegex(ResolutionError, "sorted unique non-empty strings"):
      validate_inputs(value)

  def test_component_license_inventory_is_derived_from_locked_git_bytes(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      (checkout / "licensed").mkdir()
      (checkout / "licensed" / "Font.ttf").write_bytes(b"font one\n")
      (checkout / "licensed" / "LICENSE.txt").write_text(
        "font license\n",
        encoding="utf-8",
        newline="\n",
      )
      (checkout / "missing").mkdir()
      (checkout / "missing" / "Font.ttf").write_bytes(b"font two\n")
      run_git(checkout, "add", "licensed", "missing")
      run_git(checkout, "commit", "-m", "add component payloads")
      commit = run_git(checkout, "rev-parse", "HEAD")
      bare = Path(directory) / "inventory.git"
      run_git(directory, "clone", "--bare", str(checkout), str(bare))
      repository = repository_input("fonts", commit)
      repository["license"] = {
        "status": "component-scoped",
        "payloadPatterns": ["**/*.ttf"],
        "patterns": ["**/LICENSE*"],
        "reason": "A component license mapping is incomplete.",
        "unresolvedComponents": ["missing"],
      }

      inventory = repository_license_inventory(repository, bare, commit)

      self.assertEqual("incomplete", inventory["status"])
      self.assertEqual(
        ["licensed", "missing"],
        [component["id"] for component in inventory["components"]],
      )
      licensed = inventory["components"][0]
      self.assertEqual("review-required", licensed["status"])
      self.assertEqual(
        hashlib.sha256(b"font license\n").hexdigest(),
        licensed["candidateEvidence"][0]["sha256"],
      )
      repository["license"]["unresolvedComponents"] = ["licensed"]
      with self.assertRaisesRegex(ResolutionError, "inventory is stale"):
        repository_license_inventory(repository, bare, commit)

  def test_license_audit_reads_the_standard_git_cache_layout(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, bare, _ = create_repository(directory)
      (checkout / "missing.ttf").write_bytes(b"font\n")
      run_git(checkout, "add", "missing.ttf")
      run_git(checkout, "commit", "-m", "add unlicensed font")
      commit = run_git(checkout, "rev-parse", "HEAD^{commit}")
      run_git(bare, "fetch", str(checkout), f"{commit}:refs/heads/main")
      repository = repository_input("source", commit)
      repository["license"] = {
        "status": "missing",
        "payloadPatterns": ["**/*.ttf"],
        "reason": "The component has no reviewed license evidence.",
        "unresolvedComponents": ["missing.ttf"],
      }
      run_git(bare, "remote", "set-url", "origin", repository["origin"])
      cache_root = Path(directory) / "cache"
      cache = cache_root / "git" / "source.git"
      cache.parent.mkdir(parents=True)
      bare.rename(cache)

      report = license_inventory_report(
        {"productVersion": "9.4.0", "repositories": [repository]},
        cache_root,
      )

      self.assertEqual("source", report["repositories"][0]["repository"])

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
      self.assertEqual([], record["lfsObjects"])

  def test_repository_metadata_records_locked_lfs_objects_and_paths(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      bare, commit, oid, content = add_lfs_object(directory, checkout)
      repository = repository_input("source", commit)

      record = repository_metadata(repository, bare, commit)

      self.assertEqual([{
        "oid": oid,
        "size": len(content),
        "paths": ["asset.bin"],
      }], record["lfsObjects"])

  def test_lfs_fetch_uses_anonymous_project_mirror_batch(self):
    repository = repository_input("source")
    lfs_objects = [{"oid": "c" * 64, "size": 1, "paths": ["asset.bin"]}]
    with (
      patch(
        "source_resolver._fetch_anonymous_lfs_actions",
        return_value={"c" * 64: {"href": "https://objects.invalid/source", "headers": {}}},
      ) as fetch_actions,
      patch("source_resolver._download_anonymous_lfs_object") as download,
      patch("source_resolver._verify_lfs_objects"),
      patch("source_resolver._verify_lfs_cache") as verify_cache,
      patch("source_resolver.shutil.copyfile"),
    ):
      fetch_lfs_objects(repository, Path("cache.git"), SHA1_A, lfs_objects)

    fetch_actions.assert_called_once_with(repository, lfs_objects)
    self.assertEqual(repository, download.call_args.args[0])
    self.assertNotIn(repository["upstream"], download.call_args.args[2]["href"])
    verify_cache.assert_called_once()

  def test_lfs_fetch_refreshes_an_expired_download_action(self):
    repository = repository_input("source")
    content = b"public object\n"
    oid = hashlib.sha256(content).hexdigest()
    lfs_object = {"oid": oid, "size": len(content), "paths": ["asset.bin"]}
    expired = {
      oid: {
        "href": "https://objects.invalid/expired",
        "headers": {},
        "expiresIn": 0,
        "fetchedAt": 1,
      }
    }
    fresh = {
      oid: {
        "href": "https://objects.invalid/fresh",
        "headers": {},
        "expiresIn": 3600,
        "fetchedAt": 1,
      }
    }

    def download(_, __, ___, destination):
      destination.parent.mkdir(parents=True, exist_ok=True)
      destination.write_bytes(content)

    with tempfile.TemporaryDirectory() as directory:
      cache = Path(directory) / "cache.git"
      with (
        patch(
          "source_resolver._fetch_anonymous_lfs_actions",
          side_effect=[expired, fresh],
        ) as fetch_actions,
        patch("source_resolver._download_anonymous_lfs_object", side_effect=download),
        patch("source_resolver._verify_lfs_cache"),
        patch("source_resolver.time.time", return_value=1),
      ):
        fetch_lfs_objects(repository, cache, SHA1_A, [lfs_object])

    self.assertEqual(2, fetch_actions.call_count)

  def test_lfs_fetch_refreshes_an_action_rejected_by_object_storage(self):
    repository = repository_input("source")
    content = b"public object\n"
    oid = hashlib.sha256(content).hexdigest()
    lfs_object = {"oid": oid, "size": len(content), "paths": ["asset.bin"]}
    action = {oid: {"href": "https://objects.invalid/source", "headers": {}}}

    def download(_, __, ___, destination):
      if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.touch()
        raise LfsActionRefreshRequired("expired action")
      destination.write_bytes(content)

    with tempfile.TemporaryDirectory() as directory:
      cache = Path(directory) / "cache.git"
      with (
        patch("source_resolver._fetch_anonymous_lfs_actions", return_value=action) as fetch_actions,
        patch("source_resolver._download_anonymous_lfs_object", side_effect=download),
        patch("source_resolver._verify_lfs_cache"),
      ):
        fetch_lfs_objects(repository, cache, SHA1_A, [lfs_object])

    self.assertEqual(2, fetch_actions.call_count)

  def test_anonymous_lfs_batch_rejects_missing_objects_without_credentials(self):
    repository = repository_input("source")
    oid = "c" * 64
    lfs_objects = [{"oid": oid, "size": 1, "paths": ["asset.bin"]}]
    available = io.BytesIO(json.dumps({
      "objects": [{
        "oid": oid,
        "size": 1,
        "actions": {
          "download": {"href": "https://objects.invalid/source"},
        },
      }],
    }).encode("utf-8"))
    with patch(
      "source_resolver._open_anonymous_request",
      return_value=available,
    ) as open_request:
      actions = _fetch_anonymous_lfs_actions(repository, lfs_objects)
    request = open_request.call_args.args[0]
    self.assertEqual(
      repository["origin"] + "/info/lfs/objects/batch",
      request.full_url,
    )
    self.assertIsNone(request.get_header("Authorization"))
    self.assertEqual("https://objects.invalid/source", actions[oid]["href"])

    missing = io.BytesIO(json.dumps({
      "objects": [{
        "oid": oid,
        "size": 1,
        "error": {"code": 404, "message": "missing"},
      }],
    }).encode("utf-8"))
    with patch("source_resolver._open_anonymous_request", return_value=missing):
      with self.assertRaisesRegex(ResolutionError, "not anonymously readable"):
        _fetch_anonymous_lfs_actions(repository, lfs_objects)

  def test_anonymous_lfs_download_verifies_size_and_digest(self):
    repository = repository_input("source")
    content = b"public object\n"
    oid = hashlib.sha256(content).hexdigest()
    lfs_object = {"oid": oid, "size": len(content), "paths": ["asset.bin"]}
    action = {"href": "https://objects.invalid/source", "headers": {}}
    with tempfile.TemporaryDirectory() as directory:
      destination = Path(directory) / oid
      with patch(
        "source_resolver._open_anonymous_request",
        return_value=io.BytesIO(content),
      ):
        _download_anonymous_lfs_object(
          repository,
          lfs_object,
          action,
          destination,
        )
      self.assertEqual(content, destination.read_bytes())

      with patch(
        "source_resolver._open_anonymous_request",
        side_effect=lambda *_: io.BytesIO(b"tampered\n"),
      ):
        with self.assertRaisesRegex(ResolutionError, "does not match lock"):
          _download_anonymous_lfs_object(
            repository,
            lfs_object,
            action,
            destination,
          )

  def test_lfs_public_audit_binds_anonymous_objects_to_locked_commit(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      bare, commit, oid, content = add_lfs_object(directory, checkout)
      repository = repository_input("lfs-source", commit)
      run_git(bare, "remote", "set-url", "origin", repository["origin"])
      inputs = {"productVersion": "9.4.0", "repositories": [repository]}

      cache_root = Path(directory) / "cache"
      cache = cache_root / "git" / "lfs-source.git"
      cache.parent.mkdir(parents=True)
      bare.rename(cache)
      with patch("source_resolver.fetch_lfs_objects") as fetch_objects:
        report = lfs_public_audit_report(
          inputs,
          cache_root,
          ["lfs-source"],
        )

      self.assertEqual("passed", report["status"])
      record = report["repositories"][0]
      self.assertEqual("none", record["repositoryAuthentication"])
      self.assertEqual(1, record["objectCount"])
      self.assertEqual(len(content), record["totalBytes"])
      self.assertEqual(oid, record["objects"][0]["oid"])
      fetch_objects.assert_called_once()

      with self.assertRaisesRegex(ResolutionError, "sorted, unique"):
        lfs_public_audit_report(inputs, cache_root, ["z", "a"])

  def test_powershell_audit_commands_have_distinct_default_reports(self):
    script = (REPOSITORY_ROOT / "scripts" / "resolve-sources.ps1").read_text(
      encoding="utf-8"
    )
    self.assertIn("source-input-audit.json", script)
    self.assertIn("source-license-audit.json", script)
    self.assertIn("source-lfs-public-audit.json", script)

  def test_audit_cli_validates_contract_before_writing_report(self):
    invalid_report = {
      "schemaVersion": 1,
      "auditType": "source-lfs-public",
      "productVersion": "9.4.0",
      "status": "passed",
      "repositories": [],
    }
    with tempfile.TemporaryDirectory() as directory:
      inputs_path = Path(directory) / "inputs.json"
      report_path = Path(directory) / "report.json"
      inputs_path.write_text(json.dumps(source_inputs()), encoding="utf-8")
      with patch(
        "source_resolver.lfs_public_audit_report",
        return_value=invalid_report,
      ):
        exit_code = main([
          "lfs-audit",
          "--inputs", str(inputs_path),
          "--cache-directory", str(Path(directory) / "cache"),
          "--repository", "documentserver",
          "--report", str(report_path),
          "--schema-dir", str(REPOSITORY_ROOT / "schemas"),
        ])

      self.assertEqual(2, exit_code)
      self.assertFalse(report_path.exists())

  def test_lfs_fetch_does_not_trust_objects_already_in_cache(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      bare, commit, oid, content = add_lfs_object(directory, checkout)
      repository = repository_input("source", commit)
      repository["origin"] = "http://127.0.0.1:9/unavailable.git"
      lfs_objects = [{"oid": oid, "size": len(content), "paths": ["asset.bin"]}]

      with self.assertRaises(ResolutionError):
        fetch_lfs_objects(repository, bare, commit, lfs_objects)

  def test_public_mirror_probe_fails_when_anonymous_refs_are_unavailable(self):
    repository = repository_input("source")
    with patch("source_resolver._run_anonymous_git", return_value="") as anonymous_git:
      with self.assertRaisesRegex(ResolutionError, "not anonymously readable"):
        verify_public_mirror(repository)
    self.assertEqual(
      ["ls-remote", "--refs", repository["origin"]],
      anonymous_git.call_args.args[0],
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

  def test_relationship_verification_rejects_unlocked_gitlink(self):
    with tempfile.TemporaryDirectory() as directory:
      _, child_bare, child_commit = create_repository(directory, "child")
      parent_checkout, _, _ = create_repository(directory, "parent")
      run_git(
        parent_checkout,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{child_commit},nested/child",
      )
      run_git(parent_checkout, "commit", "-m", "add undeclared child gitlink")
      parent_commit = run_git(parent_checkout, "rev-parse", "HEAD^{commit}")
      parent_bare = Path(directory) / "parent-final.git"
      run_git(directory, "clone", "--bare", str(parent_checkout), str(parent_bare))

      with self.assertRaisesRegex(
        ResolutionError,
        "parent:nested/child: gitlink is not declared",
      ):
        verify_relationships(
          {"relationships": []},
          {"parent": parent_bare, "child": child_bare},
          {"parent": parent_commit, "child": child_commit},
        )

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
      self.assertEqual(
        repository["origin"] + "/info/lfs",
        run_git(checkout, "config", "--local", "--get", "lfs.url"),
      )
      self.assertEqual("", run_git(checkout, "status", "--porcelain"))

  def test_materialize_restores_and_verifies_lfs_content_without_download(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout, _, _ = create_repository(directory)
      bare, commit, oid, content = add_lfs_object(directory, checkout)
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

      materialized = source_root / "sources" / "source" / "asset.bin"
      self.assertEqual(content, materialized.read_bytes())
      incomplete_lock = json.loads(json.dumps(lock))
      incomplete_lock["repositories"][0]["lfsObjects"] = []
      with self.assertRaisesRegex(ResolutionError, "manifest does not match"):
        verify_materialized(incomplete_lock, source_root)
      materialized.write_bytes(b"tampered\n")
      with self.assertRaisesRegex(ResolutionError, "Git LFS size does not match"):
        verify_materialized(lock, source_root)

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
