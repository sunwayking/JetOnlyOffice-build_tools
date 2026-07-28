import shutil
import subprocess
import tempfile
from pathlib import Path
import hashlib
import json
import os
import sys
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))
SHA1_A = "a" * 40
SHA1_B = "b" * 40
SHA256_A = "a" * 64


def source_lock():
  return {
    "schemaVersion": 1,
    "lockType": "source",
    "productVersion": "9.4.0",
    "baseline": {"repository": "documentserver", "commit": SHA1_A},
    "sourceDateEpoch": 200,
    "repositories": [
      {
        "id": "documentserver",
        "role": "superproject",
        "checkoutPath": "sources/DocumentServer",
        "origin": "https://github.com/sunwayking/JetOnlyOffice-DocumentServer.git",
        "upstream": "https://github.com/ONLYOFFICE/DocumentServer.git",
        "commit": SHA1_A,
        "tree": SHA1_B,
        "commitTime": 200,
        "projectFork": True,
        "buildInput": True,
        "active": True,
        "license": {
          "path": "LICENSE",
          "blob": SHA1_A,
          "sha256": SHA256_A,
          "spdx": "AGPL-3.0-only",
        },
      }
    ],
    "relationships": [],
  }


def write_json(path, value):
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(value), encoding="utf-8")


from tests.contracts.test_contract_tool import (  # noqa: E402
  artifact_manifest,
  image_lock,
  source_lock as contract_source_lock,
  toolchain_lock,
)
from scripts.contracts.contract_tool import canonical_sha256  # noqa: E402


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


def materialized_source_lock(root):
  checkout = root / "workspace" / "sources" / "documentserver"
  checkout.mkdir(parents=True)
  run_git(checkout, "init")
  run_git(checkout, "config", "user.name", "JetOnlyOffice tests")
  run_git(checkout, "config", "user.email", "tests@jetonlyoffice.invalid")
  (checkout / "LICENSE").write_text("test license\n", encoding="utf-8", newline="\n")
  (checkout / "content.txt").write_text("content\n", encoding="utf-8", newline="\n")
  run_git(checkout, "add", "LICENSE", "content.txt")
  run_git(checkout, "commit", "-m", "initial")
  commit = run_git(checkout, "rev-parse", "HEAD^{commit}")
  tree = run_git(checkout, "rev-parse", "HEAD^{tree}")
  commit_time = int(run_git(checkout, "show", "-s", "--format=%ct", commit))
  blob = run_git(checkout, "rev-parse", commit + ":LICENSE")
  origin = "https://github.com/sunwayking/JetOnlyOffice-DocumentServer.git"
  run_git(checkout, "remote", "add", "origin", origin)
  run_git(checkout, "checkout", "--detach", commit)
  return {
    "schemaVersion": 1,
    "lockType": "source",
    "productVersion": "9.4.0",
    "baseline": {"repository": "documentserver", "commit": commit},
    "sourceDateEpoch": commit_time,
    "repositories": [{
      "id": "documentserver",
      "role": "superproject",
      "checkoutPath": "sources/documentserver",
      "origin": origin,
      "upstream": "https://github.com/ONLYOFFICE/DocumentServer.git",
      "commit": commit,
      "tree": tree,
      "commitTime": commit_time,
      "projectFork": True,
      "buildInput": True,
      "active": True,
      "license": {
        "path": "LICENSE",
        "blob": blob,
        "sha256": hashlib.sha256(b"test license\n").hexdigest(),
        "spdx": "AGPL-3.0-only",
      },
    }],
    "relationships": [],
  }


def prepare_locked_inputs(root, source=None):
  source = source or contract_source_lock()
  toolchain = toolchain_lock()
  toolchain["sourceDateEpoch"] = source["sourceDateEpoch"]
  images = image_lock()
  payload = b"locked toolchain input\n"
  digest = hashlib.sha256(payload).hexdigest()
  toolchain["tools"][0]["sha256"] = digest
  toolchain["tools"][0]["size"] = len(payload)
  cache_path = root / "cache" / "toolchain" / toolchain["tools"][0]["id"] / digest
  cache_path.parent.mkdir(parents=True, exist_ok=True)
  cache_path.write_bytes(payload)
  source_path = root / "locks" / "sources.lock.json"
  toolchain_path = root / "locks" / "toolchain.lock.json"
  image_path = root / "locks" / "images.lock.json"
  write_json(source_path, source)
  write_json(toolchain_path, toolchain)
  write_json(image_path, images)
  bootstrap = {
    "schemaVersion": 1,
    "manifestType": "bootstrap",
    "platform": "linux-amd64",
    "sourceLockSha256": canonical_sha256(source),
    "toolchainLockSha256": canonical_sha256(toolchain),
    "imageLockSha256": canonical_sha256(images),
    "sourceDateEpoch": source["sourceDateEpoch"],
    "environment": toolchain["environment"],
    "network": "online-only",
    "toolchainFiles": [{
      "id": toolchain["tools"][0]["id"],
      "path": "toolchain/" + toolchain["tools"][0]["id"] + "/" + digest,
      "size": len(payload),
      "sha256": digest,
    }],
    "images": [{
      "id": image["id"],
      "role": image["role"],
      "reference": image["reference"],
      "digest": image["digest"],
    } for image in images["images"]],
  }
  bootstrap_path = root / "cache" / "bootstrap-manifest.json"
  write_json(bootstrap_path, bootstrap)
  return source_path, toolchain_path, image_path, bootstrap_path


def fake_docker(root, build_manifest):
  template = root / "fake-build-manifest.json"
  output = root / "artifacts" / "build-manifest.json"
  log = root / "docker-arguments.json"
  write_json(template, build_manifest)
  driver = root / "fake-docker.py"
  driver.write_text(
    "import json, pathlib, shutil, sys\n"
    f"artifact = pathlib.Path({str(output.parent / 'build-output' / 'documentserver.bin')!r})\n"
    "artifact.parent.mkdir(parents=True, exist_ok=True)\n"
    "artifact.write_bytes(b'x')\n"
    f"shutil.copyfile({str(template)!r}, {str(output)!r})\n"
    f"open({str(log)!r}, 'w', encoding='utf-8').write(json.dumps(sys.argv[1:]))\n",
    encoding="utf-8",
  )
  if os.name == "nt":
    executable = root / "fake-docker.cmd"
    executable.write_text(
      f'@echo off\r\n"{sys.executable}" "{driver}" %*\r\n',
      encoding="utf-8",
    )
  else:
    executable = root / "fake-docker"
    executable.write_text(
      f'#!/bin/sh\nexec "{sys.executable}" "{driver}" "$@"\n',
      encoding="utf-8",
    )
    executable.chmod(0o755)
  return executable, output, log


def materialize_artifacts(root, manifest):
  for index, artifact in enumerate(manifest["artifacts"]):
    path = root / "artifacts" / artifact["path"]
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = f"artifact {index}\n".encode("ascii")
    path.write_bytes(payload)
    artifact["size"] = len(payload)
    artifact["sha256"] = hashlib.sha256(payload).hexdigest()


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell is not available")
class OfflineBaselineEntrypointTests(unittest.TestCase):
  def test_verify_requires_independent_artifact_manifest(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source = contract_source_lock()
      source_path = root / "locks" / "sources.lock.json"
      write_json(source_path, source)
      manifest = artifact_manifest()
      manifest["sourceLockSha256"] = canonical_sha256(source)
      materialize_artifacts(root, manifest)
      manifest_path = root / "artifacts" / "artifact-manifest.json"
      write_json(manifest_path, manifest)
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "verify.ps1"),
          "-ArtifactManifestPath", str(manifest_path),
          "-ReferenceArtifactManifestPath", str(root / "reference" / "artifact-manifest.json"),
          "-SourceLockPath", str(source_path),
          "-ArtifactDirectory", str(root / "artifacts"),
          "-ReleasePolicyPath", str(root / "artifacts" / "release-policy.json"),
          "-GateResultDirectory", str(root / "artifacts" / "gate-results"),
          "-OutputPath", str(root / "artifacts" / "release-evidence.json"),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertIn("independent artifact manifest is missing", result.stderr)

  def test_verify_rejects_missing_packaged_artifact_before_evidence_aggregation(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source = contract_source_lock()
      source_path = root / "locks" / "sources.lock.json"
      write_json(source_path, source)
      manifest = artifact_manifest()
      manifest["sourceLockSha256"] = canonical_sha256(source)
      manifest_path = root / "artifacts" / "artifact-manifest.json"
      write_json(manifest_path, manifest)
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "verify.ps1"),
          "-ArtifactManifestPath", str(manifest_path),
          "-SourceLockPath", str(source_path),
          "-ArtifactDirectory", str(root / "artifacts"),
          "-ReleasePolicyPath", str(root / "artifacts" / "release-policy.json"),
          "-GateResultDirectory", str(root / "artifacts" / "gate-results"),
          "-OutputPath", str(root / "artifacts" / "release-evidence.json"),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertIn("packaged artifact is missing", result.stderr)

  def test_package_rejects_missing_locked_build_output_before_docker(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source_path, toolchain_path, image_path, _ = prepare_locked_inputs(root)
      source = json.loads(source_path.read_text(encoding="utf-8"))
      toolchain = json.loads(toolchain_path.read_text(encoding="utf-8"))
      images = json.loads(image_path.read_text(encoding="utf-8"))
      builder = next(image for image in images["images"] if image["role"] == "builder")
      build_manifest = {
        "schemaVersion": 1,
        "manifestType": "build",
        "buildId": "jetonlyoffice-9.4.0-linux-amd64",
        "platform": "linux-amd64",
        "configuration": "Release",
        "sourceLockSha256": canonical_sha256(source),
        "toolchainLockSha256": canonical_sha256(toolchain),
        "imageLockSha256": canonical_sha256(images),
        "builderImageDigest": builder["digest"],
        "sourceDateEpoch": source["sourceDateEpoch"],
        "environment": toolchain["environment"],
        "network": "none",
        "files": [{
          "path": "build-output/missing.bin",
          "mode": "0755",
          "size": 1,
          "sha256": hashlib.sha256(b"x").hexdigest(),
        }],
      }
      build_manifest_path = root / "artifacts" / "build-manifest.json"
      write_json(build_manifest_path, build_manifest)
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "package.ps1"),
          "-BuildManifestPath", str(build_manifest_path),
          "-SourceLockPath", str(source_path),
          "-ImageLockPath", str(image_path),
          "-ArtifactDirectory", str(root / "artifacts"),
          "-CacheDirectory", str(root / "cache"),
          "-DockerExecutable", str(root / "missing-docker"),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertIn("locked build output is missing", result.stderr)

  def test_build_invokes_digest_locked_container_without_network_or_pull(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source = materialized_source_lock(root)
      source_path, toolchain_path, image_path, bootstrap_path = prepare_locked_inputs(root, source)
      toolchain = json.loads(toolchain_path.read_text(encoding="utf-8"))
      images = json.loads(image_path.read_text(encoding="utf-8"))
      builder = next(image for image in images["images"] if image["role"] == "builder")
      manifest = {
        "schemaVersion": 1,
        "manifestType": "build",
        "buildId": "jetonlyoffice-9.4.0-linux-amd64",
        "platform": "linux-amd64",
        "configuration": "Release",
        "sourceLockSha256": canonical_sha256(source),
        "toolchainLockSha256": canonical_sha256(toolchain),
        "imageLockSha256": canonical_sha256(images),
        "builderImageDigest": builder["digest"],
        "sourceDateEpoch": source["sourceDateEpoch"],
        "environment": toolchain["environment"],
        "network": "none",
        "files": [{
          "path": "build-output/documentserver.bin",
          "mode": "0755",
          "size": 1,
          "sha256": hashlib.sha256(b"x").hexdigest(),
          "sourceId": "documentserver",
        }],
      }
      docker, output, log = fake_docker(root, manifest)
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "build.ps1"),
          "-SourceLockPath", str(source_path),
          "-ToolchainLockPath", str(toolchain_path),
          "-ImageLockPath", str(image_path),
          "-BootstrapManifestPath", str(bootstrap_path),
          "-SourceDirectory", str(root / "workspace"),
          "-CacheDirectory", str(root / "cache"),
          "-ArtifactDirectory", str(root / "artifacts"),
          "-DockerExecutable", str(docker),
          "-OutputPath", str(output),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(0, result.returncode, result.stderr)
      arguments = json.loads(log.read_text(encoding="utf-8"))
      self.assertEqual("none", arguments[arguments.index("--network") + 1])
      self.assertEqual("never", arguments[arguments.index("--pull") + 1])
      readonly_mounts = [
        arguments[index + 1]
        for index, item in enumerate(arguments)
        if item == "--mount" and "readonly" in arguments[index + 1]
      ]
      self.assertEqual(3, len(readonly_mounts))

  def test_build_rejects_unmaterialized_source_workspace_before_docker(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source_path, toolchain_path, image_path, bootstrap_path = prepare_locked_inputs(root)
      workspace = root / "workspace"
      workspace.mkdir()
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "build.ps1"),
          "-SourceLockPath",
          str(source_path),
          "-ToolchainLockPath",
          str(toolchain_path),
          "-ImageLockPath",
          str(image_path),
          "-BootstrapManifestPath",
          str(bootstrap_path),
          "-SourceDirectory",
          str(workspace),
          "-CacheDirectory",
          str(root / "cache"),
          "-ArtifactDirectory",
          str(root / "artifacts"),
          "-DockerExecutable",
          str(root / "missing-docker"),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertIn("locked checkout is missing", result.stderr)

  def test_bootstrap_rejects_missing_toolchain_cache_before_docker(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source_lock_path = root / "locks" / "sources.lock.json"
      toolchain_lock_path = root / "locks" / "toolchain.lock.json"
      image_lock_path = root / "locks" / "images.lock.json"
      output = root / "cache" / "bootstrap-manifest.json"
      write_json(source_lock_path, contract_source_lock())
      write_json(toolchain_lock_path, toolchain_lock())
      write_json(image_lock_path, image_lock())
      result = subprocess.run(
        [
          sys.executable,
          str(REPOSITORY_ROOT / "scripts" / "offline_baseline.py"),
          "bootstrap",
          "--source-lock",
          str(source_lock_path),
          "--toolchain-lock",
          str(toolchain_lock_path),
          "--image-lock",
          str(image_lock_path),
          "--cache-directory",
          str(root / "cache"),
          "--docker",
          str(root / "missing-docker"),
          "--schema-dir",
          str(REPOSITORY_ROOT / "schemas"),
          "--output",
          str(output),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertIn("locked toolchain cache is missing", result.stderr)
      self.assertFalse(output.exists())

  def test_bootstrap_requires_all_lock_contracts_before_resolving_sources(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source_lock_path = root / "locks" / "sources.lock.json"
      output = root / "cache" / "bootstrap-manifest.json"
      write_json(source_lock_path, source_lock())
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "bootstrap-source.ps1"),
          "-Command",
          "Bootstrap",
          "-LockPath",
          str(source_lock_path),
          "-ToolchainLockPath",
          str(root / "locks" / "toolchain.lock.json"),
          "-ImageLockPath",
          str(root / "locks" / "images.lock.json"),
          "-BootstrapManifestPath",
          str(output),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertIn("locked toolchain input is missing", result.stderr)
      self.assertFalse(output.exists())

  def test_build_fails_closed_without_bootstrap_manifest(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      output = root / "artifacts" / "build-manifest.json"
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "build.ps1"),
          "-BootstrapManifestPath",
          str(root / "cache" / "bootstrap-manifest.json"),
          "-OutputPath",
          str(output),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertIn("locked bootstrap input is missing", result.stderr)
      self.assertFalse(output.exists())

  def test_package_fails_closed_without_build_manifest(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      output = root / "artifacts" / "artifact-manifest.json"
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "package.ps1"),
          "-BuildManifestPath",
          str(root / "artifacts" / "build-manifest.json"),
          "-OutputPath",
          str(output),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertIn("locked build input is missing", result.stderr)
      self.assertFalse(output.exists())

  def test_verify_fails_closed_without_artifact_manifest(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      output = root / "artifacts" / "release-evidence.json"
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "verify.ps1"),
          "-ArtifactManifestPath",
          str(root / "artifacts" / "artifact-manifest.json"),
          "-OutputPath",
          str(output),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertIn("locked artifact input is missing", result.stderr)
      self.assertFalse(output.exists())


if __name__ == "__main__":
  unittest.main()
