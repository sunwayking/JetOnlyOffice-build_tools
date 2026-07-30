import shutil
import subprocess
import tempfile
from pathlib import Path
import hashlib
import json
import os
import sys
import unittest
from argparse import Namespace
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))
from offline_baseline import (  # noqa: E402
  pinned_image_reference,
  verify as verify_offline_baseline,
)
SHA1_A = "a" * 40
SHA1_B = "b" * 40
SHA256_A = "a" * 64
OCI_A = "sha256:" + SHA256_A
OCI_B = "sha256:" + ("b" * 64)
PACKAGE_DRIVER_PAYLOAD = b"#!/bin/sh\n"


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
        "lfsObjects": [],
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
  run_git(checkout, "config", "lfs.url", origin + "/info/lfs")
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
      "lfsObjects": [],
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
      "configDigest": image["configDigest"],
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
    "arguments = sys.argv[1:]\n"
    f"if arguments[:2] == ['image', 'inspect']:\n  print(json.dumps([{{'Id': {OCI_B!r}, 'RepoDigests': ['ubuntu@' + {OCI_A!r}], 'Os': 'linux', 'Architecture': 'amd64'}}])); raise SystemExit(0)\n"
    "if arguments and arguments[0] == 'create':\n  print('fake-runtime-container'); raise SystemExit(0)\n"
    "if arguments and arguments[0] == 'export':\n  pathlib.Path(arguments[arguments.index('--output') + 1]).write_bytes(b'runtime rootfs'); raise SystemExit(0)\n"
    "if arguments and arguments[0] == 'rm':\n  raise SystemExit(0)\n"
    "mounts = [arguments[index + 1] for index, item in enumerate(arguments) if item == '--mount']\n"
    "environments = [arguments[index + 1] for index, item in enumerate(arguments) if item == '--env']\n"
    "def mount_source(destination):\n"
    "  for mount in mounts:\n"
    "    fields = dict(field.split('=', 1) for field in mount.split(',') if '=' in field)\n"
    "    if fields.get('dst') == destination:\n"
    "      return pathlib.Path(fields['src'])\n"
    "  raise RuntimeError('mount is missing: ' + destination)\n"
    "output_root = mount_source('/output')\n"
    "cache_root = mount_source('/input/cache')\n"
    "if not (cache_root / 'materialization-plan.tsv').is_file(): raise RuntimeError('materialization plan is missing')\n"
    "manifest_path = next(value.split('=', 1)[1] for value in environments if value.startswith('JETONLYOFFICE_BUILD_MANIFEST_PATH='))\n"
    "manifest = output_root / pathlib.PurePosixPath(manifest_path).relative_to('/output')\n"
    "artifact = output_root / 'build-output' / 'documentserver.bin'\n"
    "artifact.parent.mkdir(parents=True, exist_ok=True)\n"
    "artifact.write_bytes(b'x')\n"
    "package_driver = output_root / 'build-output' / 'packaging' / 'package.sh'\n"
    "package_driver.parent.mkdir(parents=True, exist_ok=True)\n"
    f"package_driver.write_bytes({PACKAGE_DRIVER_PAYLOAD!r})\n"
    "manifest.parent.mkdir(parents=True, exist_ok=True)\n"
    f"shutil.copyfile({str(template)!r}, manifest)\n"
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


def fake_package_docker(root, manifest):
  staged_root = root / "fake-package-output"
  materialize_artifacts(staged_root, manifest)
  template = root / "fake-artifact-manifest.json"
  output = root / "artifacts" / "artifact-manifest.json"
  log = root / "package-docker-arguments.json"
  write_json(template, manifest)
  driver = root / "fake-package-docker.py"
  driver.write_text(
    "import json, pathlib, shutil, sys\n"
    "arguments = sys.argv[1:]\n"
    f"if arguments[:2] == ['image', 'inspect']:\n  print(json.dumps([{{'Id': {OCI_B!r}, 'RepoDigests': ['ubuntu@' + {OCI_A!r}], 'Os': 'linux', 'Architecture': 'amd64'}}])); raise SystemExit(0)\n"
    "if arguments and arguments[0] == 'create':\n  print('fake-runtime-container'); raise SystemExit(0)\n"
    "if arguments and arguments[0] == 'export':\n  pathlib.Path(arguments[arguments.index('--output') + 1]).write_bytes(b'runtime rootfs'); raise SystemExit(0)\n"
    "if arguments and arguments[0] == 'rm':\n  raise SystemExit(0)\n"
    "mounts = [arguments[index + 1] for index, item in enumerate(arguments) if item == '--mount']\n"
    "environments = [arguments[index + 1] for index, item in enumerate(arguments) if item == '--env']\n"
    "def mount_source(destination):\n"
    "  for mount in mounts:\n"
    "    fields = dict(field.split('=', 1) for field in mount.split(',') if '=' in field)\n"
    "    if fields.get('dst') == destination:\n"
    "      return pathlib.Path(fields['src'])\n"
    "  raise RuntimeError('mount is missing: ' + destination)\n"
    "cache_root = mount_source('/input/cache')\n"
    "if not (cache_root / 'materialization-plan.tsv').is_file(): raise RuntimeError('materialization plan is missing')\n"
    f"source = pathlib.Path({str(staged_root / 'artifacts')!r})\n"
    "destination = mount_source('/artifacts')\n"
    "manifest_path = next(value.split('=', 1)[1] for value in environments if value.startswith('JETONLYOFFICE_ARTIFACT_MANIFEST_PATH='))\n"
    "manifest = destination / pathlib.PurePosixPath(manifest_path).relative_to('/artifacts')\n"
    "destination.mkdir(parents=True, exist_ok=True)\n"
    "shutil.copytree(source, destination, dirs_exist_ok=True)\n"
    "manifest.parent.mkdir(parents=True, exist_ok=True)\n"
    f"shutil.copyfile({str(template)!r}, manifest)\n"
    f"open({str(log)!r}, 'w', encoding='utf-8').write(json.dumps(sys.argv[1:]))\n",
    encoding="utf-8",
  )
  if os.name == "nt":
    executable = root / "fake-package-docker.cmd"
    executable.write_text(
      f'@echo off\r\n"{sys.executable}" "{driver}" %*\r\n',
      encoding="utf-8",
    )
  else:
    executable = root / "fake-package-docker"
    executable.write_text(
      f'#!/bin/sh\nexec "{sys.executable}" "{driver}" "$@"\n',
      encoding="utf-8",
    )
    executable.chmod(0o755)
  return executable, output, log


def fake_noop_docker(root, name="fake-noop-docker"):
  log = root / (name + "-arguments.json")
  driver = root / (name + ".py")
  driver.write_text(
    "import json, pathlib, sys\n"
    f"if sys.argv[1:3] == ['image', 'inspect']:\n  print(json.dumps([{{'Id': {OCI_B!r}, 'RepoDigests': ['ubuntu@' + {OCI_A!r}], 'Os': 'linux', 'Architecture': 'amd64'}}])); raise SystemExit(0)\n"
    "if len(sys.argv) > 1 and sys.argv[1] == 'create':\n  print('fake-runtime-container'); raise SystemExit(0)\n"
    "if len(sys.argv) > 1 and sys.argv[1] == 'export':\n  pathlib.Path(sys.argv[sys.argv.index('--output') + 1]).write_bytes(b'runtime rootfs'); raise SystemExit(0)\n"
    "if len(sys.argv) > 1 and sys.argv[1] == 'rm':\n  raise SystemExit(0)\n"
    f"open({str(log)!r}, 'w', encoding='utf-8').write(json.dumps(sys.argv[1:]))\n",
    encoding="utf-8",
  )
  if os.name == "nt":
    executable = root / (name + ".cmd")
    executable.write_text(
      f'@echo off\r\n"{sys.executable}" "{driver}" %*\r\n',
      encoding="utf-8",
    )
  else:
    executable = root / name
    executable.write_text(
      f'#!/bin/sh\nexec "{sys.executable}" "{driver}" "$@"\n',
      encoding="utf-8",
    )
    executable.chmod(0o755)
  return executable, log


def materialize_artifacts(root, manifest):
  for index, artifact in enumerate(manifest["artifacts"]):
    path = root / "artifacts" / artifact["path"]
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = f"artifact {index}\n".encode("ascii")
    path.write_bytes(payload)
    artifact["size"] = len(payload)
    artifact["sha256"] = hashlib.sha256(payload).hexdigest()


def bind_package_driver(manifest, root=None):
  record = {
    "type": "file",
    "path": "build-output/packaging/package.sh",
    "mode": "0755",
    "size": len(PACKAGE_DRIVER_PAYLOAD),
    "sha256": hashlib.sha256(PACKAGE_DRIVER_PAYLOAD).hexdigest(),
  }
  manifest["packageDriver"] = {
    key: record[key] for key in ("type", "path", "mode", "size", "sha256")
  }
  manifest["files"].append(record)
  manifest["files"].sort(key=lambda item: item["path"])
  if root is not None:
    path = root / "artifacts" / record["path"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(PACKAGE_DRIVER_PAYLOAD)
  return manifest


class OfflineBaselineVerificationUnitTests(unittest.TestCase):
  def test_verify_passes_repository_root_to_evidence_aggregation(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source = contract_source_lock()
      source_path = root / "locks" / "sources.lock.json"
      write_json(source_path, source)

      artifact_directory = root / "artifacts"
      reference_directory = root / "reference" / "artifacts"
      manifest = artifact_manifest()
      reference_manifest = artifact_manifest()
      source_hash = canonical_sha256(source)
      manifest["sourceLockSha256"] = source_hash
      reference_manifest["sourceLockSha256"] = source_hash
      materialize_artifacts(root, manifest)
      materialize_artifacts(root / "reference", reference_manifest)
      manifest_path = artifact_directory / "artifact-manifest.json"
      reference_manifest_path = reference_directory / "artifact-manifest.json"
      write_json(manifest_path, manifest)
      write_json(reference_manifest_path, reference_manifest)

      policy_path = artifact_directory / "release-policy.json"
      write_json(policy_path, {
        "schemaVersion": 1,
        "policyType": "release-gates",
        "releaseId": manifest["releaseId"],
        "productVersion": manifest["productVersion"],
        "sourceLockSha256": source_hash,
        "gateCatalogSha256": "d" * 64,
        "gates": [{
          "id": "browser.desktop.chromium",
          "category": "browser",
          "blocking": True,
        }],
      })
      gate_directory = artifact_directory / "gate-results"
      gate_directory.mkdir(parents=True)
      output = artifact_directory / "release-evidence.json"
      args = Namespace(
        artifact_manifest=str(manifest_path),
        reference_artifact_manifest=str(reference_manifest_path),
        source_lock=str(source_path),
        artifact_directory=str(artifact_directory),
        reference_artifact_directory=str(reference_directory),
        release_policy=str(policy_path),
        gate_result_directory=str(gate_directory),
        run_id="verify-regression",
        image=None,
        schema_dir=str(REPOSITORY_ROOT / "schemas"),
        repository_root=str(root),
        output=str(output),
      )

      with patch(
        "offline_baseline.aggregate_release_evidence",
        return_value={"outcome": "PASS"},
      ) as aggregate, patch(
        "offline_baseline.verify_supply_chain_artifacts",
      ) as verify_supply_chain:
        verify_offline_baseline(args)

      self.assertEqual(2, verify_supply_chain.call_count)
      self.assertEqual(str(root), aggregate.call_args.args[-1])
      self.assertEqual("PASS", json.loads(output.read_text(encoding="utf-8"))["outcome"])


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell is not available")
class OfflineBaselineEntrypointTests(unittest.TestCase):
  def test_verify_rejects_primary_artifacts_reused_as_independent_build(self):
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
          "pwsh", "-NoProfile", "-File",
          str(REPOSITORY_ROOT / "scripts" / "verify.ps1"),
          "-ArtifactManifestPath", str(manifest_path),
          "-ReferenceArtifactManifestPath", str(manifest_path),
          "-SourceLockPath", str(source_path),
          "-ArtifactDirectory", str(root / "artifacts"),
          "-ReferenceArtifactDirectory", str(root / "artifacts"),
          "-ReleasePolicyPath", str(root / "artifacts" / "release-policy.json"),
          "-GateResultDirectory", str(root / "artifacts" / "gate-results"),
          "-OutputPath", str(root / "artifacts" / "release-evidence.json"),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(4, result.returncode, result.stderr)
      self.assertIn("must use a different manifest and artifact directory", result.stderr)

  def test_verify_generates_diffoscope_report_before_blocking_mismatch(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source = contract_source_lock()
      source_path = root / "locks" / "sources.lock.json"
      write_json(source_path, source)
      manifest = artifact_manifest()
      reference_manifest = artifact_manifest()
      source_hash = canonical_sha256(source)
      manifest["sourceLockSha256"] = source_hash
      reference_manifest["sourceLockSha256"] = source_hash
      materialize_artifacts(root, manifest)
      materialize_artifacts(root / "reference", reference_manifest)
      reference_deb = next(
        item for item in reference_manifest["artifacts"] if item["type"] == "deb"
      )
      reference_deb_path = root / "reference" / "artifacts" / reference_deb["path"]
      reference_deb_path.write_bytes(b"independent deb differs\n")
      reference_deb["size"] = reference_deb_path.stat().st_size
      reference_deb["sha256"] = hashlib.sha256(reference_deb_path.read_bytes()).hexdigest()
      manifest_path = root / "artifacts" / "artifact-manifest.json"
      reference_manifest_path = root / "reference" / "artifacts" / "artifact-manifest.json"
      write_json(manifest_path, manifest)
      write_json(reference_manifest_path, reference_manifest)

      diffoscope_log = root / "diffoscope-arguments.json"
      diffoscope_driver = root / "fake-diffoscope.py"
      diffoscope_driver.write_text(
        "import json, pathlib, sys\n"
        "arguments = sys.argv[1:]\n"
        "pathlib.Path(arguments[arguments.index('--html') + 1]).write_text('<html>different</html>', encoding='utf-8')\n"
        f"pathlib.Path({str(diffoscope_log)!r}).write_text(json.dumps(arguments), encoding='utf-8')\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
      )
      if os.name == "nt":
        diffoscope = root / "fake-diffoscope.cmd"
        diffoscope.write_text(
          f'@echo off\r\n"{sys.executable}" "{diffoscope_driver}" %*\r\n',
          encoding="utf-8",
        )
      else:
        diffoscope = root / "fake-diffoscope"
        diffoscope.write_text(
          f'#!/bin/sh\nexec "{sys.executable}" "{diffoscope_driver}" "$@"\n',
          encoding="utf-8",
        )
        diffoscope.chmod(0o755)
      diffoscope_directory = root / "artifacts" / "diffoscope"
      result = subprocess.run(
        [
          "pwsh", "-NoProfile", "-File",
          str(REPOSITORY_ROOT / "scripts" / "verify.ps1"),
          "-ArtifactManifestPath", str(manifest_path),
          "-ReferenceArtifactManifestPath", str(reference_manifest_path),
          "-SourceLockPath", str(source_path),
          "-ArtifactDirectory", str(root / "artifacts"),
          "-ReferenceArtifactDirectory", str(root / "reference" / "artifacts"),
          "-ReleasePolicyPath", str(root / "artifacts" / "release-policy.json"),
          "-GateResultDirectory", str(root / "artifacts" / "gate-results"),
          "-DiffoscopeExecutable", str(diffoscope),
          "-DiffoscopeDirectory", str(diffoscope_directory),
          "-OutputPath", str(root / "artifacts" / "release-evidence.json"),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(4, result.returncode, result.stderr)
      self.assertIn("REPRODUCIBILITY_MISMATCH", result.stderr)
      report = diffoscope_directory / "deb.html"
      self.assertTrue(report.is_file())
      arguments = json.loads(diffoscope_log.read_text(encoding="utf-8"))
      self.assertEqual(str(report), arguments[arguments.index("--html") + 1])
      summary = json.loads(
        (diffoscope_directory / "reproducibility-report.json").read_text(encoding="utf-8")
      )
      self.assertEqual("BLOCKED", summary["outcome"])
      self.assertEqual("deb", summary["mismatches"][0]["artifactType"])

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
      source_path, toolchain_path, image_path, bootstrap_path = prepare_locked_inputs(root)
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
          "type": "file",
          "path": "build-output/missing.bin",
          "mode": "0755",
          "size": 1,
          "sha256": hashlib.sha256(b"x").hexdigest(),
        }],
      }
      bind_package_driver(build_manifest, root)
      build_manifest_path = root / "artifacts" / "build-manifest.json"
      write_json(build_manifest_path, build_manifest)
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "package.ps1"),
          "-BuildManifestPath", str(build_manifest_path),
          "-BootstrapManifestPath", str(bootstrap_path),
          "-SourceLockPath", str(source_path),
          "-ToolchainLockPath", str(toolchain_path),
          "-ImageLockPath", str(image_path),
          "-ArtifactDirectory", str(root / "artifacts"),
          "-CacheDirectory", str(root / "cache"),
          "-DockerExecutable", str(root / "missing-docker"),
          "-OutputPath", str(root / "artifacts" / "artifact-manifest.json"),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertIn("locked build output is missing", result.stderr)

  def test_package_rejects_tampered_locked_cache_before_docker(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source_path, toolchain_path, image_path, bootstrap_path = prepare_locked_inputs(root)
      source = json.loads(source_path.read_text(encoding="utf-8"))
      toolchain = json.loads(toolchain_path.read_text(encoding="utf-8"))
      images = json.loads(image_path.read_text(encoding="utf-8"))
      builder = next(image for image in images["images"] if image["role"] == "builder")
      build_payload = b"locked build output\n"
      build_output = root / "artifacts" / "build-output" / "documentserver.bin"
      build_output.parent.mkdir(parents=True)
      build_output.write_bytes(build_payload)
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
          "type": "file",
          "path": "build-output/documentserver.bin",
          "mode": "0644",
          "size": len(build_payload),
          "sha256": hashlib.sha256(build_payload).hexdigest(),
        }],
      }
      bind_package_driver(build_manifest, root)
      build_manifest_path = root / "artifacts" / "build-manifest.json"
      write_json(build_manifest_path, build_manifest)
      locked_file = next(
        path for path in (root / "cache" / "toolchain").rglob("*") if path.is_file()
      )
      locked_file.write_bytes(b"tampered toolchain input")

      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "package.ps1"),
          "-BuildManifestPath", str(build_manifest_path),
          "-BootstrapManifestPath", str(bootstrap_path),
          "-SourceLockPath", str(source_path),
          "-ToolchainLockPath", str(toolchain_path),
          "-ImageLockPath", str(image_path),
          "-ArtifactDirectory", str(root / "artifacts"),
          "-CacheDirectory", str(root / "cache"),
          "-DockerExecutable", str(root / "missing-docker"),
          "-OutputPath", str(root / "artifacts" / "artifact-manifest.json"),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )

      self.assertEqual(3, result.returncode, result.stderr)
      self.assertIn("locked toolchain cache digest mismatch", result.stderr)

  def test_package_rejects_build_manifest_from_different_toolchain(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source_path, toolchain_path, image_path, bootstrap_path = prepare_locked_inputs(root)
      source = json.loads(source_path.read_text(encoding="utf-8"))
      toolchain = json.loads(toolchain_path.read_text(encoding="utf-8"))
      images = json.loads(image_path.read_text(encoding="utf-8"))
      builder = next(image for image in images["images"] if image["role"] == "builder")
      build_payload = b"locked build output\n"
      build_output = root / "artifacts" / "build-output" / "documentserver.bin"
      build_output.parent.mkdir(parents=True)
      build_output.write_bytes(build_payload)
      build_manifest = {
        "schemaVersion": 1,
        "manifestType": "build",
        "buildId": "jetonlyoffice-9.4.0-linux-amd64",
        "platform": "linux-amd64",
        "configuration": "Release",
        "sourceLockSha256": canonical_sha256(source),
        "toolchainLockSha256": SHA256_A,
        "imageLockSha256": canonical_sha256(images),
        "builderImageDigest": builder["digest"],
        "sourceDateEpoch": source["sourceDateEpoch"],
        "environment": toolchain["environment"],
        "network": "none",
        "files": [{
          "type": "file",
          "path": "build-output/documentserver.bin",
          "mode": "0644",
          "size": len(build_payload),
          "sha256": hashlib.sha256(build_payload).hexdigest(),
        }],
      }
      bind_package_driver(build_manifest, root)
      build_manifest_path = root / "artifacts" / "build-manifest.json"
      write_json(build_manifest_path, build_manifest)
      output = root / "artifacts" / "artifact-manifest.json"

      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "package.ps1"),
          "-BuildManifestPath", str(build_manifest_path),
          "-BootstrapManifestPath", str(bootstrap_path),
          "-SourceLockPath", str(source_path),
          "-ToolchainLockPath", str(toolchain_path),
          "-ImageLockPath", str(image_path),
          "-ArtifactDirectory", str(root / "artifacts"),
          "-CacheDirectory", str(root / "cache"),
          "-DockerExecutable", str(root / "missing-docker"),
          "-OutputPath", str(output),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )

      self.assertEqual(3, result.returncode, result.stderr)
      self.assertIn("build manifest toolchain lock does not match", result.stderr)

  def test_package_invokes_digest_locked_container_without_network_or_pull(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source_path, toolchain_path, image_path, bootstrap_path = prepare_locked_inputs(root)
      source = json.loads(source_path.read_text(encoding="utf-8"))
      toolchain = json.loads(toolchain_path.read_text(encoding="utf-8"))
      images = json.loads(image_path.read_text(encoding="utf-8"))
      builder = next(image for image in images["images"] if image["role"] == "builder")
      build_payload = b"locked build output\n"
      build_output = root / "artifacts" / "build-output" / "documentserver.bin"
      build_output.parent.mkdir(parents=True)
      build_output.write_bytes(build_payload)
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
          "type": "file",
          "path": "build-output/documentserver.bin",
          "mode": "0644",
          "size": len(build_payload),
          "sha256": hashlib.sha256(build_payload).hexdigest(),
        }],
      }
      bind_package_driver(build_manifest, root)
      build_manifest_path = root / "artifacts" / "build-manifest.json"
      write_json(build_manifest_path, build_manifest)
      packaged = artifact_manifest()
      packaged["sourceLockSha256"] = canonical_sha256(source)
      packaged["buildManifestSha256"] = canonical_sha256(build_manifest)
      docker, output, log = fake_package_docker(root, packaged)

      command = [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "package.ps1"),
          "-BuildManifestPath", str(build_manifest_path),
          "-BootstrapManifestPath", str(bootstrap_path),
          "-SourceLockPath", str(source_path),
          "-ToolchainLockPath", str(toolchain_path),
          "-ImageLockPath", str(image_path),
          "-ArtifactDirectory", str(root / "artifacts"),
          "-CacheDirectory", str(root / "cache"),
          "-DockerExecutable", str(docker),
      ]
      result = subprocess.run(
        command,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )

      self.assertEqual(0, result.returncode, result.stderr)
      arguments = json.loads(log.read_text(encoding="utf-8"))
      self.assertEqual("none", arguments[arguments.index("--network") + 1])
      self.assertEqual("never", arguments[arguments.index("--pull") + 1])
      self.assertIn(pinned_image_reference(builder), arguments)
      environments = [
        arguments[index + 1]
        for index, item in enumerate(arguments)
        if item == "--env"
      ]
      self.assertIn(
        "JETONLYOFFICE_PACKAGE_DRIVER_PATH=/artifacts/"
        + build_manifest["packageDriver"]["path"],
        environments,
      )
      self.assertIn(
        "JETONLYOFFICE_PACKAGE_DRIVER_MODE="
        + build_manifest["packageDriver"]["mode"],
        environments,
      )
      self.assertIn("JETONLYOFFICE_RUNTIME_ROOTFS_PATH=/input/runtime-rootfs.tar",
                    environments)
      cache_mount = next(item for item in arguments if "dst=/input/cache,readonly" in item)
      self.assertNotIn((root / "cache").as_posix(), cache_mount)
      self.assertTrue(
        any("dst=/artifacts/build-output,readonly" in item for item in arguments)
      )
      self.assertTrue(
        any("dst=/artifacts/build-manifest.json,readonly" in item for item in arguments)
      )
      self.assertTrue(
        any("dst=/input/runtime-rootfs.tar,readonly" in item for item in arguments)
      )
      for lock_name in ("sources.lock.json", "toolchain.lock.json", "images.lock.json"):
        self.assertTrue(
          any(f"dst=/input/locks/{lock_name},readonly" in item for item in arguments)
        )
      second = subprocess.run(
        command,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(4, second.returncode, second.stderr)
      self.assertIn("packaged artifact destination already exists", second.stderr)
      self.assertFalse(output.exists())

  def test_package_rejects_stale_manifest_when_container_produces_no_output(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source_path, toolchain_path, image_path, bootstrap_path = prepare_locked_inputs(root)
      source = json.loads(source_path.read_text(encoding="utf-8"))
      toolchain = json.loads(toolchain_path.read_text(encoding="utf-8"))
      images = json.loads(image_path.read_text(encoding="utf-8"))
      builder = next(image for image in images["images"] if image["role"] == "builder")
      build_payload = b"locked build output\n"
      build_output = root / "artifacts" / "build-output" / "documentserver.bin"
      build_output.parent.mkdir(parents=True)
      build_output.write_bytes(build_payload)
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
          "type": "file",
          "path": "build-output/documentserver.bin",
          "mode": "0644",
          "size": len(build_payload),
          "sha256": hashlib.sha256(build_payload).hexdigest(),
        }],
      }
      bind_package_driver(build_manifest, root)
      build_manifest_path = root / "artifacts" / "build-manifest.json"
      write_json(build_manifest_path, build_manifest)
      stale_manifest = artifact_manifest()
      stale_manifest["sourceLockSha256"] = canonical_sha256(source)
      stale_manifest["buildManifestSha256"] = canonical_sha256(build_manifest)
      materialize_artifacts(root, stale_manifest)
      output = root / "artifacts" / "artifact-manifest.json"
      write_json(output, stale_manifest)
      docker, _ = fake_noop_docker(root, "fake-noop-package-docker")

      command = [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "package.ps1"),
          "-BuildManifestPath", str(build_manifest_path),
          "-BootstrapManifestPath", str(bootstrap_path),
          "-SourceLockPath", str(source_path),
          "-ToolchainLockPath", str(toolchain_path),
          "-ImageLockPath", str(image_path),
          "-ArtifactDirectory", str(root / "artifacts"),
          "-CacheDirectory", str(root / "cache"),
          "-DockerExecutable", str(docker),
          "-OutputPath", str(output),
      ]
      result = subprocess.run(
        command,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )

      self.assertEqual(4, result.returncode, result.stderr)
      self.assertIn("offline package output is missing", result.stderr)
      self.assertFalse(output.exists())

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
          "type": "file",
          "path": "build-output/documentserver.bin",
          "mode": "0755",
          "size": 1,
          "sha256": hashlib.sha256(b"x").hexdigest(),
          "sourceId": "documentserver",
        }],
      }
      bind_package_driver(manifest)
      docker, output, log = fake_docker(root, manifest)
      command = [
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
      ]
      result = subprocess.run(
        command,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(0, result.returncode, result.stderr)
      arguments = json.loads(log.read_text(encoding="utf-8"))
      self.assertEqual("none", arguments[arguments.index("--network") + 1])
      self.assertEqual("never", arguments[arguments.index("--pull") + 1])
      environments = [
        arguments[index + 1]
        for index, item in enumerate(arguments)
        if item == "--env"
      ]
      self.assertIn("NPM_CONFIG_OFFLINE=true", environments)
      self.assertIn("PIP_NO_INDEX=1", environments)
      self.assertIn("CARGO_NET_OFFLINE=true", environments)
      self.assertIn("GIT_TERMINAL_PROMPT=0", environments)
      cache_mount = next(item for item in arguments if "dst=/input/cache,readonly" in item)
      self.assertNotIn((root / "cache").as_posix(), cache_mount)
      readonly_mounts = [
        arguments[index + 1]
        for index, item in enumerate(arguments)
        if item == "--mount" and "readonly" in arguments[index + 1]
      ]
      self.assertEqual(6, len(readonly_mounts))
      second = subprocess.run(
        command,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(4, second.returncode, second.stderr)
      self.assertIn("offline build output destination already exists", second.stderr)
      self.assertFalse(output.exists())

  def test_build_rejects_stale_manifest_when_container_produces_no_output(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source = materialized_source_lock(root)
      source_path, toolchain_path, image_path, bootstrap_path = prepare_locked_inputs(root, source)
      toolchain = json.loads(toolchain_path.read_text(encoding="utf-8"))
      images = json.loads(image_path.read_text(encoding="utf-8"))
      builder = next(image for image in images["images"] if image["role"] == "builder")
      stale_payload = b"stale build output\n"
      stale_file = root / "artifacts" / "build-output" / "documentserver.bin"
      stale_file.parent.mkdir(parents=True)
      stale_file.write_bytes(stale_payload)
      stale_manifest = {
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
          "type": "file",
          "path": "build-output/documentserver.bin",
          "mode": "0644",
          "size": len(stale_payload),
          "sha256": hashlib.sha256(stale_payload).hexdigest(),
        }],
      }
      bind_package_driver(stale_manifest)
      output = root / "artifacts" / "build-manifest.json"
      write_json(output, stale_manifest)
      docker, _ = fake_noop_docker(root)

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

      self.assertEqual(4, result.returncode, result.stderr)
      self.assertIn("offline build output is missing", result.stderr)
      self.assertFalse(output.exists())

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

  def test_bootstrap_fails_closed_when_locked_toolchain_download_is_unavailable(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source_lock_path = root / "locks" / "sources.lock.json"
      toolchain_lock_path = root / "locks" / "toolchain.lock.json"
      image_lock_path = root / "locks" / "images.lock.json"
      output = root / "cache" / "bootstrap-manifest.json"
      write_json(source_lock_path, contract_source_lock())
      toolchain = toolchain_lock()
      toolchain["tools"][0]["sourceUrl"] = "https://missing.invalid/tool"
      write_json(toolchain_lock_path, toolchain)
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
      self.assertIn("locked toolchain download failed", result.stderr)
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
