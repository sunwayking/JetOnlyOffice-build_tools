import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from contracts.contract_tool import (  # noqa: E402
  CONTRACT_SCHEMAS,
  ContractError,
  canonical_json_bytes,
  canonical_sha256,
  load_json,
  main,
  validate_contract,
  validate_entrypoints,
)


SHA1_A = "a" * 40
SHA1_B = "b" * 40
SHA256_A = "a" * 64
SHA256_B = "b" * 64
OCI_A = "sha256:" + SHA256_A


def environment():
  return {
    "timezone": "UTC",
    "locale": "C.UTF-8",
    "umask": "022",
    "pythonHashSeed": "0",
    "buildPath": "/work",
    "concurrency": 4,
  }


def license_record():
  return {
    "path": "LICENSE",
    "blob": SHA1_A,
    "sha256": SHA256_A,
    "spdx": "AGPL-3.0-only",
  }


def source_lock():
  return {
    "schemaVersion": 1,
    "lockType": "source",
    "productVersion": "9.4.0",
    "baseline": {
      "repository": "documentserver",
      "commit": SHA1_A,
    },
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
        "license": license_record(),
      },
      {
        "id": "sdkjs",
        "role": "gitlink",
        "checkoutPath": "sources/sdkjs",
        "origin": "https://github.com/sunwayking/JetOnlyOffice-sdkjs.git",
        "upstream": "https://github.com/ONLYOFFICE/sdkjs.git",
        "commit": SHA1_B,
        "tree": SHA1_A,
        "commitTime": 100,
        "projectFork": True,
        "buildInput": True,
        "active": True,
        "license": license_record(),
      },
    ],
    "relationships": [
      {
        "parent": "documentserver",
        "child": "sdkjs",
        "path": "sdkjs",
        "mode": "160000",
      }
    ],
  }


def toolchain_lock():
  return {
    "schemaVersion": 1,
    "lockType": "toolchain",
    "platform": "linux-amd64",
    "sourceDateEpoch": 200,
    "environment": environment(),
    "tools": [
      {
        "id": "node",
        "name": "Node.js",
        "version": "20.19.4",
        "kind": "binary",
        "platform": "linux-amd64",
        "sourceUrl": "https://nodejs.org/dist/node.tar.xz",
        "sha256": SHA256_A,
        "size": 10,
        "license": "MIT",
      }
    ],
  }


def image_lock():
  return {
    "schemaVersion": 1,
    "lockType": "image",
    "platform": "linux-amd64",
    "images": [
      {
        "id": "builder",
        "role": "builder",
        "reference": "ubuntu:24.04",
        "digest": OCI_A,
        "platform": "linux/amd64",
        "sourceUrl": "https://hub.docker.com/_/ubuntu",
      },
      {
        "id": "buildkit",
        "role": "buildkit",
        "reference": "moby/buildkit:v1",
        "digest": OCI_A,
        "platform": "linux/amd64",
        "sourceUrl": "https://hub.docker.com/r/moby/buildkit",
      },
      {
        "id": "frontend",
        "role": "dockerfile-frontend",
        "reference": "docker/dockerfile:1",
        "digest": OCI_A,
        "platform": "linux/amd64",
        "sourceUrl": "https://hub.docker.com/r/docker/dockerfile",
      },
      {
        "id": "runtime",
        "role": "runtime",
        "reference": "ubuntu:24.04",
        "digest": OCI_A,
        "platform": "linux/amd64",
        "sourceUrl": "https://hub.docker.com/_/ubuntu",
      },
    ],
  }


def build_manifest():
  return {
    "schemaVersion": 1,
    "manifestType": "build",
    "buildId": "jetonlyoffice-9.4.0-linux-amd64",
    "platform": "linux-amd64",
    "configuration": "Release",
    "sourceLockSha256": SHA256_A,
    "toolchainLockSha256": SHA256_B,
    "imageLockSha256": SHA256_A,
    "builderImageDigest": OCI_A,
    "sourceDateEpoch": 200,
    "environment": environment(),
    "network": "none",
    "files": [
      {
        "path": "documentserver/server/docservice",
        "mode": "0755",
        "size": 10,
        "sha256": SHA256_A,
        "mediaType": "application/octet-stream",
        "sourceId": "documentserver",
      },
      {
        "path": "documentserver/web-apps/apps.js",
        "mode": "0644",
        "size": 20,
        "sha256": SHA256_B,
        "mediaType": "text/javascript",
        "sourceId": "web-apps",
      },
    ],
  }


def artifact_manifest():
  records = [
    ("checksums", "checksums", "checksums.sha256"),
    ("cyclonedx-deb", "cyclonedx", "sbom/deb.cdx.json"),
    ("deb", "deb", "packages/jetonlyoffice.deb"),
    ("oci", "oci", "images/jetonlyoffice.oci.tar"),
    ("provenance", "provenance", "provenance/intoto.jsonl"),
    ("rootfs", "rootfs", "packages/rootfs.tar.zst"),
    ("source", "source", "sources/jetonlyoffice-source.tar.zst"),
    ("spdx-deb", "spdx", "sbom/deb.spdx.json"),
  ]
  return {
    "schemaVersion": 1,
    "manifestType": "artifact",
    "releaseId": "jetonlyoffice-v9.4.0",
    "productVersion": "9.4.0",
    "platform": "linux-amd64",
    "sourceLockSha256": SHA256_A,
    "buildManifestSha256": SHA256_B,
    "artifacts": [
      {
        "id": identifier,
        "type": artifact_type,
        "path": path,
        "size": 10,
        "sha256": SHA256_A,
        "mediaType": "application/octet-stream",
        "subjects": ["documentserver", "sdkjs"],
      }
      for identifier, artifact_type, path in records
    ],
  }


VALID_CONTRACTS = {
  "source-lock": source_lock,
  "toolchain-lock": toolchain_lock,
  "image-lock": image_lock,
  "build-manifest": build_manifest,
  "artifact-manifest": artifact_manifest,
}


class ContractToolTests(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.schema_dir = REPOSITORY_ROOT / "schemas"

  def test_all_contracts_validate(self):
    for contract, factory in VALID_CONTRACTS.items():
      with self.subTest(contract=contract):
        validate_contract(factory(), contract, self.schema_dir)

  def test_all_schema_documents_are_strict_json(self):
    identifiers = set()
    for schema_name in ["common.schema.json", *CONTRACT_SCHEMAS.values()]:
      schema = load_json(self.schema_dir / schema_name)
      self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
      self.assertNotIn(schema["$id"], identifiers)
      identifiers.add(schema["$id"])

  def test_canonical_json_is_order_independent(self):
    left = {"z": 1, "a": {"two": 2, "one": 1}}
    right = {"a": {"one": 1, "two": 2}, "z": 1}
    expected = b'{"a":{"one":1,"two":2},"z":1}'
    self.assertEqual(expected, canonical_json_bytes(left))
    self.assertEqual(expected, canonical_json_bytes(right))
    self.assertEqual(hashlib.sha256(expected).hexdigest(), canonical_sha256(left))
    with self.assertRaisesRegex(ContractError, "interoperable range"):
      canonical_json_bytes({"value": 9007199254740992})

  def test_load_rejects_duplicate_keys_and_floats(self):
    with tempfile.TemporaryDirectory() as directory:
      duplicate = Path(directory) / "duplicate.json"
      duplicate.write_text('{"a":1,"a":2}', encoding="utf-8")
      with self.assertRaisesRegex(ContractError, "duplicate JSON object key"):
        load_json(duplicate)
      floating = Path(directory) / "floating.json"
      floating.write_text('{"a":1.5}', encoding="utf-8")
      with self.assertRaisesRegex(ContractError, "floating-point values"):
        load_json(floating)

  def test_source_lock_rejects_unsorted_repositories(self):
    value = source_lock()
    value["repositories"].reverse()
    with self.assertRaisesRegex(ContractError, "items must be sorted"):
      validate_contract(value, "source-lock", self.schema_dir)

  def test_source_lock_rejects_epoch_and_relationship_drift(self):
    value = source_lock()
    value["sourceDateEpoch"] = 199
    with self.assertRaisesRegex(ContractError, "maximum repository commitTime"):
      validate_contract(value, "source-lock", self.schema_dir)
    value = source_lock()
    value["relationships"][0]["child"] = "missing"
    with self.assertRaisesRegex(ContractError, "repository is not locked"):
      validate_contract(value, "source-lock", self.schema_dir)

  def test_contracts_reject_path_traversal(self):
    value = build_manifest()
    value["files"][0]["path"] = "../escape"
    with self.assertRaisesRegex(ContractError, "normalized and relative"):
      validate_contract(value, "build-manifest", self.schema_dir)

  def test_build_manifest_requires_offline_release_profile(self):
    value = build_manifest()
    value["network"] = "default"
    with self.assertRaisesRegex(ContractError, "expected constant"):
      validate_contract(value, "build-manifest", self.schema_dir)
    value = build_manifest()
    value["environment"]["concurrency"] = 8
    with self.assertRaisesRegex(ContractError, "release profile"):
      validate_contract(value, "build-manifest", self.schema_dir)

  def test_image_and_artifact_manifests_require_complete_roles(self):
    value = image_lock()
    value["images"].pop()
    with self.assertRaisesRegex(ContractError, "missing required roles"):
      validate_contract(value, "image-lock", self.schema_dir)
    value = artifact_manifest()
    value["artifacts"] = [item for item in value["artifacts"] if item["type"] != "provenance"]
    with self.assertRaisesRegex(ContractError, "missing required types"):
      validate_contract(value, "artifact-manifest", self.schema_dir)

  def test_entrypoint_contract_is_fail_closed(self):
    value = load_json(self.schema_dir / "entrypoints.v1.json")
    validate_entrypoints(value)
    value["entrypoints"][1]["networkPolicy"] = "online"
    with self.assertRaisesRegex(ContractError, "not fail-closed"):
      validate_entrypoints(value)

  def test_cli_writes_canonical_output_and_digest_sidecar(self):
    with tempfile.TemporaryDirectory() as directory:
      source = Path(directory) / "input.json"
      output = Path(directory) / "canonical.json"
      sidecar = Path(directory) / "canonical.sha256"
      source.write_text(json.dumps({"z": 1, "a": 2}), encoding="utf-8")
      self.assertEqual(0, main(["canonicalize", str(source), "--output", str(output)]))
      self.assertEqual(b'{"a":2,"z":1}\n', output.read_bytes())
      with contextlib.redirect_stdout(io.StringIO()):
        self.assertEqual(0, main(["digest", str(source), "--sidecar", str(sidecar)]))
      self.assertEqual(canonical_sha256({"z": 1, "a": 2}) + "\n", sidecar.read_text(encoding="ascii"))

  @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is not available")
  def test_powershell_entrypoint_passes_validation_exit_code(self):
    with tempfile.TemporaryDirectory() as directory:
      source = Path(directory) / "source-lock.json"
      source.write_text(json.dumps(source_lock()), encoding="utf-8")
      result = subprocess.run(
        [
          "pwsh",
          "-NoProfile",
          "-File",
          str(REPOSITORY_ROOT / "scripts" / "contracts.ps1"),
          "-Command",
          "Validate",
          "-Contract",
          "source-lock",
          "-Path",
          str(source),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
  unittest.main()
