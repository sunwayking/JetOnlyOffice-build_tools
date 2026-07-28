from pathlib import Path
import sys
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from contracts.contract_tool import ContractError, validate_contract  # noqa: E402


SHA256_A = "a" * 64
SHA256_B = "b" * 64
OCI_A = "sha256:" + SHA256_A
OCI_B = "sha256:" + SHA256_B


def bootstrap_manifest():
  return {
    "schemaVersion": 1,
    "manifestType": "bootstrap",
    "platform": "linux-amd64",
    "sourceLockSha256": SHA256_A,
    "toolchainLockSha256": SHA256_B,
    "imageLockSha256": SHA256_A,
    "sourceDateEpoch": 200,
    "environment": {
      "timezone": "UTC",
      "locale": "C.UTF-8",
      "umask": "022",
      "pythonHashSeed": "0",
      "buildPath": "/work",
      "concurrency": 4,
    },
    "network": "online-only",
    "toolchainFiles": [
      {
        "id": "node",
        "path": "toolchain/node/" + SHA256_A,
        "size": 10,
        "sha256": SHA256_A,
      }
    ],
    "images": [
      {
        "id": "builder",
        "role": "builder",
        "reference": "ubuntu:24.04",
        "digest": OCI_A,
      },
      {
        "id": "buildkit",
        "role": "buildkit",
        "reference": "moby/buildkit:v1",
        "digest": OCI_B,
      },
      {
        "id": "frontend",
        "role": "dockerfile-frontend",
        "reference": "docker/dockerfile:1",
        "digest": OCI_A,
      },
      {
        "id": "runtime",
        "role": "runtime",
        "reference": "ubuntu:24.04",
        "digest": OCI_B,
      },
    ],
  }


class BootstrapManifestContractTests(unittest.TestCase):
  def test_bootstrap_manifest_binds_locked_offline_inputs(self):
    value = bootstrap_manifest()
    validate_contract(value, "bootstrap-manifest", REPOSITORY_ROOT / "schemas")
    value["network"] = "default"
    with self.assertRaisesRegex(ContractError, "expected constant"):
      validate_contract(value, "bootstrap-manifest", REPOSITORY_ROOT / "schemas")
    value = bootstrap_manifest()
    value["images"].append({
      "id": "second-builder",
      "role": "builder",
      "reference": "ubuntu:24.04",
      "digest": OCI_B,
    })
    value["images"].sort(key=lambda item: item["id"])
    with self.assertRaisesRegex(ContractError, "roles must be unique"):
      validate_contract(value, "bootstrap-manifest", REPOSITORY_ROOT / "schemas")


if __name__ == "__main__":
  unittest.main()
