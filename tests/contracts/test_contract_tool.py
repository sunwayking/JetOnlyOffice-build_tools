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
OCI_B = "sha256:" + SHA256_B


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


def component_license_record():
  return {
    "scope": "component",
    "payloadPatterns": ["**/*.ttf"],
    "components": [{
      "id": "fonts",
      "payloadPaths": ["fonts/Example.ttf"],
      "license": {
        "spdx": "LicenseRef-Unicode-Fonts-for-Ancient-Scripts",
        "evidence": [{
          "type": "git-blob",
          "path": "fonts/Example.ttf",
          "blob": SHA1_A,
          "sha256": SHA256_A,
          "locator": "fonts/LICENSE.txt",
          "evidenceBlob": SHA1_A,
          "evidenceSha256": SHA256_B,
        }],
      },
    }],
  }


def multi_reference_component_license_record():
  return {
    "scope": "component",
    "payloadPatterns": ["**/*.ttf"],
    "components": [{
      "id": "fonts",
      "payloadPaths": ["fonts/Example.ttf", "fonts/Other.ttf"],
      "license": {
        "spdx": (
          "LicenseRef-SCOWL-2020-12-07 AND "
          "LicenseRef-Hyphen-en-US-2011-10-07 AND WordNet"
        ),
        "evidence": [
          {
            "type": "git-blob",
            "path": "fonts/Example.ttf",
            "blob": SHA1_A,
            "sha256": SHA256_A,
            "locator": "fonts/SCOWL.txt",
            "evidenceBlob": SHA1_A,
            "evidenceSha256": SHA256_B,
            "licenseRefs": ["LicenseRef-SCOWL-2020-12-07"],
          },
          {
            "type": "git-blob",
            "path": "fonts/Other.ttf",
            "blob": SHA1_B,
            "sha256": SHA256_B,
            "locator": "fonts/hyphen.txt",
            "evidenceBlob": SHA1_B,
            "evidenceSha256": SHA256_A,
            "licenseRefs": ["LicenseRef-Hyphen-en-US-2011-10-07"],
          },
        ],
      },
    }],
  }


def repository_component_license_record():
  return {
    "scope": "component",
    "payloadPatterns": ["**/*.ttf"],
    "components": [{
      "id": "fonts",
      "payloadPaths": ["fonts/Example.ttf"],
      "license": {
        "spdx": "LicenseRef-Unicode-Fonts-for-Ancient-Scripts",
        "evidence": [{
          "type": "repository-git-blob",
          "path": "fonts/Example.ttf",
          "blob": SHA1_A,
          "sha256": SHA256_A,
          "repository": "license-evidence",
          "referencePath": "fonts/Example.ttf",
          "referenceBlob": SHA1_A,
          "referenceSha256": SHA256_A,
          "locator": "fonts/LICENSE.txt",
          "evidenceBlob": SHA1_A,
          "evidenceSha256": SHA256_B,
        }],
      },
    }],
  }


def derived_cef_license_record():
  expression = "BSD-3-Clause AND LicenseRef-Chromium-Third-Party-Credits"
  records = []
  for locator, resource_id, compression, digest, blob, bindings in (
    ("cef/LICENSE.txt", 63001, "none", SHA256_A, SHA1_A, []),
    (
      "cef/chromium-credits.html",
      31061,
      "chromium-grit-brotli",
      SHA256_B,
      SHA1_B,
      ["LicenseRef-Chromium-Third-Party-Credits"],
    ),
  ):
    records.append({
      "type": "repository-cef-pak-resource",
      "path": "cef/cef_binary.7z",
      "blob": SHA1_A,
      "sha256": SHA256_A,
      "repository": "license-evidence",
      "locator": locator,
      "evidenceBlob": blob,
      "evidenceSha256": digest,
      "archiveMember": (
        "cef_binary/Resources/resources.pak"
        if resource_id == 31061
        else "cef_binary/Resources/chrome_100_percent.pak"
      ),
      "resourceId": resource_id,
      "compression": compression,
      "licenseRefs": bindings,
    })
  return {
    "scope": "component",
    "payloadPatterns": ["cef/cef_binary.7z"],
    "components": [{
      "id": "cef",
      "payloadPaths": ["cef/cef_binary.7z"],
      "license": {"spdx": expression, "evidence": records},
    }],
  }


def cef_evidence_repository_license_record():
  expression = "BSD-3-Clause AND LicenseRef-Chromium-Third-Party-Credits"
  return {
    "scope": "component",
    "payloadPatterns": ["cef/LICENSE.txt", "cef/chromium-credits.html"],
    "components": [{
      "id": "cef",
      "payloadPaths": ["cef/LICENSE.txt", "cef/chromium-credits.html"],
      "license": {
        "spdx": expression,
        "evidence": [
          {
            "type": "git-blob",
            "path": "cef/LICENSE.txt",
            "blob": SHA1_A,
            "sha256": SHA256_A,
            "locator": "cef/LICENSE.txt",
            "evidenceBlob": SHA1_A,
            "evidenceSha256": SHA256_A,
            "licenseRefs": [],
          },
          {
            "type": "git-blob",
            "path": "cef/chromium-credits.html",
            "blob": SHA1_B,
            "sha256": SHA256_B,
            "locator": "cef/chromium-credits.html",
            "evidenceBlob": SHA1_B,
            "evidenceSha256": SHA256_B,
            "licenseRefs": ["LicenseRef-Chromium-Third-Party-Credits"],
          },
        ],
      },
    }],
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
    "sourceTreeManifest": {
      "path": "source-tree-manifest.json",
      "size": 1,
      "sha256": SHA256_A,
    },
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
        "lfsObjects": [],
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


def source_tree_manifest():
  return {
    "schemaVersion": 1,
    "manifestType": "source-tree",
    "repositories": [
      {
        "id": "documentserver",
        "checkoutPath": "sources/DocumentServer",
        "commit": SHA1_A,
        "tree": SHA1_B,
        "entries": [],
      },
      {
        "id": "sdkjs",
        "checkoutPath": "sources/sdkjs",
        "commit": SHA1_B,
        "tree": SHA1_A,
        "entries": [],
      },
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
        "mediaType": "application/x-xz",
        "consumers": ["build", "package", "runtime"],
        "license": "MIT",
        "materialization": {
          "root": "toolchain",
          "type": "tar-xz",
          "destination": "usr",
          "stripComponents": 1,
        },
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
        "configDigest": OCI_B,
        "platform": "linux/amd64",
        "sourceUrl": "https://hub.docker.com/_/ubuntu",
      },
      {
        "id": "buildkit",
        "role": "buildkit",
        "reference": "moby/buildkit:v1",
        "digest": OCI_A,
        "configDigest": OCI_B,
        "platform": "linux/amd64",
        "sourceUrl": "https://hub.docker.com/r/moby/buildkit",
      },
      {
        "id": "frontend",
        "role": "dockerfile-frontend",
        "reference": "docker/dockerfile:1",
        "digest": OCI_A,
        "configDigest": OCI_B,
        "platform": "linux/amd64",
        "sourceUrl": "https://hub.docker.com/r/docker/dockerfile",
      },
      {
        "id": "runtime",
        "role": "runtime",
        "reference": "ubuntu:24.04",
        "digest": OCI_A,
        "configDigest": OCI_B,
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
    "packageDriver": {
      "type": "file",
      "path": "build-output/packaging/package.sh",
      "mode": "0755",
      "size": 10,
      "sha256": SHA256_A,
    },
    "files": [
      {
        "type": "file",
        "path": "build-output/packaging/package.sh",
        "mode": "0755",
        "size": 10,
        "sha256": SHA256_A,
        "mediaType": "application/x-sh",
        "sourceId": "build-tools",
      },
      {
        "type": "file",
        "path": "documentserver/server/docservice",
        "mode": "0755",
        "size": 10,
        "sha256": SHA256_A,
        "mediaType": "application/octet-stream",
        "sourceId": "documentserver",
      },
      {
        "type": "file",
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
    ("cyclonedx", "cyclonedx", "sbom/release.cdx.json"),
    ("deb", "deb", "packages/jetonlyoffice.deb"),
    ("licenses", "licenses", "licenses/jetonlyoffice-licenses.tar.zst"),
    ("notice", "notice", "licenses/NOTICE.txt"),
    ("oci", "oci", "images/jetonlyoffice.oci.tar"),
    ("provenance", "provenance", "provenance/intoto.jsonl"),
    ("rootfs", "rootfs", "packages/rootfs.tar.zst"),
    ("source", "source", "sources/jetonlyoffice-source.tar.zst"),
    ("spdx", "spdx", "sbom/release.spdx.json"),
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
      dict({
        "id": identifier,
        "type": artifact_type,
        "path": path,
        "size": 10,
        "sha256": SHA256_A,
        "mediaType": "application/octet-stream",
        "subjects": ["deb", "oci", "rootfs"]
        if artifact_type in {"spdx", "cyclonedx", "provenance"}
        else [],
      }, **({"ociDigest": OCI_A} if artifact_type == "oci" else {}))
      for identifier, artifact_type, path in records
    ],
  }


def source_license_audit():
  return {
    "schemaVersion": 1,
    "auditType": "source-license-inventory",
    "productVersion": "9.4.0",
    "status": "failed",
    "repositories": [
      {
        "repository": "core-fonts",
        "commit": SHA1_A,
        "tree": SHA1_B,
        "status": "incomplete",
        "components": [
          {
            "id": "font-family",
            "status": "review-required",
            "payloadPaths": ["font-family/font.ttf"],
            "candidateEvidence": [
              {
                "path": "font-family/LICENSE.txt",
                "blob": SHA1_A,
                "sha256": SHA256_A,
              }
            ],
          },
          {
            "id": "licensed-family",
            "status": "resolved",
            "payloadPaths": ["licensed-family/font.ttf"],
            "candidateEvidence": [],
            "license": {
              "spdx": "GPL-3.0-or-later WITH Font-exception-2.0",
              "evidence": [
                {
                  "type": "font-name",
                  "path": "licensed-family/font.ttf",
                  "blob": SHA1_A,
                  "sha256": SHA256_A,
                  "locator": "name:13",
                  "evidenceSha256": SHA256_B,
                }
              ],
            },
          },
          {
            "id": "missing-family",
            "status": "unresolved",
            "payloadPaths": ["missing-family/font.ttf"],
            "candidateEvidence": [],
          },
          {
            "id": "zz-blocked-family",
            "status": "blocked",
            "payloadPaths": ["zz-blocked-family/font.ttf"],
            "candidateEvidence": [
              {
                "path": "zz-blocked-family/LICENSE.txt",
                "blob": SHA1_A,
                "sha256": SHA256_A,
              }
            ],
            "blockingReview": {
              "code": "CONFLICTING_TERMS",
              "reason": "The locked notice contains conflicting terms.",
              "evidence": [
                {
                  "path": "zz-blocked-family/LICENSE.txt",
                  "blob": SHA1_A,
                  "sha256": SHA256_A,
                }
              ],
            },
          },
        ],
      }
    ],
  }


def source_license_audit_with_repository_evidence():
  return {
    "schemaVersion": 1,
    "auditType": "source-license-inventory",
    "productVersion": "9.4.0",
    "status": "passed",
    "repositories": [
      {
        "repository": "font-source",
        "commit": SHA1_A,
        "tree": SHA1_B,
        "status": "complete",
        "components": [{
          "id": "fonts",
          "status": "resolved",
          "payloadPaths": ["fonts/Example.ttf"],
          "candidateEvidence": [],
          "license": {
            "spdx": "LicenseRef-Unicode-Fonts-for-Ancient-Scripts",
            "evidence": [repository_component_license_record()[
              "components"
            ][0]["license"]["evidence"][0]],
          },
        }],
      },
      {
        "repository": "license-evidence",
        "commit": SHA1_A,
        "tree": SHA1_B,
        "status": "complete",
        "components": [{
          "id": "fonts",
          "status": "resolved",
          "payloadPaths": ["fonts/Example.ttf"],
          "candidateEvidence": [],
          "license": component_license_record()["components"][0]["license"],
        }],
      },
    ],
  }


def source_lfs_audit():
  return {
    "schemaVersion": 1,
    "auditType": "source-lfs-public",
    "productVersion": "9.4.0",
    "status": "passed",
    "repositories": [
      {
        "repository": "build-tools-data",
        "origin": "https://github.com/sunwayking/JetOnlyOffice-build_tools_data.git",
        "commit": SHA1_A,
        "tree": SHA1_B,
        "repositoryAuthentication": "none",
        "objectCount": 1,
        "totalBytes": 10,
        "objects": [
          {
            "oid": SHA256_A,
            "size": 10,
            "paths": ["package/archive.tar.xz"],
          }
        ],
      }
    ],
  }


def source_selection_audit():
  return {
    "schemaVersion": 1,
    "auditType": "source-selection",
    "productVersion": "9.4.0",
    "releaseCutoff": 100,
    "status": "passed",
    "repositories": [
      {
        "repository": "branch-fork",
        "type": "branch",
        "commit": SHA1_A,
        "ref": "refs/heads/develop",
      },
      {
        "repository": "build-tools",
        "type": "self",
        "commit": SHA1_A,
      },
      {
        "repository": "core",
        "type": "gitlink",
        "commit": SHA1_A,
        "parent": "documentserver",
        "path": "core",
      },
      {
        "repository": "plugin-catalog",
        "type": "cutoff",
        "commit": SHA1_A,
        "commitTime": 99,
        "refPrefix": "refs/heads/upstream/",
        "releaseCutoff": 100,
        "resolvedRef": "refs/heads/upstream/master",
      },
      {
        "repository": "sdkjs-forms",
        "type": "tag",
        "commit": SHA1_A,
        "ref": "refs/tags/v9.4.0.129",
      },
    ],
  }


VALID_CONTRACTS = {
  "source-lock": source_lock,
  "source-tree-manifest": source_tree_manifest,
  "toolchain-lock": toolchain_lock,
  "image-lock": image_lock,
  "build-manifest": build_manifest,
  "artifact-manifest": artifact_manifest,
  "source-license-audit": source_license_audit,
  "source-lfs-audit": source_lfs_audit,
  "source-selection-audit": source_selection_audit,
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
    with self.assertRaisesRegex(ContractError, "Unicode scalar values"):
      canonical_json_bytes({"value": "\ud800"})

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

  def test_source_lock_accepts_reviewed_dictionary_license_expressions(self):
    for reviewed_expression in (
      "BSD-3-Clause",
      "LGPL-2.1-only AND LPPL-1.0",
      "LGPL-3.0-only AND LPPL-1.0",
      "LGPL-3.0-only AND LicenseRef-SCOWL-2020-12-07",
      "LPPL-1.3c",
      "(GPL-2.0-only OR LGPL-2.1-only OR MPL-1.1 OR CC-SA-1.0) AND LGPL-2.1-only",
      "PSF-2.0 AND MIT AND Apache-2.0 AND MPL-2.0 AND LGPL-2.1-only AND BSD-3-Clause AND BSD-2-Clause AND ISC AND (BSD-2-Clause OR Apache-2.0) AND OpenSSL AND Zlib AND bzip2-1.0.6 AND LicenseRef-Public-Domain",
    ):
      value = source_lock()
      value["repositories"][0]["license"]["spdx"] = reviewed_expression
      validate_contract(value, "source-lock", self.schema_dir)

  def test_source_lock_rejects_incomplete_license_and_ambiguous_lfs_paths(self):
    for invalid_expression in ("NOASSERTION", "TBD", "MIT OR", " "):
      value = source_lock()
      value["repositories"][0]["license"]["spdx"] = invalid_expression
      with self.assertRaisesRegex(ContractError, "reviewed source set"):
        validate_contract(value, "source-lock", self.schema_dir)

    value = source_lock()
    value["repositories"][0]["lfsObjects"] = [
      {"oid": SHA256_A, "size": 1, "paths": ["asset.bin"]},
      {"oid": SHA256_B, "size": 1, "paths": ["asset.bin"]},
    ]
    with self.assertRaisesRegex(ContractError, "paths must be unique across objects"):
      validate_contract(value, "source-lock", self.schema_dir)

    value = source_lock()
    value["repositories"][0]["lfsObjects"] = [
      {"oid": SHA256_A, "size": 1, "paths": ["C:/outside.bin"]},
    ]
    with self.assertRaisesRegex(ContractError, "normalized and relative"):
      validate_contract(value, "source-lock", self.schema_dir)

    value = source_lock()
    value["repositories"][0]["lfsObjects"] = [
      {"oid": SHA256_A, "size": 1, "paths": ["LICENSE"]},
    ]
    with self.assertRaisesRegex(ContractError, "materializedSha256"):
      validate_contract(value, "source-lock", self.schema_dir)

    value["repositories"][0]["license"]["materializedSha256"] = SHA256_B
    with self.assertRaisesRegex(ContractError, "must match the LFS object oid"):
      validate_contract(value, "source-lock", self.schema_dir)

    value["repositories"][0]["license"]["materializedSha256"] = SHA256_A
    validate_contract(value, "source-lock", self.schema_dir)

    value = source_lock()
    value["repositories"][0]["license"]["materializedSha256"] = SHA256_B
    with self.assertRaisesRegex(ContractError, "materializedSha256"):
      validate_contract(value, "source-lock", self.schema_dir)

  def test_source_lock_accepts_component_scoped_license_evidence(self):
    value = source_lock()
    value["repositories"][0]["license"] = component_license_record()

    validate_contract(value, "source-lock", self.schema_dir)

    evidence = value["repositories"][0]["license"]["components"][0]["license"][
      "evidence"
    ]
    second_locator = json.loads(json.dumps(evidence[0]))
    second_locator.update({
      "locator": "fonts/NOTICE.txt",
      "evidenceBlob": SHA1_B,
      "evidenceSha256": SHA256_A,
    })
    evidence.append(second_locator)
    validate_contract(value, "source-lock", self.schema_dir)

    evidence.append(json.loads(json.dumps(second_locator)))
    with self.assertRaisesRegex(ContractError, "item keys must be unique"):
      validate_contract(value, "source-lock", self.schema_dir)

  def test_source_lock_binds_each_custom_license_to_its_evidence(self):
    value = source_lock()
    value["repositories"][0]["license"] = multi_reference_component_license_record()
    validate_contract(value, "source-lock", self.schema_dir)

    missing = json.loads(json.dumps(value))
    del missing["repositories"][0]["license"]["components"][0]["license"][
      "evidence"
    ][0]["licenseRefs"]
    with self.assertRaisesRegex(ContractError, "required when an expression has multiple"):
      validate_contract(missing, "source-lock", self.schema_dir)

    unknown = json.loads(json.dumps(value))
    unknown["repositories"][0]["license"]["components"][0]["license"][
      "evidence"
    ][0]["licenseRefs"] = ["LicenseRef-Unknown"]
    with self.assertRaisesRegex(ContractError, "not present in the SPDX expression"):
      validate_contract(unknown, "source-lock", self.schema_dir)

    uncovered = json.loads(json.dumps(value))
    uncovered["repositories"][0]["license"]["components"][0]["license"][
      "evidence"
    ][1]["licenseRefs"] = []
    with self.assertRaisesRegex(ContractError, "every LicenseRef identifier needs evidence"):
      validate_contract(uncovered, "source-lock", self.schema_dir)

  def test_source_lock_accepts_only_mapped_repository_license_evidence(self):
    value = source_lock()
    value["repositories"][0]["license"] = repository_component_license_record()
    reference = json.loads(json.dumps(value["repositories"][1]))
    reference.update({
      "id": "license-evidence",
      "role": "auxiliary-mirror",
      "checkoutPath": "sources/license-evidence",
      "origin": "https://github.com/sunwayking/JetOnlyOffice-license-evidence.git",
      "upstream": "https://github.com/sunwayking/JetOnlyOffice-license-evidence.git",
      "license": component_license_record(),
    })
    value["repositories"].insert(1, reference)

    validate_contract(value, "source-lock", self.schema_dir)

    multiple = json.loads(json.dumps(value))
    source_evidence = multiple["repositories"][0]["license"]["components"][0][
      "license"
    ]["evidence"]
    reference_evidence = multiple["repositories"][1]["license"]["components"][0][
      "license"
    ]["evidence"]
    source_second = json.loads(json.dumps(source_evidence[0]))
    source_second.update({
      "locator": "fonts/NOTICE.txt",
      "evidenceBlob": SHA1_B,
      "evidenceSha256": SHA256_A,
    })
    reference_second = json.loads(json.dumps(reference_evidence[0]))
    reference_second.update({
      "locator": "fonts/NOTICE.txt",
      "evidenceBlob": SHA1_B,
      "evidenceSha256": SHA256_A,
    })
    source_evidence.append(source_second)
    reference_evidence.append(reference_second)
    validate_contract(multiple, "source-lock", self.schema_dir)

    reference_evidence.pop()
    with self.assertRaisesRegex(ContractError, "referenced component mapping"):
      validate_contract(multiple, "source-lock", self.schema_dir)

    tampered = json.loads(json.dumps(value))
    tampered["repositories"][0]["license"]["components"][0]["license"][
      "evidence"
    ][0]["evidenceBlob"] = SHA1_B
    with self.assertRaisesRegex(ContractError, "referenced component mapping"):
      validate_contract(tampered, "source-lock", self.schema_dir)

    value["repositories"][0]["license"]["components"][0]["license"][
      "evidence"
    ][0]["repository"] = "missing-evidence"
    with self.assertRaisesRegex(ContractError, "evidence repository is not locked"):
      validate_contract(value, "source-lock", self.schema_dir)

    value = source_lock()
    value["repositories"][0]["license"] = repository_component_license_record()
    reference = json.loads(json.dumps(value["repositories"][1]))
    reference.update({
      "id": "license-evidence",
      "role": "auxiliary-mirror",
      "checkoutPath": "sources/license-evidence",
      "origin": "https://github.com/sunwayking/JetOnlyOffice-license-evidence.git",
      "upstream": "https://github.com/sunwayking/JetOnlyOffice-license-evidence.git",
      "lfsObjects": [{
        "oid": SHA256_A,
        "size": 1,
        "paths": ["fonts/Example.ttf"],
      }],
      "license": component_license_record(),
    })
    value["repositories"].insert(1, reference)
    with self.assertRaisesRegex(ContractError, "regular Git blobs"):
      validate_contract(value, "source-lock", self.schema_dir)

    value = source_lock()
    value["repositories"][0]["license"] = repository_component_license_record()
    reference = json.loads(json.dumps(value["repositories"][1]))
    reference.update({
      "id": "license-evidence",
      "role": "auxiliary-mirror",
      "checkoutPath": "sources/license-evidence",
      "origin": "https://github.com/sunwayking/JetOnlyOffice-license-evidence.git",
      "upstream": "https://github.com/sunwayking/JetOnlyOffice-license-evidence.git",
      "license": component_license_record(),
    })
    reference["license"]["components"][0]["license"]["evidence"][0][
      "locator"
    ] = "fonts/OTHER.txt"
    value["repositories"].insert(1, reference)
    with self.assertRaisesRegex(ContractError, "referenced component mapping"):
      validate_contract(value, "source-lock", self.schema_dir)

  def test_source_lock_accepts_payload_derived_cef_evidence(self):
    value = source_lock()
    value["repositories"][0]["license"] = derived_cef_license_record()
    reference = json.loads(json.dumps(value["repositories"][1]))
    reference.update({
      "id": "license-evidence",
      "role": "auxiliary-mirror",
      "checkoutPath": "sources/license-evidence",
      "origin": "https://github.com/sunwayking/JetOnlyOffice-license-evidence.git",
      "upstream": "https://github.com/sunwayking/JetOnlyOffice-license-evidence.git",
      "license": cef_evidence_repository_license_record(),
    })
    value["repositories"].insert(1, reference)

    validate_contract(value, "source-lock", self.schema_dir)

    tampered = json.loads(json.dumps(value))
    tampered["repositories"][0]["license"]["components"][0]["license"][
      "evidence"
    ][0]["resourceId"] = 0
    with self.assertRaisesRegex(ContractError, "exactly one schema"):
      validate_contract(tampered, "source-lock", self.schema_dir)

    tampered = json.loads(json.dumps(value))
    tampered["repositories"][0]["license"]["components"][0]["license"][
      "evidence"
    ][0]["evidenceBlob"] = SHA1_B
    with self.assertRaisesRegex(ContractError, "referenced component mapping"):
      validate_contract(tampered, "source-lock", self.schema_dir)

  def test_source_lock_rejects_invalid_component_scoped_license_evidence(self):
    value = source_lock()
    value["repositories"][0]["license"] = component_license_record()
    value["repositories"][0]["license"]["path"] = "LICENSE"
    with self.assertRaisesRegex(ContractError, "exactly one schema"):
      validate_contract(value, "source-lock", self.schema_dir)

    value = source_lock()
    value["repositories"][0]["license"] = component_license_record()
    del value["repositories"][0]["license"]["components"][0]["license"][
      "evidence"
    ][0]["evidenceBlob"]
    with self.assertRaisesRegex(ContractError, "locked git-blob evidence"):
      validate_contract(value, "source-lock", self.schema_dir)

    value = source_lock()
    value["repositories"][0]["license"] = component_license_record()
    value["repositories"][0]["license"]["components"][0]["payloadPaths"] = [
      "fonts/Other.ttf"
    ]
    with self.assertRaisesRegex(ContractError, "evidence.*exactly cover"):
      validate_contract(value, "source-lock", self.schema_dir)

    value = source_lock()
    value["repositories"][0]["license"] = component_license_record()
    value["repositories"][0]["license"]["components"][0]["license"]["spdx"] = (
      "NOASSERTION"
    )
    with self.assertRaisesRegex(ContractError, "reviewed source set"):
      validate_contract(value, "source-lock", self.schema_dir)

  def test_source_license_audit_rejects_status_and_inventory_drift(self):
    value = source_license_audit()
    value["repositories"][0]["components"].reverse()
    with self.assertRaisesRegex(ContractError, "items must be sorted"):
      validate_contract(value, "source-license-audit", self.schema_dir)

    value = source_license_audit()
    value["repositories"][0]["components"][0]["status"] = "unresolved"
    with self.assertRaisesRegex(ContractError, "candidate evidence"):
      validate_contract(value, "source-license-audit", self.schema_dir)

    value = source_license_audit()
    del value["repositories"][0]["components"][-1]["blockingReview"]
    with self.assertRaisesRegex(ContractError, "blocking review"):
      validate_contract(value, "source-license-audit", self.schema_dir)

    value = source_license_audit()
    value["repositories"][0]["components"][-1]["blockingReview"]["evidence"][0][
      "path"
    ] = "other/LICENSE.txt"
    with self.assertRaisesRegex(ContractError, "component candidate evidence"):
      validate_contract(value, "source-license-audit", self.schema_dir)

    value = source_license_audit()
    value["repositories"][0]["components"][-1]["blockingReview"]["evidence"][0][
      "sha256"
    ] = SHA256_B
    with self.assertRaisesRegex(ContractError, "component candidate evidence"):
      validate_contract(value, "source-license-audit", self.schema_dir)

    value = source_license_audit()
    blocked_component = value["repositories"][0]["components"][-1]
    blocked_component["candidateEvidence"][0]["path"] = "other/LICENSE.txt"
    blocked_component["blockingReview"]["evidence"][0]["path"] = (
      "other/LICENSE.txt"
    )
    with self.assertRaisesRegex(ContractError, "belong to the blocked component"):
      validate_contract(value, "source-license-audit", self.schema_dir)

    value = source_license_audit()
    value["repositories"][0]["components"][1]["payloadPaths"] = ["../font.ttf"]
    with self.assertRaisesRegex(ContractError, "normalized and relative"):
      validate_contract(value, "source-license-audit", self.schema_dir)

    value = source_license_audit()
    del value["repositories"][0]["components"][1]["license"]
    with self.assertRaisesRegex(ContractError, "license"):
      validate_contract(value, "source-license-audit", self.schema_dir)

    value = source_license_audit()
    value["repositories"][0]["components"][1]["license"]["evidence"][0]["path"] = (
      "font-family/font.ttf"
    )
    with self.assertRaisesRegex(ContractError, "exactly cover"):
      validate_contract(value, "source-license-audit", self.schema_dir)

  def test_source_license_audit_requires_multiple_custom_license_bindings(self):
    value = source_license_audit()
    license_record = value["repositories"][0]["components"][1]["license"]
    license_record["spdx"] = (
      "LicenseRef-SCOWL-2020-12-07 AND "
      "LicenseRef-Hyphen-en-US-2011-10-07 AND WordNet"
    )
    with self.assertRaisesRegex(ContractError, "required when an expression has multiple"):
      validate_contract(value, "source-license-audit", self.schema_dir)

  def test_source_license_audit_rejects_derived_status_drift(self):
    value = source_license_audit()
    value["status"] = "passed"
    with self.assertRaisesRegex(ContractError, "audit status"):
      validate_contract(value, "source-license-audit", self.schema_dir)

    value = source_license_audit()
    value["repositories"][0]["status"] = "complete"
    with self.assertRaisesRegex(ContractError, "repository status"):
      validate_contract(value, "source-license-audit", self.schema_dir)

    value = source_license_audit()
    value["repositories"][0]["components"] = [
      value["repositories"][0]["components"][1]
    ]
    with self.assertRaisesRegex(ContractError, "repository status"):
      validate_contract(value, "source-license-audit", self.schema_dir)

    value["repositories"][0]["status"] = "complete"
    value["status"] = "passed"
    validate_contract(value, "source-license-audit", self.schema_dir)

  def test_source_license_audit_binds_repository_reference_digest(self):
    value = source_license_audit_with_repository_evidence()
    validate_contract(value, "source-license-audit", self.schema_dir)

    value["repositories"][0]["components"][0]["license"]["evidence"][0][
      "referenceSha256"
    ] = SHA256_B
    with self.assertRaisesRegex(ContractError, "referenced payload digest"):
      validate_contract(value, "source-license-audit", self.schema_dir)

    value = source_license_audit_with_repository_evidence()
    value["repositories"][0]["components"][0]["license"]["evidence"][0][
      "evidenceBlob"
    ] = SHA1_B
    with self.assertRaisesRegex(ContractError, "referenced component mapping"):
      validate_contract(value, "source-license-audit", self.schema_dir)

  def test_source_lfs_audit_rejects_counts_bytes_and_path_drift(self):
    value = source_lfs_audit()
    value["repositories"][0]["objectCount"] = 2
    with self.assertRaisesRegex(ContractError, "objectCount"):
      validate_contract(value, "source-lfs-audit", self.schema_dir)

    value = source_lfs_audit()
    value["repositories"][0]["totalBytes"] = 11
    with self.assertRaisesRegex(ContractError, "totalBytes"):
      validate_contract(value, "source-lfs-audit", self.schema_dir)

    value = source_lfs_audit()
    value["repositories"][0]["objects"][0]["paths"] = ["../archive.tar.xz"]
    with self.assertRaisesRegex(ContractError, "normalized and relative"):
      validate_contract(value, "source-lfs-audit", self.schema_dir)

  def test_source_selection_audit_rejects_cutoff_and_order_drift(self):
    value = source_selection_audit()
    next(
      repository
      for repository in value["repositories"]
      if repository["type"] == "cutoff"
    )["commitTime"] = 101
    with self.assertRaisesRegex(ContractError, "exceeds release cutoff"):
      validate_contract(value, "source-selection-audit", self.schema_dir)

    value = source_selection_audit()
    next(
      repository
      for repository in value["repositories"]
      if repository["type"] == "branch"
    )["ref"] = "refs/heads/main"
    with self.assertRaisesRegex(ContractError, "expected constant"):
      validate_contract(value, "source-selection-audit", self.schema_dir)

    value = source_selection_audit()
    value["repositories"] = list(reversed(value["repositories"]))
    with self.assertRaisesRegex(ContractError, "must be sorted"):
      validate_contract(value, "source-selection-audit", self.schema_dir)

  def test_source_selection_audit_rejects_incomplete_discriminated_records(self):
    value = source_selection_audit()
    tag = next(
      repository
      for repository in value["repositories"]
      if repository["type"] == "tag"
    )
    del tag["ref"]
    with self.assertRaisesRegex(ContractError, "missing required property ref"):
      validate_contract(value, "source-selection-audit", self.schema_dir)

    value = source_selection_audit()
    self_selection = next(
      repository
      for repository in value["repositories"]
      if repository["type"] == "self"
    )
    self_selection["ref"] = "refs/heads/develop"
    with self.assertRaisesRegex(ContractError, "unknown properties: ref"):
      validate_contract(value, "source-selection-audit", self.schema_dir)

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

  def test_validation_rejects_noncanonical_values_and_missing_license(self):
    value = build_manifest()
    value["sourceDateEpoch"] = 9007199254740992
    with self.assertRaisesRegex(ContractError, "interoperable range"):
      validate_contract(value, "build-manifest", self.schema_dir)
    value = toolchain_lock()
    del value["tools"][0]["license"]
    with self.assertRaisesRegex(ContractError, "missing required property license"):
      validate_contract(value, "toolchain-lock", self.schema_dir)
    for invalid_license in ("NOASSERTION", "TBD", "UNKNOWN", " MIT "):
      value = toolchain_lock()
      value["tools"][0]["license"] = invalid_license
      with self.subTest(license=invalid_license), self.assertRaisesRegex(
        ContractError, "reviewed SPDX expression"
      ):
        validate_contract(value, "toolchain-lock", self.schema_dir)
    value = toolchain_lock()
    value["tools"][0]["license"] = "LicenseRef-Unbundled-Tool-License"
    with self.assertRaisesRegex(ContractError, "custom license evidence is unsupported"):
      validate_contract(value, "toolchain-lock", self.schema_dir)

  def test_toolchain_lock_requires_sorted_complete_consumer_coverage(self):
    value = toolchain_lock()
    value["tools"][0]["consumers"] = ["runtime", "build", "package"]
    with self.assertRaisesRegex(ContractError, "values must be sorted and unique"):
      validate_contract(value, "toolchain-lock", self.schema_dir)
    value = toolchain_lock()
    value["tools"][0]["consumers"] = ["build"]
    with self.assertRaisesRegex(ContractError, "missing consumers: package, runtime"):
      validate_contract(value, "toolchain-lock", self.schema_dir)

  def test_toolchain_lock_requires_safe_deterministic_materialization(self):
    value = toolchain_lock()
    value["tools"][0]["materialization"]["destination"] = "../outside"
    with self.assertRaisesRegex(ContractError, "path must be normalized and relative"):
      validate_contract(value, "toolchain-lock", self.schema_dir)

    value = toolchain_lock()
    value["tools"][0]["materialization"] = {
      "root": "toolchain",
      "type": "file",
      "destination": "usr/bin/node",
      "stripComponents": 1,
      "mode": "0755",
    }
    with self.assertRaisesRegex(ContractError, "stripComponents: allowed only for archives"):
      validate_contract(value, "toolchain-lock", self.schema_dir)

    value = toolchain_lock()
    value["tools"][0]["materialization"] = {
      "root": "toolchain",
      "type": "file",
      "destination": "usr/bin/node",
    }
    with self.assertRaisesRegex(ContractError, "mode: required for files"):
      validate_contract(value, "toolchain-lock", self.schema_dir)

  def test_image_and_artifact_manifests_require_complete_roles(self):
    value = image_lock()
    value["images"].pop()
    with self.assertRaisesRegex(ContractError, "missing required roles"):
      validate_contract(value, "image-lock", self.schema_dir)
    value = artifact_manifest()
    value["artifacts"] = [item for item in value["artifacts"] if item["type"] != "provenance"]
    with self.assertRaisesRegex(ContractError, "missing required types"):
      validate_contract(value, "artifact-manifest", self.schema_dir)

  def test_image_lock_rejects_unsafe_or_digest_bearing_references(self):
    value = image_lock()
    value["images"][0]["reference"] = "registry.example:5000/ns/image:tag_1"
    validate_contract(value, "image-lock", self.schema_dir)

    for reference in (
      "https://registry.example/image:tag",
      "Ubuntu:24.04",
      "ubuntu:bad tag",
      "ubuntu:24.04@" + OCI_A,
    ):
      with self.subTest(reference=reference):
        value = image_lock()
        value["images"][0]["reference"] = reference
        with self.assertRaisesRegex(ContractError, "value does not match"):
          validate_contract(value, "image-lock", self.schema_dir)

  def test_build_manifest_binds_one_executable_package_driver(self):
    value = build_manifest()
    value["packageDriver"]["sha256"] = SHA256_B
    with self.assertRaisesRegex(ContractError, "does not match the inventoried driver"):
      validate_contract(value, "build-manifest", self.schema_dir)
    value = build_manifest()
    value["packageDriver"]["mode"] = "0644"
    next(
      item for item in value["files"]
      if item["path"] == value["packageDriver"]["path"]
    )["mode"] = "0644"
    with self.assertRaisesRegex(ContractError, "driver must be executable"):
      validate_contract(value, "build-manifest", self.schema_dir)

  def test_build_manifest_rejects_symlink_targets_outside_the_output(self):
    value = build_manifest()
    value["files"].append({
      "type": "symlink",
      "path": "build-output/lib/libjet.so",
      "mode": "0777",
      "size": 13,
      "sha256": SHA256_A,
      "symlinkTarget": "../../../outside",
    })
    value["files"].sort(key=lambda item: item["path"])
    with self.assertRaisesRegex(ContractError, "target escapes the manifest root"):
      validate_contract(value, "build-manifest", self.schema_dir)

  def test_build_manifest_rejects_symbolic_link_cycles(self):
    for records in (
      [{"path": "build-output/self", "symlinkTarget": "self"}],
      [
        {"path": "build-output/loop-a", "symlinkTarget": "loop-b"},
        {"path": "build-output/loop-b", "symlinkTarget": "loop-a"},
      ],
    ):
      with self.subTest(records=records):
        value = build_manifest()
        value["files"].extend({
          "type": "symlink",
          "path": record["path"],
          "mode": "0777",
          "size": len(record["symlinkTarget"].encode("utf-8")),
          "sha256": SHA256_A,
          "symlinkTarget": record["symlinkTarget"],
        } for record in records)
        value["files"].sort(key=lambda item: item["path"])
        with self.assertRaisesRegex(ContractError, "symbolic link cycle"):
          validate_contract(value, "build-manifest", self.schema_dir)

  def test_artifact_manifest_requires_digest_and_real_subjects(self):
    value = artifact_manifest()
    del next(item for item in value["artifacts"] if item["type"] == "oci")["ociDigest"]
    with self.assertRaisesRegex(ContractError, "required for OCI artifacts"):
      validate_contract(value, "artifact-manifest", self.schema_dir)
    value = artifact_manifest()
    evidence = next(item for item in value["artifacts"] if item["type"] == "spdx")
    evidence["subjects"] = sorted([*evidence["subjects"], "missing"])
    with self.assertRaisesRegex(ContractError, "unknown artifact ids"):
      validate_contract(value, "artifact-manifest", self.schema_dir)
    value = artifact_manifest()
    next(item for item in value["artifacts"] if item["type"] == "deb")["ociDigest"] = OCI_A
    with self.assertRaisesRegex(ContractError, "allowed only for OCI artifacts"):
      validate_contract(value, "artifact-manifest", self.schema_dir)

  def test_artifact_manifest_requires_supply_chain_coverage(self):
    for evidence_type in ("spdx", "cyclonedx", "provenance"):
      with self.subTest(evidence_type=evidence_type):
        value = artifact_manifest()
        evidence = next(item for item in value["artifacts"] if item["type"] == evidence_type)
        evidence["subjects"].remove("rootfs")
        with self.assertRaisesRegex(ContractError, f"{evidence_type} does not cover: rootfs"):
          validate_contract(value, "artifact-manifest", self.schema_dir)

  def test_entrypoint_contract_is_fail_closed(self):
    value = load_json(self.schema_dir / "entrypoints.v1.json")
    validate_entrypoints(value)
    value["entrypoints"][1]["networkPolicy"] = "online"
    with self.assertRaisesRegex(ContractError, "not fail-closed"):
      validate_entrypoints(value)

  def test_entrypoint_contract_rejects_malformed_shapes_and_paths(self):
    value = load_json(self.schema_dir / "entrypoints.v1.json")
    value["entrypoints"][0]["inputs"] = ["../sources.lock.json"]
    with self.assertRaisesRegex(ContractError, "normalized and relative"):
      validate_entrypoints(value)
    value = load_json(self.schema_dir / "entrypoints.v1.json")
    value["entrypoints"][0] = "bootstrap-source"
    with self.assertRaisesRegex(ContractError, "expected object"):
      validate_entrypoints(value)
    value = load_json(self.schema_dir / "entrypoints.v1.json")
    value["unexpected"] = True
    with self.assertRaisesRegex(ContractError, "unknown properties"):
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
