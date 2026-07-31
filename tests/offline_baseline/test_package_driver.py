import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DRIVER_PATH = REPOSITORY_ROOT / "scripts" / "container" / "package-driver.py"
ENTRYPOINT_PATH = REPOSITORY_ROOT / "scripts" / "container" / "jwt-entrypoint.sh"
RUNTIME_IMAGE = (
  "ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2ba"
  "fbc0aab6c06ba2cef9ebffbc7092d90"
)
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def docker_has_runtime_image():
  docker = shutil.which("docker")
  if not docker:
    return False
  result = subprocess.run(
    [docker, "image", "inspect", RUNTIME_IMAGE],
    capture_output=True,
    check=False,
  )
  return result.returncode == 0

specification = importlib.util.spec_from_file_location("package_driver", DRIVER_PATH)
package_driver = importlib.util.module_from_spec(specification)
specification.loader.exec_module(package_driver)
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))
from offline_baseline import (  # noqa: E402
  BaselineError,
  locked_zstd_verifier,
  open_license_archive,
  pinned_image_reference,
  verify_cyclonedx_artifact,
  verify_license_artifact,
  verify_oci_artifact,
  verify_provenance_artifact,
  verify_spdx_artifact,
  verify_supply_chain_artifacts,
)
from contracts.contract_tool import canonical_sha256, validate_contract  # noqa: E402


def source_lock():
  return {
    "schemaVersion": 1,
    "lockType": "source",
    "productVersion": "9.4.0",
    "baseline": {"repository": "documentserver", "commit": "a" * 40},
    "sourceDateEpoch": 1720000000,
    "repositories": [{
      "id": "documentserver",
      "role": "superproject",
      "checkoutPath": "sources/DocumentServer",
      "origin": "https://github.com/sunwayking/JetOnlyOffice-DocumentServer.git",
      "upstream": "https://github.com/ONLYOFFICE/DocumentServer.git",
      "commit": "a" * 40,
      "tree": "b" * 40,
      "commitTime": 1720000000,
      "projectFork": True,
      "buildInput": True,
      "active": True,
      "license": {
        "path": "LICENSE", "blob": "c" * 40,
        "sha256": "d" * 64, "spdx": "AGPL-3.0-only",
      },
    }],
    "relationships": [],
  }


def toolchain_lock():
  return {
    "schemaVersion": 1,
    "lockType": "toolchain",
    "platform": "linux-amd64",
    "sourceDateEpoch": 1720000000,
    "environment": {},
    "tools": [{
      "id": "zstd", "name": "zstd", "version": "1.5.6",
      "sourceUrl": "https://packages.example.test/zstd.deb",
      "license": "BSD-3-Clause",
    }],
  }


def locked_zstd_toolchain(payload):
  digest = hashlib.sha256(payload).hexdigest()
  return {
    "schemaVersion": 1,
    "lockType": "toolchain",
    "platform": "linux-amd64",
    "sourceDateEpoch": 1720000000,
    "environment": {},
    "tools": [{
      "id": "zstd",
      "name": "zstd",
      "version": "1.5.6",
      "kind": "binary",
      "platform": "linux-amd64",
      "sourceUrl": "https://packages.example.test/zstd",
      "sha256": digest,
      "size": len(payload),
      "mediaType": "application/octet-stream",
      "consumers": ["package"],
      "license": "BSD-3-Clause",
      "materialization": {
        "root": "toolchain",
        "type": "file",
        "destination": "usr/bin/zstd",
        "mode": "0755",
      },
    }],
  }


def verifier_image_lock():
  return {
    "schemaVersion": 1,
    "lockType": "image",
    "platform": "linux-amd64",
    "images": [{
      "id": "builder",
      "role": "builder",
      "reference": "ubuntu:24.04",
      "digest": "sha256:" + "1" * 64,
      "configDigest": "sha256:" + "2" * 64,
      "platform": "linux/amd64",
      "sourceUrl": "https://hub.docker.com/_/ubuntu",
    }],
  }


def component_license():
  payload = b"component payload\n"
  license_text = b"custom component license\n"
  return payload, license_text, {
    "scope": "component",
    "payloadPatterns": ["**/*.bin"],
    "components": [{
      "id": "fonts",
      "payloadPaths": ["fonts/payload.bin"],
      "license": {
        "spdx": "LicenseRef-Unicode-Fonts-for-Ancient-Scripts",
        "evidence": [{
          "type": "git-blob",
          "path": "fonts/payload.bin",
          "blob": "e" * 40,
          "sha256": hashlib.sha256(payload).hexdigest(),
          "locator": "fonts/LICENSE.txt",
          "evidenceSha256": hashlib.sha256(license_text).hexdigest(),
        }],
      },
    }],
  }


def font_with_license_name(license_text):
  encoded = license_text.encode("utf-16-be")
  name_table = (
    struct.pack(">HHH", 0, 1, 18)
    + struct.pack(">HHHHHH", 3, 1, 0x0409, 13, len(encoded), 0)
    + encoded
  )
  return (
    struct.pack(">IHHHH", 0x00010000, 1, 0, 0, 0)
    + struct.pack(">4sIII", b"name", 0, 28, len(name_table))
    + name_table
  )


class PackageDriverTests(unittest.TestCase):
  def test_artifact_record_uses_normalized_relative_path(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      path = root / "packages" / "documentserver.deb"
      path.parent.mkdir()
      path.write_bytes(b"package")
      record = package_driver.artifact_record(
        "jetonlyoffice-deb", "deb", path, root, [],
        "application/vnd.debian.binary-package",
      )
      self.assertEqual("packages/documentserver.deb", record["path"])
      self.assertEqual(hashlib.sha256(b"package").hexdigest(), record["sha256"])

  def test_safe_destination_rejects_escape(self):
    with tempfile.TemporaryDirectory() as directory:
      with self.assertRaisesRegex(package_driver.PackageError, "escapes package root"):
        package_driver.safe_destination(Path(directory), "../outside", "artifact")

  def test_copy_tree_rejects_external_symlink(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source = root / "source"
      source.mkdir()
      outside = root / "outside"
      outside.write_text("outside", encoding="utf-8")
      try:
        (source / "escape").symlink_to(outside)
      except OSError as error:
        self.skipTest(f"symbolic links are unavailable: {error}")
      with self.assertRaisesRegex(package_driver.PackageError, "symlink escapes source"):
        package_driver.copy_tree(source, root / "destination")

  def test_sboms_are_canonical_and_bind_locked_sources(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source = source_lock()
      tools = toolchain_lock()
      source_digest = hashlib.sha256(
        package_driver.canonical_bytes(source).rstrip(b"\n")
      ).hexdigest()
      spdx = root / "release.spdx.json"
      cdx = root / "release.cdx.json"
      carriers = ["jetonlyoffice-deb", "jetonlyoffice-oci", "jetonlyoffice-rootfs"]
      package_driver.make_sbom("spdx", source, tools, carriers, source_digest, spdx)
      package_driver.make_sbom("cyclonedx", source, tools, carriers, source_digest, cdx)
      self.assertEqual(spdx.read_bytes(), package_driver.canonical_bytes(json.loads(spdx.read_text())))
      self.assertEqual(cdx.read_bytes(), package_driver.canonical_bytes(json.loads(cdx.read_text())))
      spdx_value = json.loads(spdx.read_text(encoding="utf-8"))
      self.assertEqual("AGPL-3.0-only", spdx_value["packages"][0]["licenseDeclared"])
      cdx_value = json.loads(cdx.read_text(encoding="utf-8"))
      self.assertEqual(source_digest, cdx_value["metadata"]["properties"][0]["value"])

  def test_sbom_rejects_custom_tool_license_without_extracted_text(self):
    with tempfile.TemporaryDirectory() as directory:
      tools = toolchain_lock()
      tools["tools"][0]["license"] = "LicenseRef-Unbundled-Tool-License"
      with self.assertRaisesRegex(
        package_driver.PackageError, "missing extracted license text"
      ):
        package_driver.make_sbom(
          "spdx",
          source_lock(),
          tools,
          [],
          "f" * 64,
          Path(directory) / "release.spdx.json",
        )

  def test_sboms_exclude_inactive_and_non_build_repositories(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source = source_lock()
      inactive = json.loads(json.dumps(source["repositories"][0]))
      inactive.update({
        "id": "inactive-reference",
        "checkoutPath": "sources/inactive-reference",
        "active": False,
        "buildInput": True,
      })
      non_build = json.loads(json.dumps(source["repositories"][0]))
      non_build.update({
        "id": "non-build-reference",
        "checkoutPath": "sources/non-build-reference",
        "active": True,
        "buildInput": False,
      })
      source["repositories"] += [inactive, non_build]
      source_digest = canonical_sha256(source)
      spdx = root / "release.spdx.json"
      cdx = root / "release.cdx.json"

      package_driver.make_sbom(
        "spdx", source, toolchain_lock(), [], source_digest, spdx
      )
      package_driver.make_sbom(
        "cyclonedx", source, toolchain_lock(), [], source_digest, cdx
      )

      spdx_value = json.loads(spdx.read_text(encoding="utf-8"))
      self.assertEqual(
        {"SPDXRef-documentserver", "SPDXRef-tool-zstd"},
        {item["SPDXID"] for item in spdx_value["packages"]},
      )
      cdx_value = json.loads(cdx.read_text(encoding="utf-8"))
      self.assertEqual(
        {"repo:documentserver", "tool:zstd"},
        {item["bom-ref"] for item in cdx_value["components"]},
      )
      verify_spdx_artifact(
        {"artifacts": [{"type": "spdx", "path": spdx.name}]},
        root,
        source,
        toolchain_lock(),
      )
      verify_cyclonedx_artifact(
        {"artifacts": [{"type": "cyclonedx", "path": cdx.name}]},
        root,
        source,
        toolchain_lock(),
      )

  def test_sboms_preserve_component_licenses_and_custom_license_text(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source = source_lock()
      _, license_text, license_record = component_license()
      source["repositories"][0]["license"] = license_record
      source_digest = hashlib.sha256(
        package_driver.canonical_bytes(source).rstrip(b"\n")
      ).hexdigest()
      spdx = root / "release.spdx.json"
      cdx = root / "release.cdx.json"
      extracted = {
        "LicenseRef-Unicode-Fonts-for-Ancient-Scripts": license_text.decode("utf-8")
      }

      package_driver.make_sbom(
        "spdx", source, toolchain_lock(), [], source_digest, spdx, extracted
      )
      package_driver.make_sbom(
        "cyclonedx", source, toolchain_lock(), [], source_digest, cdx, extracted
      )

      spdx_value = json.loads(spdx.read_text(encoding="utf-8"))
      component_package = next(
        item for item in spdx_value["packages"]
        if item["SPDXID"] == "SPDXRef-documentserver-fonts"
      )
      self.assertEqual(
        "LicenseRef-Unicode-Fonts-for-Ancient-Scripts",
        component_package["licenseDeclared"],
      )
      self.assertIn("fonts/payload.bin", component_package["comment"])
      self.assertEqual([{
        "licenseId": "LicenseRef-Unicode-Fonts-for-Ancient-Scripts",
        "extractedText": license_text.decode("utf-8"),
      }], spdx_value["hasExtractedLicensingInfos"])
      cdx_value = json.loads(cdx.read_text(encoding="utf-8"))
      component = next(
        item for item in cdx_value["components"]
        if item["bom-ref"] == "repo:documentserver:fonts"
      )
      self.assertEqual(
        [{"expression": "LicenseRef-Unicode-Fonts-for-Ancient-Scripts"}],
        component["licenses"],
      )
      self.assertTrue(any(
        item["name"] == "jetonlyoffice.licenseEvidence"
        and "fonts/LICENSE.txt" in item["value"]
        for item in component["properties"]
      ))

      spdx_manifest = {"artifacts": [{
        "id": "jetonlyoffice-spdx", "type": "spdx", "path": spdx.name,
      }]}
      cdx_manifest = {"artifacts": [{
        "id": "jetonlyoffice-cyclonedx", "type": "cyclonedx", "path": cdx.name,
      }]}
      verify_spdx_artifact(spdx_manifest, root, source, toolchain_lock())
      verify_cyclonedx_artifact(cdx_manifest, root, source, toolchain_lock())

      cdx_value["metadata"]["properties"][0]["value"] = "0" * 64
      cdx.write_bytes(package_driver.canonical_bytes(cdx_value))
      with self.assertRaisesRegex(BaselineError, "source lock binding"):
        verify_cyclonedx_artifact(cdx_manifest, root, source, toolchain_lock())
      cdx_value["metadata"]["properties"][0]["value"] = source_digest
      cdx.write_bytes(package_driver.canonical_bytes(cdx_value))

      original_packages = list(spdx_value["packages"])
      spdx_value["packages"] = [
        item for item in original_packages
        if item["SPDXID"] != "SPDXRef-tool-zstd"
      ]
      spdx.write_bytes(package_driver.canonical_bytes(spdx_value))
      with self.assertRaisesRegex(BaselineError, "package ids"):
        verify_spdx_artifact(spdx_manifest, root, source, toolchain_lock())
      spdx_value["packages"] = list(original_packages)

      spdx_value["packages"].append({
        "SPDXID": "SPDXRef-unlocked",
        "name": "unlocked",
      })
      spdx.write_bytes(package_driver.canonical_bytes(spdx_value))
      with self.assertRaisesRegex(BaselineError, "package ids"):
        verify_spdx_artifact(spdx_manifest, root, source, toolchain_lock())
      spdx_value["packages"] = list(original_packages)

      del spdx_value["hasExtractedLicensingInfos"]
      spdx.write_bytes(package_driver.canonical_bytes(spdx_value))
      with self.assertRaisesRegex(BaselineError, "extracted license"):
        verify_spdx_artifact(spdx_manifest, root, source, toolchain_lock())

      original_components = list(cdx_value["components"])
      cdx_value["components"] = [
        item for item in original_components
        if item["bom-ref"] != "tool:zstd"
      ]
      cdx.write_bytes(package_driver.canonical_bytes(cdx_value))
      with self.assertRaisesRegex(BaselineError, "bom-ref values"):
        verify_cyclonedx_artifact(cdx_manifest, root, source, toolchain_lock())
      cdx_value["components"] = list(original_components)

      cdx_value["components"].append({
        "bom-ref": "tool:unlocked",
        "name": "unlocked",
      })
      cdx.write_bytes(package_driver.canonical_bytes(cdx_value))
      with self.assertRaisesRegex(BaselineError, "bom-ref values"):
        verify_cyclonedx_artifact(cdx_manifest, root, source, toolchain_lock())
      cdx_value["components"] = list(original_components)

      component["properties"] = [
        item for item in component["properties"]
        if item["name"] != "jetonlyoffice.licenseEvidence"
      ]
      cdx.write_bytes(package_driver.canonical_bytes(cdx_value))
      with self.assertRaisesRegex(BaselineError, "license evidence"):
        verify_cyclonedx_artifact(cdx_manifest, root, source, toolchain_lock())

  def test_license_bundle_collects_component_evidence(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source_tree = root / "source"
      checkout = source_tree / "sources" / "DocumentServer"
      (checkout / "fonts").mkdir(parents=True)
      payload, license_text, license_record = component_license()
      (checkout / "fonts" / "payload.bin").write_bytes(payload)
      (checkout / "fonts" / "LICENSE.txt").write_bytes(license_text)
      source = source_lock()
      source["repositories"][0]["license"] = license_record
      excluded = json.loads(json.dumps(source["repositories"][0]))
      excluded.update({
        "id": "optional-reference",
        "checkoutPath": "sources/optional-reference",
        "active": False,
        "buildInput": False,
      })
      source["repositories"].append(excluded)
      work = root / "work"
      notice = root / "NOTICE.txt"
      zstd_payload = b"locked zstd executable\n"
      tools = locked_zstd_toolchain(zstd_payload)
      zstd_tool = tools["tools"][0]
      cached_zstd = root / "toolchain" / "zstd" / zstd_tool["sha256"]
      cached_zstd.parent.mkdir(parents=True)
      cached_zstd.write_bytes(zstd_payload)

      with patch.object(package_driver, "tar_directory"):
        extracted = package_driver.make_license_artifacts(
          source_tree,
          source,
          tools,
          canonical_sha256(source),
          work,
          root / "licenses.tar.zst",
          notice,
          source["sourceDateEpoch"],
        )

      evidence = work / "license-bundle" / "repositories" / "documentserver" \
        / "components" / "fonts" / "evidence" \
        / (hashlib.sha256(license_text).hexdigest() + ".license")
      self.assertEqual(license_text, evidence.read_bytes())
      self.assertEqual({
        "LicenseRef-Unicode-Fonts-for-Ancient-Scripts": license_text.decode("utf-8")
      }, extracted)
      manifest = json.loads(
        (work / "license-bundle" / "manifest.json").read_text(encoding="utf-8")
      )
      component = manifest["repositories"][0]["components"][0]
      self.assertEqual("fonts/payload.bin", component["payloadPaths"][0])
      self.assertEqual(
        evidence.relative_to(work / "license-bundle").as_posix(),
        component["license"]["evidence"][0]["licensePath"],
      )
      self.assertIn("documentserver/fonts", notice.read_text(encoding="utf-8"))

      bundle_root = work / "license-bundle"
      archive = root / "licenses.tar"
      with tarfile.open(archive, "w") as output:
        for path in sorted(bundle_root.rglob("*"), key=lambda item: item.as_posix()):
          output.add(path, arcname=path.relative_to(bundle_root).as_posix(), recursive=False)
      compressed = root / "licenses.tar.zst"
      compressed.write_bytes(ZSTD_MAGIC + b"locked payload")
      license_manifest = {"artifacts": [{
        "id": "jetonlyoffice-licenses", "type": "licenses", "path": compressed.name,
      }]}

      def verify_archive():
        def fake_run(command, **kwargs):
          verifier_mount = next(
            item for item in command
            if item.startswith("type=bind,src=")
            and item.endswith(",dst=/verifier,readonly")
          )
          verifier_root = Path(
            verifier_mount.removeprefix("type=bind,src=").removesuffix(
              ",dst=/verifier,readonly"
            )
          )
          self.assertEqual(zstd_payload, (verifier_root / "zstd").read_bytes())
          kwargs["stdout"].write(archive.read_bytes())
          return SimpleNamespace(returncode=0, stderr=b"")

        with patch("offline_baseline.subprocess.run", side_effect=fake_run):
          return verify_license_artifact(
            license_manifest,
            root,
            source,
            tools,
            root,
            verifier_image_lock(),
            "docker",
          )

      self.assertEqual({
        "LicenseRef-Unicode-Fonts-for-Ancient-Scripts": license_text.decode("utf-8")
      }, verify_archive())

      manifest["sourceLockSha256"] = "0" * 64
      (bundle_root / "manifest.json").write_bytes(
        package_driver.canonical_bytes(manifest)
      )
      with tarfile.open(archive, "w") as output:
        for path in sorted(bundle_root.rglob("*"), key=lambda item: item.as_posix()):
          output.add(path, arcname=path.relative_to(bundle_root).as_posix(), recursive=False)
      with self.assertRaisesRegex(BaselineError, "source lock binding"):
        verify_archive()
      manifest["sourceLockSha256"] = canonical_sha256(source)

      manifest["tools"] = []
      (bundle_root / "manifest.json").write_bytes(
        package_driver.canonical_bytes(manifest)
      )
      with tarfile.open(archive, "w") as output:
        for path in sorted(bundle_root.rglob("*"), key=lambda item: item.as_posix()):
          output.add(path, arcname=path.relative_to(bundle_root).as_posix(), recursive=False)
      with self.assertRaisesRegex(BaselineError, "toolchain inventory"):
        verify_archive()

      manifest["tools"] = [{
        "id": zstd_tool["id"],
        "name": zstd_tool["name"],
        "version": zstd_tool["version"],
        "license": zstd_tool["license"],
        "sourceUrl": zstd_tool["sourceUrl"],
        "sha256": zstd_tool["sha256"],
      }]
      (bundle_root / "manifest.json").write_bytes(
        package_driver.canonical_bytes(manifest)
      )

      evidence.write_bytes(b"tampered license\n")
      with tarfile.open(archive, "w") as output:
        for path in sorted(bundle_root.rglob("*"), key=lambda item: item.as_posix()):
          output.add(path, arcname=path.relative_to(bundle_root).as_posix(), recursive=False)
      with self.assertRaisesRegex(BaselineError, "evidence digest"):
        verify_archive()

      evidence.write_bytes(license_text)
      unexpected = bundle_root / "unexpected.txt"
      unexpected.write_text("unlocked material\n", encoding="utf-8")
      with tarfile.open(archive, "w") as output:
        for path in sorted(bundle_root.rglob("*"), key=lambda item: item.as_posix()):
          output.add(path, arcname=path.relative_to(bundle_root).as_posix(), recursive=False)
      with self.assertRaisesRegex(BaselineError, "member inventory"):
        verify_archive()
      unexpected.unlink()
      with tarfile.open(archive, "w") as output:
        for path in sorted(bundle_root.rglob("*"), key=lambda item: item.as_posix()):
          output.add(path, arcname=path.relative_to(bundle_root).as_posix(), recursive=False)
        symbolic_link = tarfile.TarInfo("unexpected-link")
        symbolic_link.type = tarfile.SYMTYPE
        symbolic_link.linkname = "manifest.json"
        output.addfile(symbolic_link)
      with self.assertRaisesRegex(BaselineError, "member inventory"):
        verify_archive()

  def test_locked_zstd_verifier_uses_only_digest_bound_cache_bytes(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      payload = b"locked zstd executable\n"
      toolchain = locked_zstd_toolchain(payload)
      tool = toolchain["tools"][0]
      cached = root / "toolchain" / "zstd" / tool["sha256"]
      cached.parent.mkdir(parents=True)
      cached.write_bytes(payload)

      with locked_zstd_verifier(toolchain, root) as executable:
        self.assertNotEqual(cached, executable)
        self.assertEqual(payload, executable.read_bytes())
        self.assertEqual(tool["sha256"], hashlib.sha256(executable.read_bytes()).hexdigest())

      cached.write_bytes(b"tampered zstd executable\n")
      with self.assertRaisesRegex(BaselineError, "digest does not match") as caught:
        with locked_zstd_verifier(toolchain, root):
          pass
      self.assertEqual(3, caught.exception.exit_code)

      cached.unlink()
      with self.assertRaisesRegex(BaselineError, "is missing") as caught:
        with locked_zstd_verifier(toolchain, root):
          pass
      self.assertEqual(3, caught.exception.exit_code)

      toolchain["tools"][0]["materialization"]["type"] = "deb"
      with self.assertRaisesRegex(BaselineError, "executable") as caught:
        with locked_zstd_verifier(toolchain, root):
          pass
      self.assertEqual(2, caught.exception.exit_code)

  def test_license_archive_fallback_invokes_locked_zstd_copy(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      payload = b"locked zstd executable\n"
      toolchain = locked_zstd_toolchain(payload)
      tool = toolchain["tools"][0]
      cached = root / "toolchain" / "zstd" / tool["sha256"]
      cached.parent.mkdir(parents=True)
      cached.write_bytes(payload)
      compressed = root / "licenses.tar.zst"
      compressed.write_bytes(ZSTD_MAGIC + b"not directly readable as tar")
      expanded = root / "licenses.tar"
      with tarfile.open(expanded, "w") as archive:
        manifest = root / "manifest.json"
        manifest.write_text("{}\n", encoding="ascii")
        archive.add(manifest, arcname="manifest.json")
      expanded_bytes = expanded.read_bytes()
      commands = []

      def fake_run(command, **kwargs):
        commands.append(command)
        self.assertEqual("docker", command[0])
        self.assertEqual("never", command[command.index("--pull") + 1])
        self.assertEqual("none", command[command.index("--network") + 1])
        self.assertEqual("linux/amd64", command[command.index("--platform") + 1])
        self.assertIn("--read-only", command)
        self.assertIn("no-new-privileges", command)
        self.assertIn(
          pinned_image_reference(verifier_image_lock()["images"][0]), command
        )
        verifier_mount = next(
          item for item in command
          if item.startswith("type=bind,src=") and item.endswith(",dst=/verifier,readonly")
        )
        verifier_root = Path(
          verifier_mount.removeprefix("type=bind,src=").removesuffix(",dst=/verifier,readonly")
        )
        self.assertEqual(payload, (verifier_root / "zstd").read_bytes())
        kwargs["stdout"].write(expanded_bytes)
        return SimpleNamespace(returncode=0, stderr=b"")

      with patch("offline_baseline.subprocess.run", side_effect=fake_run):
        with open_license_archive(
          compressed, toolchain, root, verifier_image_lock(), "docker"
        ) as archive:
          self.assertIn("manifest.json", archive.getnames())

      self.assertEqual(
        ["/verifier/zstd", "--decompress", "--stdout", "/input/licenses.tar.zst"],
        commands[0][-4:],
      )

  def test_locked_zstd_verifier_rejects_aliased_cache_root(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      cache = root / "cache"
      cache.mkdir()
      alias = root / "cache-alias"
      try:
        alias.symlink_to(cache, target_is_directory=True)
      except OSError as error:
        self.skipTest(f"directory symlinks are unavailable: {error}")
      toolchain = locked_zstd_toolchain(b"locked zstd executable\n")

      with self.assertRaisesRegex(BaselineError, "cache root must not be an alias") \
          as caught:
        with locked_zstd_verifier(toolchain, alias):
          pass
      self.assertEqual(3, caught.exception.exit_code)

  def test_license_archive_rejects_non_zstd_before_decompression(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      payload = b"locked zstd executable\n"
      toolchain = locked_zstd_toolchain(payload)
      tool = toolchain["tools"][0]
      cached = root / "toolchain" / "zstd" / tool["sha256"]
      cached.parent.mkdir(parents=True)
      cached.write_bytes(payload)
      archive_path = root / "licenses.tar.zst"
      with tarfile.open(archive_path, "w") as archive:
        manifest = root / "manifest.json"
        manifest.write_text("{}\n", encoding="ascii")
        archive.add(manifest, arcname="manifest.json")

      with patch(
        "offline_baseline.subprocess.run",
        side_effect=AssertionError("decompressor must not run"),
      ):
        with self.assertRaisesRegex(BaselineError, "zstd"):
          with open_license_archive(archive_path, toolchain, root):
            pass

  def test_license_archive_verifies_declared_lfs_materialized_digest(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      license_text = b"materialized LFS license\n"
      source = source_lock()
      source["repositories"][0]["license"]["materializedSha256"] = hashlib.sha256(
        license_text
      ).hexdigest()
      source["repositories"][0]["license"]["spdx"] = "LicenseRef-LFS-License"
      payload = b"locked zstd executable\n"
      toolchain = locked_zstd_toolchain(payload)
      tool = toolchain["tools"][0]
      cached = root / "toolchain" / "zstd" / tool["sha256"]
      cached.parent.mkdir(parents=True)
      cached.write_bytes(payload)

      bundle = root / "bundle"
      bundled_license = bundle / "repositories" / "documentserver" / "LICENSE"
      bundled_license.parent.mkdir(parents=True)
      bundled_license.write_bytes(license_text)
      manifest = {
        "schemaVersion": 1,
        "sourceLockSha256": canonical_sha256(source),
        "repositories": [{
          "id": "documentserver",
          "commit": source["repositories"][0]["commit"],
          "origin": source["repositories"][0]["origin"],
          "spdx": "LicenseRef-LFS-License",
          "licenseSha256": hashlib.sha256(license_text).hexdigest(),
          "licensePath": bundled_license.relative_to(bundle).as_posix(),
        }],
        "tools": [{
          "id": tool["id"],
          "name": tool["name"],
          "version": tool["version"],
          "license": tool["license"],
          "sourceUrl": tool["sourceUrl"],
          "sha256": tool["sha256"],
        }],
      }
      (bundle / "manifest.json").write_bytes(package_driver.canonical_bytes(manifest))
      expanded = root / "licenses.tar"
      with tarfile.open(expanded, "w") as archive:
        for path in sorted(bundle.rglob("*"), key=lambda item: item.as_posix()):
          archive.add(path, arcname=path.relative_to(bundle).as_posix(), recursive=False)
      compressed = root / "licenses.tar.zst"
      compressed.write_bytes(ZSTD_MAGIC + b"locked payload")
      artifact_manifest = {"artifacts": [{
        "id": "jetonlyoffice-licenses",
        "type": "licenses",
        "path": compressed.name,
      }]}

      def fake_run(command, **kwargs):
        verifier_mount = next(
          item for item in command
          if item.startswith("type=bind,src=")
          and item.endswith(",dst=/verifier,readonly")
        )
        verifier_root = Path(
          verifier_mount.removeprefix("type=bind,src=").removesuffix(
            ",dst=/verifier,readonly"
          )
        )
        self.assertEqual(payload, (verifier_root / "zstd").read_bytes())
        kwargs["stdout"].write(expanded.read_bytes())
        return SimpleNamespace(returncode=0, stderr=b"")

      with patch("offline_baseline.subprocess.run", side_effect=fake_run):
        self.assertEqual(
          {"LicenseRef-LFS-License": license_text.decode("utf-8")},
          verify_license_artifact(
            artifact_manifest,
            root,
            source,
            toolchain,
            root,
            verifier_image_lock(),
            "docker",
          ),
        )

  def test_license_bundle_uses_declared_lfs_materialized_digest(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source_tree = root / "source"
      checkout = source_tree / "sources" / "DocumentServer"
      checkout.mkdir(parents=True)
      license_text = b"materialized LFS license\n"
      (checkout / "LICENSE").write_bytes(license_text)
      source = source_lock()
      source["repositories"][0]["license"]["materializedSha256"] = hashlib.sha256(
        license_text
      ).hexdigest()
      source["repositories"][0]["license"]["spdx"] = "LicenseRef-LFS-License"
      with patch.object(package_driver, "tar_directory"):
        extracted = package_driver.make_license_artifacts(
          source_tree,
          source,
          toolchain_lock(),
          "f" * 64,
          root / "work",
          root / "licenses.tar.zst",
          root / "NOTICE.txt",
          source["sourceDateEpoch"],
        )
      self.assertEqual(
        {"LicenseRef-LFS-License": license_text.decode("utf-8")},
        extracted,
      )
      spdx = root / "release.spdx.json"
      package_driver.make_sbom(
        "spdx",
        source,
        toolchain_lock(),
        [],
        canonical_sha256(source),
        spdx,
        extracted,
      )
      verify_spdx_artifact(
        {"artifacts": [{"type": "spdx", "path": spdx.name}]},
        root,
        source,
        toolchain_lock(),
        extracted,
      )

  def test_component_license_bundle_extracts_font_and_zip_evidence(self):
    with tempfile.TemporaryDirectory() as directory:
      checkout = Path(directory)
      font_text = "embedded font license"
      font = font_with_license_name(font_text)
      font_path = checkout / "fonts" / "Example.ttf"
      font_path.parent.mkdir()
      font_path.write_bytes(font)
      font_evidence = {
        "type": "font-name",
        "path": "fonts/Example.ttf",
        "blob": "1" * 40,
        "sha256": hashlib.sha256(font).hexdigest(),
        "locator": "name:13",
        "evidenceSha256": hashlib.sha256(font_text.encode("utf-8")).hexdigest(),
      }
      repository = {"id": "fonts", "lfsObjects": []}
      self.assertEqual(
        font_text.encode("utf-8"),
        package_driver.component_evidence_bytes(checkout, repository, font_evidence),
      )

      zip_path = checkout / "archives" / "bundle.zip"
      zip_path.parent.mkdir()
      zip_text = b"archive license\n"
      with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("LICENSE.txt", zip_text)
      zip_payload = zip_path.read_bytes()
      zip_evidence = {
        "type": "zip-member",
        "path": "archives/bundle.zip",
        "blob": "2" * 40,
        "sha256": hashlib.sha256(zip_payload).hexdigest(),
        "locator": "LICENSE.txt",
        "evidenceSha256": hashlib.sha256(zip_text).hexdigest(),
      }
      self.assertEqual(
        zip_text,
        package_driver.component_evidence_bytes(checkout, repository, zip_evidence),
      )

  def test_provenance_binds_only_release_carriers(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      source = source_lock()
      inactive = json.loads(json.dumps(source["repositories"][0]))
      inactive.update({
        "id": "inactive-reference",
        "origin": "https://example.test/inactive.git",
        "active": False,
      })
      non_build = json.loads(json.dumps(source["repositories"][0]))
      non_build.update({
        "id": "non-build-reference",
        "origin": "https://example.test/non-build.git",
        "buildInput": False,
      })
      source["repositories"] += [inactive, non_build]
      tools = toolchain_lock()
      images = json.loads(
        (REPOSITORY_ROOT / "locks" / "images.lock.json").read_text(encoding="utf-8")
      )
      builder = next(item for item in images["images"] if item["role"] == "builder")
      build = {
        "sourceLockSha256": canonical_sha256(source),
        "toolchainLockSha256": canonical_sha256(tools),
        "imageLockSha256": canonical_sha256(images),
        "sourceDateEpoch": 1720000000,
        "builderImageDigest": builder["digest"],
        "buildId": "jetonlyoffice-9.4.0-linux-amd64",
      }
      records = [
        {"id": "jetonlyoffice-deb", "sha256": "1" * 64},
        {"id": "jetonlyoffice-oci", "sha256": "2" * 64},
        {"id": "jetonlyoffice-rootfs", "sha256": "3" * 64},
        {"id": "jetonlyoffice-source", "sha256": "4" * 64},
      ]
      output = root / "provenance.jsonl"
      package_driver.make_provenance(source, build, [
        "jetonlyoffice-deb", "jetonlyoffice-oci", "jetonlyoffice-rootfs",
      ], records, output)
      value = json.loads(output.read_text(encoding="utf-8"))
      self.assertEqual(["jetonlyoffice-deb", "jetonlyoffice-oci", "jetonlyoffice-rootfs"],
                       [item["name"] for item in value["subject"]])
      self.assertEqual("none", value["predicate"]["buildDefinition"]["externalParameters"]["network"])
      self.assertEqual(
        [{
          "uri": source["repositories"][0]["origin"],
          "digest": {"gitCommit": source["repositories"][0]["commit"]},
        }],
        value["predicate"]["buildDefinition"]["resolvedDependencies"],
      )
      manifest = {
        "artifacts": [
          {"id": record["id"], "type": artifact_type, "sha256": record["sha256"]}
          for record, artifact_type in zip(records[:3], ("deb", "oci", "rootfs"))
        ] + [{
          "id": "jetonlyoffice-provenance",
          "type": "provenance",
          "path": output.name,
          "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        }],
      }
      verify_provenance_artifact(manifest, root, source, tools, images)
      tampered = json.loads(json.dumps(value))
      tampered["predicate"]["buildDefinition"]["resolvedDependencies"].append({
        "uri": inactive["origin"],
        "digest": {"gitCommit": inactive["commit"]},
      })
      output.write_text(json.dumps(tampered), encoding="utf-8")
      with self.assertRaisesRegex(BaselineError, "resolved dependencies"):
        verify_provenance_artifact(manifest, root, source, tools, images)
      for field, replacement in (
        ("imageLockSha256", "f" * 64),
        ("sourceDateEpoch", 1),
      ):
        tampered = json.loads(json.dumps(value))
        tampered["predicate"]["buildDefinition"]["externalParameters"][field] = replacement
        output.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaisesRegex(BaselineError, field):
          verify_provenance_artifact(manifest, root, source, tools, images)
      tampered = json.loads(json.dumps(value))
      tampered["predicate"]["buildDefinition"]["externalParameters"][
        "unexpectedInput"
      ] = "unlocked"
      output.write_text(json.dumps(tampered), encoding="utf-8")
      with self.assertRaisesRegex(BaselineError, "external parameters"):
        verify_provenance_artifact(manifest, root, source, tools, images)
      for path, replacement, message in (
        (("predicate", "buildDefinition", "buildType"), "https://example.test/build", "build type"),
        (("predicate", "runDetails", "builder", "id"), "example://builder", "builder identity"),
      ):
        tampered = json.loads(json.dumps(value))
        target = tampered
        for key in path[:-1]:
          target = target[key]
        target[path[-1]] = replacement
        output.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaisesRegex(BaselineError, message):
          verify_provenance_artifact(manifest, root, source, tools, images)

  @unittest.skipUnless(
    sys.platform.startswith("linux")
    and all(shutil.which(command) for command in ("dpkg-deb", "tar", "zstd"))
    and docker_has_runtime_image(),
    "Linux deterministic packaging tools are unavailable",
  )
  def test_full_package_driver_is_binary_reproducible(self):
    epoch = 1720000000
    source = source_lock()
    docker_input = {
      "id": "docker-documentserver", "role": "package-input",
      "checkoutPath": "sources/docker-documentserver",
      "origin": "https://github.com/sunwayking/JetOnlyOffice-Docker-DocumentServer.git",
      "upstream": "https://github.com/ONLYOFFICE/Docker-DocumentServer.git",
      "commit": "1" * 40, "tree": "2" * 40, "commitTime": epoch,
      "projectFork": False, "buildInput": True, "active": True,
      "license": {"path": "LICENSE", "blob": "3" * 40,
                  "sha256": "4" * 64, "spdx": "AGPL-3.0-only"},
    }
    package_input = {
      "id": "document-server-package", "role": "package-input",
      "checkoutPath": "sources/document-server-package",
      "origin": "https://github.com/sunwayking/JetOnlyOffice-document-server-package.git",
      "upstream": "https://github.com/ONLYOFFICE/document-server-package.git",
      "commit": "5" * 40, "tree": "6" * 40, "commitTime": epoch,
      "projectFork": False, "buildInput": True, "active": True,
      "license": {"path": "LICENSE", "blob": "7" * 40,
                  "sha256": hashlib.sha256(b"package license\n").hexdigest(),
                   "spdx": "AGPL-3.0-only"},
    }
    component_payload, component_text, component_record = component_license()
    component_input = {
      "id": "font-assets", "role": "build-input",
      "checkoutPath": "sources/font-assets",
      "origin": "https://github.com/sunwayking/JetOnlyOffice-font-assets.git",
      "upstream": "https://github.com/ONLYOFFICE/font-assets.git",
      "commit": "8" * 40, "tree": "9" * 40, "commitTime": epoch,
      "projectFork": False, "buildInput": True, "active": True,
      "lfsObjects": [], "license": component_record,
    }
    source["repositories"][0:0] = [docker_input, package_input]
    source["repositories"].append(component_input)
    documentserver_input = next(
      item for item in source["repositories"] if item["id"] == "documentserver"
    )
    documentserver_input["license"]["sha256"] = hashlib.sha256(
      b"documentserver license\n"
    ).hexdigest()
    docker_input["license"]["sha256"] = hashlib.sha256(
      b"docker license\n"
    ).hexdigest()
    zstd_payload = Path(shutil.which("zstd")).read_bytes()
    tools = locked_zstd_toolchain(zstd_payload)
    tools["sourceDateEpoch"] = epoch
    images = json.loads(
      (REPOSITORY_ROOT / "locks" / "images.lock.json").read_text(encoding="utf-8")
    )
    builder_image = next(
      item for item in images["images"] if item["role"] == "builder"
    )
    build = {
      "schemaVersion": 1, "manifestType": "build",
      "buildId": "jetonlyoffice-9.4.0-linux-amd64",
      "platform": "linux-amd64", "configuration": "Release",
      "sourceLockSha256": canonical_sha256(source),
      "toolchainLockSha256": canonical_sha256(tools),
      "imageLockSha256": canonical_sha256(images),
      "builderImageDigest": builder_image["digest"],
      "sourceDateEpoch": epoch,
    }

    def run_package(root):
      output = root / "artifacts"
      build_output = output / "build-output"
      server = build_output / "linux_64" / "onlyoffice" / "documentserver"
      docservice = server / "server" / "DocService" / "docservice"
      docservice.parent.mkdir(parents=True)
      docservice.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8", newline="\n")
      docservice.chmod(0o755)
      source_tree = root / "source-tree"
      documentserver_license = source_tree / "sources" / "DocumentServer" / "LICENSE"
      documentserver_license.parent.mkdir(parents=True)
      documentserver_license.write_text(
        "documentserver license\n", encoding="utf-8", newline="\n"
      )
      docker_entrypoint = source_tree / "sources" / "docker-documentserver" / "run-document-server.sh"
      docker_entrypoint.parent.mkdir(parents=True)
      (docker_entrypoint.parent / "LICENSE").write_text(
        "docker license\n", encoding="utf-8", newline="\n"
      )
      docker_entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8", newline="\n")
      docker_entrypoint.chmod(0o755)
      supervisor_init = docker_entrypoint.parent / "config" / "supervisor" / "supervisor"
      supervisor_init.parent.mkdir(parents=True)
      supervisor_init.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8", newline="\n")
      supervisor_init.chmod(0o755)
      supervisor_conf = docker_entrypoint.parent / "config" / "supervisor" / "ds" / "ds-docservice.conf"
      supervisor_conf.parent.mkdir(parents=True)
      supervisor_conf.write_text(
        "[program:docservice]\ncommand=/var/www/COMPANY_NAME/documentserver/server/DocService/docservice\n",
        encoding="utf-8", newline="\n",
      )
      package_source = source_tree / "sources" / "document-server-package"
      package_source.mkdir(parents=True)
      (package_source / "LICENSE").write_text(
        "package license\n", encoding="utf-8", newline="\n"
      )
      (package_source / "Makefile").write_text(
        "PRODUCT_VERSION ?= 0.0.0\n"
        "BUILD_NUMBER ?= 0\n"
        "deb:\n"
        "\trm -rf fixture deb\n"
        "\tmkdir -p fixture/DEBIAN fixture/etc/onlyoffice/documentserver fixture/usr/lib/systemd/system fixture/var/www/onlyoffice/documentserver deb\n"
        "\tprintf 'Package: onlyoffice-documentserver\\nVersion: $(PRODUCT_VERSION)-$(BUILD_NUMBER)\\nArchitecture: amd64\\nDepends: nginx-extras, supervisor\\nMaintainer: Upstream\\nDescription: Upstream DocumentServer\\n' > fixture/DEBIAN/control\n"
        "\tprintf '#!/bin/sh\\nexit 0\\n' > fixture/DEBIAN/postinst\n"
        "\tprintf '#!/bin/sh\\nexit 0\\n' > fixture/DEBIAN/prerm\n"
        "\tchmod 0755 fixture/DEBIAN/postinst fixture/DEBIAN/prerm\n"
        "\tprintf '{\\\"services\\\":{}}\\n' > fixture/etc/onlyoffice/documentserver/local.json\n"
        "\tprintf '[Unit]\\nDescription=DocumentServer\\n' > fixture/usr/lib/systemd/system/ds-docservice.service\n"
        "\tcp -a ../build_tools/out/linux_64/onlyoffice/documentserver/. fixture/var/www/onlyoffice/documentserver/\n"
        "\tdpkg-deb --build --root-owner-group fixture deb/onlyoffice-documentserver_$(PRODUCT_VERSION)-$(BUILD_NUMBER)_amd64.deb\n",
        encoding="utf-8", newline="\n",
      )
      component_source = source_tree / "sources" / "font-assets" / "fonts"
      component_source.mkdir(parents=True)
      (component_source / "payload.bin").write_bytes(component_payload)
      (component_source / "LICENSE.txt").write_bytes(component_text)
      package_driver.tar_directory(source_tree, build_output / "source-archive.tar.zst",
                                   epoch, compressed=True)
      runtime_tree = root / "runtime-tree"
      os_release = runtime_tree / "etc" / "os-release"
      os_release.parent.mkdir(parents=True)
      os_release.write_text("ID=ubuntu\nVERSION_ID=24.04\n", encoding="ascii", newline="\n")
      runtime_binary = runtime_tree / "usr" / "sbin" / "rmt"
      runtime_binary.parent.mkdir(parents=True)
      runtime_binary.write_text("#!/bin/sh\n", encoding="ascii", newline="\n")
      (runtime_tree / "etc" / "rmt").symlink_to("/usr/sbin/rmt")
      (runtime_tree / "etc" / "mtab").symlink_to("/proc/mounts")
      package_driver.tar_directory(runtime_tree, root / "runtime-rootfs.tar", epoch)
      build_path = output / "build-manifest.json"
      build_path.write_bytes(package_driver.canonical_bytes(build))
      source_path = root / "sources.lock.json"
      toolchain_path = root / "toolchain.lock.json"
      image_path = root / "images.lock.json"
      source_path.write_bytes(package_driver.canonical_bytes(source))
      toolchain_path.write_bytes(package_driver.canonical_bytes(tools))
      image_path.write_bytes(package_driver.canonical_bytes(images))
      zstd_tool = tools["tools"][0]
      cached_zstd = root / "cache" / "toolchain" / "zstd" / zstd_tool["sha256"]
      cached_zstd.parent.mkdir(parents=True)
      cached_zstd.write_bytes(zstd_payload)
      package_driver.package(SimpleNamespace(
        build_manifest=build_path, source_lock=source_path,
        toolchain_lock=toolchain_path, image_lock=image_path,
        runtime_rootfs=root / "runtime-rootfs.tar", cache=root / "cache",
        work=root / "work", output=output,
        output_manifest="artifact-manifest.json",
      ))
      manifest = json.loads((output / "artifact-manifest.json").read_text(encoding="utf-8"))
      validate_contract(manifest, "artifact-manifest", REPOSITORY_ROOT / "schemas")
      verify_supply_chain_artifacts(
        manifest,
        output,
        source,
        tools,
        root / "cache",
        images,
        shutil.which("docker"),
      )
      license_tree = root / "license-tree"
      license_tree.mkdir()
      subprocess.run(
        ["tar", "--use-compress-program=zstd", "-xf",
         str(output / "licenses" / "jetonlyoffice-licenses.tar.zst"),
         "-C", str(license_tree)],
        check=True,
      )
      self.assertEqual(
        "documentserver license\n",
        (license_tree / "repositories" / "documentserver" / "LICENSE")
        .read_text(encoding="utf-8"),
      )
      component_evidence = license_tree / "repositories" / "font-assets" \
        / "components" / "fonts" / "evidence" \
        / (hashlib.sha256(component_text).hexdigest() + ".license")
      self.assertEqual(component_text, component_evidence.read_bytes())
      notice = (output / "licenses" / "NOTICE.txt").read_text(encoding="utf-8")
      self.assertIn("document-server-package", notice)
      self.assertIn(canonical_sha256(source), notice)
      deb_tree = root / "deb-tree"
      rootfs_tree = root / "rootfs-tree"
      deb_tree.mkdir()
      rootfs_tree.mkdir()
      subprocess.run(
        ["dpkg-deb", "--extract", str(output / "packages" / "jetonlyoffice.deb"),
         str(deb_tree)],
        check=True,
      )
      subprocess.run(
        ["tar", "--use-compress-program=zstd", "-xf",
         str(output / "packages" / "rootfs.tar.zst"), "-C", str(rootfs_tree)],
        check=True,
      )
      payload = Path("var/www/onlyoffice/documentserver/server/DocService/docservice")
      self.assertTrue((deb_tree / payload).is_file())
      self.assertTrue((deb_tree / "etc" / "onlyoffice" / "documentserver" / "local.json").is_file())
      control = subprocess.run(
        ["dpkg-deb", "--field", str(output / "packages" / "jetonlyoffice.deb")],
        check=True, capture_output=True, text=True,
      ).stdout
      self.assertIn("Package: jetonlyoffice", control)
      self.assertIn("Depends: nginx-extras, supervisor", control)
      self.assertFalse((deb_tree / "etc" / "os-release").exists())
      self.assertEqual("ID=ubuntu\nVERSION_ID=24.04\n",
                       (rootfs_tree / "etc" / "os-release").read_text(encoding="ascii"))
      self.assertEqual("/usr/sbin/rmt", os.readlink(rootfs_tree / "etc" / "rmt"))
      self.assertEqual("/proc/mounts", os.readlink(rootfs_tree / "etc" / "mtab"))
      self.assertEqual((deb_tree / payload).read_bytes(),
                       (rootfs_tree / payload).read_bytes())
      self.assertIn(
        "/var/www/onlyoffice/documentserver",
        (rootfs_tree / "etc" / "supervisor" / "conf.d" / "ds-docservice.conf")
        .read_text(encoding="utf-8"),
      )
      return {item["type"]: item["sha256"] for item in manifest["artifacts"]
              if item["type"] in {"deb", "rootfs", "oci"}}

    with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
      self.assertEqual(run_package(Path(first)), run_package(Path(second)))

  def test_oci_verifier_binds_digest_and_jwt_entrypoint(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      oci = root / "oci"
      blobs = oci / "blobs" / "sha256"
      blobs.mkdir(parents=True)
      layer = root / "layer.tar"
      entrypoint_bytes = ENTRYPOINT_PATH.read_bytes()
      entrypoint_source = root / "entrypoint"
      entrypoint_source.write_bytes(entrypoint_bytes)
      with tarfile.open(layer, "w") as archive:
        archive.add(entrypoint_source,
                    arcname="usr/local/bin/jetonlyoffice-entrypoint")
      layer_bytes = layer.read_bytes()
      layer_digest = hashlib.sha256(layer_bytes).hexdigest()
      (blobs / layer_digest).write_bytes(layer_bytes)
      config_bytes = package_driver.canonical_bytes({
        "architecture": "amd64", "os": "linux",
        "config": {"Entrypoint": ["/usr/local/bin/jetonlyoffice-entrypoint"],
                   "Env": ["JWT_ENABLED=true"]},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + layer_digest]},
      })
      config_digest = hashlib.sha256(config_bytes).hexdigest()
      (blobs / config_digest).write_bytes(config_bytes)
      manifest_bytes = package_driver.canonical_bytes({
        "schemaVersion": 2,
        "config": {"digest": "sha256:" + config_digest, "size": len(config_bytes)},
        "layers": [{"digest": "sha256:" + layer_digest, "size": len(layer_bytes)}],
      })
      manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
      (blobs / manifest_digest).write_bytes(manifest_bytes)
      (oci / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}\n', encoding="utf-8")
      (oci / "index.json").write_bytes(package_driver.canonical_bytes({
        "schemaVersion": 2,
        "manifests": [{"digest": "sha256:" + manifest_digest,
                       "size": len(manifest_bytes)}],
      }))
      archive_path = root / "jetonlyoffice.oci.tar"
      with tarfile.open(archive_path, "w") as archive:
        for path in sorted(oci.rglob("*"), key=lambda item: item.as_posix()):
          archive.add(path, arcname=path.relative_to(oci).as_posix(), recursive=False)
      manifest = {"artifacts": [{
        "id": "jetonlyoffice-oci", "type": "oci", "path": archive_path.name,
        "ociDigest": "sha256:" + manifest_digest,
      }]}
      verify_oci_artifact(manifest, root)

  @unittest.skipUnless(docker_has_runtime_image(), "locked runtime image is unavailable")
  def test_jwt_entrypoint_fails_closed_without_secret_or_when_disabled(self):
    def command(environment=(), arguments=()):
      value = ["docker", "run", "--rm", "--pull", "never", "--network", "none"]
      for item in environment:
        value += ["--env", item]
      value += ["--mount", f"type=bind,src={ENTRYPOINT_PATH.resolve()},dst=/entrypoint,readonly",
                RUNTIME_IMAGE, "/bin/sh", "/entrypoint", *arguments]
      return value

    missing = subprocess.run(command(), capture_output=True, text=True, check=False)
    self.assertEqual(78, missing.returncode, missing.stderr)
    disabled = subprocess.run(
      command(["JWT_SECRET=valid-secret", "JWT_ENABLED=false"]),
      capture_output=True, text=True, check=False,
    )
    self.assertEqual(78, disabled.returncode, disabled.stderr)
    valid = subprocess.run(
      command(["JWT_SECRET=valid-secret"], ["/bin/sh", "-c", "exit 0"]),
      capture_output=True, text=True, check=False,
    )
    self.assertEqual(0, valid.returncode, valid.stderr)


if __name__ == "__main__":
  unittest.main()
