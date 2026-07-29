import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from offline_baseline import (  # noqa: E402
  BaselineError,
  cache_toolchain_input,
  locked_cache_view,
  promote_manifest_files,
  verify_local_image,
  verify_manifest_files,
)


class FakeResponse:
  def __init__(self, payload, url="https://downloads.example.test/tool"):
    self.payload = payload
    self.url = url
    self.offset = 0
    self.headers = {"Content-Length": str(len(payload))}

  def __enter__(self):
    return self

  def __exit__(self, *_args):
    return False

  def geturl(self):
    return self.url

  def read(self, size):
    chunk = self.payload[self.offset:self.offset + size]
    self.offset += len(chunk)
    return chunk


def tool(identifier, payload, consumers):
  return {
    "id": identifier,
    "name": identifier,
    "version": "1",
    "kind": "binary",
    "platform": "linux-amd64",
    "sourceUrl": "https://downloads.example.test/" + identifier,
    "sha256": hashlib.sha256(payload).hexdigest(),
    "size": len(payload),
    "mediaType": "application/octet-stream",
    "consumers": consumers,
    "license": "MIT",
    "materialization": {
      "root": "toolchain",
      "type": "file",
      "destination": "usr/share/jetonlyoffice/" + identifier,
      "mode": "0644",
    },
  }


class LockedInputTests(unittest.TestCase):
  def test_bootstrap_downloads_and_atomically_caches_exact_locked_bytes(self):
    payload = b"locked bytes\n"
    value = tool("compiler", payload, ["build"])
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory) / value["sha256"]
      with patch("offline_baseline.urlopen", return_value=FakeResponse(payload)):
        cache_toolchain_input(value, path, path.parent)
      self.assertEqual(payload, path.read_bytes())
      self.assertEqual([], list(path.parent.glob("*.part")))

  def test_bootstrap_rejects_redirect_downgrade_and_mismatched_bytes(self):
    payload = b"locked bytes\n"
    value = tool("compiler", payload, ["build"])
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory) / value["sha256"]
      response = FakeResponse(payload, "http://downloads.example.test/tool")
      with patch("offline_baseline.urlopen", return_value=response):
        with self.assertRaisesRegex(BaselineError, "redirected outside HTTPS"):
          cache_toolchain_input(value, path, path.parent)
      self.assertFalse(path.exists())

      response = FakeResponse(payload, "https://user:password@downloads.example.test/tool")
      with patch("offline_baseline.urlopen", return_value=response):
        with self.assertRaisesRegex(BaselineError, "credential-free HTTPS"):
          cache_toolchain_input(value, path, path.parent)
      self.assertFalse(path.exists())

      response = FakeResponse(b"wrong bytes\n")
      response.headers = {}
      with patch("offline_baseline.urlopen", return_value=response):
        with self.assertRaisesRegex(BaselineError, "download size mismatch"):
          cache_toolchain_input(value, path, path.parent)
      self.assertFalse(path.exists())

  def test_cache_view_contains_only_declared_consumers_and_is_not_a_hardlink(self):
    build_payload = b"build\n"
    package_payload = b"package\n"
    runtime_payload = b"runtime\n"
    tools = [
      tool("build-tool", build_payload, ["build"]),
      tool("package-tool", package_payload, ["package"]),
      tool("runtime-tool", runtime_payload, ["runtime"]),
    ]
    lock = {
      "schemaVersion": 1,
      "lockType": "toolchain",
      "platform": "linux-amd64",
      "sourceDateEpoch": 1,
      "environment": {},
      "tools": tools,
    }
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      for value, payload in zip(tools, (build_payload, package_payload, runtime_payload)):
        path = root / "toolchain" / value["id"] / value["sha256"]
        path.parent.mkdir(parents=True)
        path.write_bytes(payload)
      with locked_cache_view(lock, root, {}, {"build"}) as view:
        selected = view / "toolchain" / "build-tool" / tools[0]["sha256"]
        self.assertEqual(build_payload, selected.read_bytes())
        self.assertFalse((view / "toolchain" / "package-tool").exists())
        self.assertFalse((view / "toolchain" / "runtime-tool").exists())
        plan = json.loads((view / "materialization-plan.json").read_text(encoding="utf-8"))
        self.assertEqual(["build"], plan["consumers"])
        self.assertEqual([{
          "destination": "usr/share/jetonlyoffice/build-tool",
          "id": "build-tool",
          "mode": "0644",
          "root": "toolchain",
          "source": "toolchain/build-tool/" + tools[0]["sha256"],
          "type": "file",
        }], plan["entries"])
        self.assertEqual(
          "file\ttoolchain/build-tool/" + tools[0]["sha256"]
          + "\ttoolchain\tusr/share/jetonlyoffice/build-tool\t0\t0644\n",
          (view / "materialization-plan.tsv").read_text(encoding="utf-8"),
        )
        (root / "toolchain" / "build-tool" / tools[0]["sha256"]).write_bytes(b"changed\n")
        self.assertEqual(build_payload, selected.read_bytes())

  def test_toolchain_cache_rejects_symbolic_link_parent_aliases(self):
    payload = b"locked bytes\n"
    value = tool("compiler", payload, ["build"])
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      cache = root / "cache"
      aliased = root / "aliased"
      cache.mkdir()
      aliased.mkdir()
      try:
        (cache / "toolchain").symlink_to(aliased, target_is_directory=True)
      except OSError as error:
        self.skipTest(f"symbolic links are unavailable: {error}")
      path = cache / "toolchain" / value["id"] / value["sha256"]
      with patch("offline_baseline.urlopen", return_value=FakeResponse(payload)):
        with self.assertRaisesRegex(BaselineError, "parent must not be a symbolic link"):
          cache_toolchain_input(value, path, cache)
      self.assertEqual([], list(aliased.rglob("*")))

  def test_cache_view_rechecks_symbolic_link_parent_aliases(self):
    payload = b"locked bytes\n"
    value = tool("compiler", payload, ["build"])
    lock = {
      "schemaVersion": 1,
      "lockType": "toolchain",
      "platform": "linux-amd64",
      "sourceDateEpoch": 1,
      "environment": {},
      "tools": [value],
    }
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      cache = root / "cache"
      aliased = root / "aliased"
      cache.mkdir()
      target = aliased / value["id"] / value["sha256"]
      target.parent.mkdir(parents=True)
      target.write_bytes(payload)
      try:
        (cache / "toolchain").symlink_to(aliased, target_is_directory=True)
      except OSError as error:
        self.skipTest(f"symbolic links are unavailable: {error}")
      with self.assertRaisesRegex(BaselineError, "parent must not be a symbolic link"):
        with locked_cache_view(lock, cache, {}, {"build"}):
          self.fail("unsafe cache view was created")

  @unittest.skipUnless(os.name == "nt", "junctions are Windows-specific")
  def test_toolchain_cache_rejects_junction_parent_aliases(self):
    if not hasattr(Path, "is_junction"):
      self.skipTest("Path.is_junction is unavailable")
    payload = b"locked bytes\n"
    value = tool("compiler", payload, ["build"])
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      cache = root / "cache"
      aliased = root / "aliased"
      cache.mkdir()
      aliased.mkdir()
      result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(cache / "toolchain"), str(aliased)],
        capture_output=True,
        check=False,
      )
      if result.returncode != 0:
        self.skipTest("junction creation is unavailable")
      path = cache / "toolchain" / value["id"] / value["sha256"]
      with patch("offline_baseline.urlopen", return_value=FakeResponse(payload)):
        with self.assertRaisesRegex(BaselineError, "parent must not be a symbolic link"):
          cache_toolchain_input(value, path, cache)
      self.assertEqual([], list(aliased.rglob("*")))

  def test_image_identity_binds_platform_repository_and_config_digests(self):
    digest = "sha256:" + "a" * 64
    config = "sha256:" + "b" * 64
    image = {
      "id": "builder",
      "reference": "ubuntu:24.04",
      "digest": digest,
      "configDigest": config,
    }
    record = (
      '[{"Id":"' + config + '","RepoDigests":["ubuntu@' + digest
      + '"],"Os":"linux","Architecture":"amd64"}]'
    )
    with patch("offline_baseline.run_external", return_value=record):
      verify_local_image("docker", image)

    bad_record = record.replace(config, "sha256:" + "c" * 64, 1)
    with patch("offline_baseline.run_external", return_value=bad_record):
      with self.assertRaisesRegex(BaselineError, "config digest mismatch"):
        verify_local_image("docker", image)

    wrong_repository = record.replace("ubuntu@", "untrusted/ubuntu@")
    with patch("offline_baseline.run_external", return_value=wrong_repository):
      with self.assertRaisesRegex(BaselineError, "repository digest mismatch"):
        verify_local_image("docker", image)

  def test_image_identity_rejects_malformed_inspect_records(self):
    image = {
      "id": "builder",
      "reference": "ubuntu:24.04",
      "digest": "sha256:" + "a" * 64,
      "configDigest": "sha256:" + "b" * 64,
    }
    for record in (
      "[null]",
      '[{"Id":"sha256:' + "b" * 64
      + '","RepoDigests":"ubuntu@sha256:' + "a" * 64
      + '","Os":"linux","Architecture":"amd64"}]',
    ):
      with self.subTest(record=record):
        with patch("offline_baseline.run_external", return_value=record):
          with self.assertRaisesRegex(BaselineError, "unexpected image record"):
            verify_local_image("docker", image)

  def test_symlink_inventory_promotes_the_link_instead_of_moving_its_target(self):
    payload = b"library\n"
    target = "libjet.so.1"
    target_bytes = target.encode("utf-8")
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      staging = root / "staging"
      artifact = root / "artifact"
      library = staging / "build-output" / target
      link = staging / "build-output" / "libjet.so"
      library.parent.mkdir(parents=True)
      library.write_bytes(payload)
      try:
        link.symlink_to(target)
      except OSError as error:
        self.skipTest(f"symbolic links are unavailable: {error}")
      manifest = {
        "files": [
          {
            "type": "symlink",
            "path": "build-output/libjet.so",
            "mode": "0777",
            "size": len(target_bytes),
            "sha256": hashlib.sha256(target_bytes).hexdigest(),
            "symlinkTarget": target,
          },
          {
            "type": "file",
            "path": "build-output/libjet.so.1",
            "mode": "0644",
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
          },
        ]
      }
      verify_manifest_files(manifest, staging, "test output")
      artifact.mkdir()
      promote_manifest_files(
        manifest,
        staging,
        artifact,
        artifact / "build-manifest.json",
        "test output",
      )
      promoted_link = artifact / "build-output" / "libjet.so"
      self.assertTrue(promoted_link.is_symlink())
      self.assertEqual(target, promoted_link.readlink().as_posix())
      self.assertEqual(payload, (artifact / "build-output" / target).read_bytes())

  def test_manifest_inventory_rejects_symbolic_link_parent_aliases(self):
    payload = b"artifact\n"
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      real = root / "real"
      real.mkdir()
      (real / "artifact.bin").write_bytes(payload)
      try:
        (root / "build-output").symlink_to(real, target_is_directory=True)
      except OSError as error:
        self.skipTest(f"symbolic links are unavailable: {error}")
      manifest = {
        "files": [{
          "type": "file",
          "path": "build-output/artifact.bin",
          "mode": "0644",
          "size": len(payload),
          "sha256": hashlib.sha256(payload).hexdigest(),
        }]
      }
      with self.assertRaisesRegex(BaselineError, "parent must not be a symbolic link"):
        verify_manifest_files(manifest, root, "test output")

  def test_manifest_inventory_rejects_cyclic_symbolic_link_targets(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      try:
        (root / "self-loop").symlink_to("self-loop")
        (root / "loop-a").symlink_to("loop-b")
        (root / "loop-b").symlink_to("loop-a")
      except OSError as error:
        self.skipTest(f"symbolic links are unavailable: {error}")
      for path, target in (("self-loop", "self-loop"), ("loop-a", "loop-b")):
        target_bytes = target.encode("utf-8")
        manifest = {
          "files": [{
            "type": "symlink",
            "path": path,
            "mode": "0777",
            "size": len(target_bytes),
            "sha256": hashlib.sha256(target_bytes).hexdigest(),
            "symlinkTarget": target,
          }]
        }
        with self.subTest(path=path):
          with self.assertRaisesRegex(BaselineError, "target cannot be resolved"):
            verify_manifest_files(manifest, root, "test output")

  def test_promotion_rejects_artifact_that_conflicts_with_manifest_output(self):
    payload = b"not the final manifest\n"
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      staging = root / "staging"
      artifact = root / "artifact"
      staging.mkdir()
      artifact.mkdir()
      (staging / "build-manifest.json").write_bytes(payload)
      manifest = {
        "files": [{
          "type": "file",
          "path": "build-manifest.json",
          "mode": "0644",
          "size": len(payload),
          "sha256": hashlib.sha256(payload).hexdigest(),
        }]
      }
      with self.assertRaisesRegex(BaselineError, "conflicts with manifest output"):
        promote_manifest_files(
          manifest,
          staging,
          artifact,
          artifact / "build-manifest.json",
          "test output",
        )

  def test_promotion_rejects_source_and_destination_parent_aliases(self):
    payload = b"artifact\n"
    manifest = {
      "files": [{
        "type": "file",
        "path": "build-output/artifact.bin",
        "mode": "0644",
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
      }]
    }
    for alias_side in ("source", "destination"):
      with self.subTest(alias_side=alias_side), tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        staging = root / "staging"
        artifact = root / "artifact"
        staging.mkdir()
        artifact.mkdir()
        if alias_side == "source":
          real = staging / "real"
          real.mkdir()
          (real / "artifact.bin").write_bytes(payload)
          alias = staging / "build-output"
        else:
          source = staging / "build-output" / "artifact.bin"
          source.parent.mkdir()
          source.write_bytes(payload)
          real = artifact / "real"
          real.mkdir()
          alias = artifact / "build-output"
        try:
          alias.symlink_to(real, target_is_directory=True)
        except OSError as error:
          self.skipTest(f"symbolic links are unavailable: {error}")
        with self.assertRaisesRegex(BaselineError, "parent must not be a symbolic link"):
          promote_manifest_files(
            manifest,
            staging,
            artifact,
            artifact / "build-manifest.json",
            "test output",
          )


if __name__ == "__main__":
  unittest.main()
