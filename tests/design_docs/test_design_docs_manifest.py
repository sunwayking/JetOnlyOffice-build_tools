import contextlib
import io
import json
import shutil
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.design_docs.design_docs_manifest import main  # noqa: E402


def write_design_tree(root):
  (root / "docs").mkdir()
  (root / "CONTEXT.md").write_bytes(b"context\n")
  guide = root / "docs" / "guide.md"
  guide.write_bytes(b"guide\n")
  return guide


class DesignDocsManifestTests(unittest.TestCase):
  def test_committed_manifest_covers_the_migrated_authority(self):
    manifest = (
      REPOSITORY_ROOT / "manifests" / "authoritative-design-docs.v1.json"
    )
    with contextlib.redirect_stderr(io.StringIO()):
      self.assertEqual(0, main([
        "verify",
        "--root",
        str(REPOSITORY_ROOT),
        "--manifest",
        str(manifest),
      ]))
    value = json.loads(manifest.read_text(encoding="utf-8"))
    paths = [item["path"] for item in value["files"]]
    self.assertEqual(paths, sorted(paths, key=lambda path: path.encode("utf-8")))
    self.assertEqual(len(paths), len(set(paths)))
    for expected in (
      "CONTEXT.md",
      "docs/adr/0001-project-forks-and-develop-branch.md",
      "docs/design-source-manifest.json",
      "docs/mobile-design-reference.md",
      "docs/reference/mobile/android-onlyoffice-20260728/01-editor-initial.png",
      "docs/upstream-build-tools.md",
    ):
      with self.subTest(path=expected):
        self.assertIn(expected, paths)

  def test_generate_cli_writes_a_deterministic_per_file_manifest(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      write_design_tree(root)
      manifest = root / "manifests" / "authoritative-design-docs.v1.json"

      self.assertEqual(0, main([
        "generate",
        "--root",
        str(root),
        "--manifest",
        str(manifest),
      ]))

      expected = (
        b'{"files":['
        b'{"path":"CONTEXT.md","sha256":"1ee232df47462fa4a561adbe24ea4a0b67b6d79f9b5f6e15cb8a7ba80f2de117","size":8},'
        b'{"path":"docs/guide.md","sha256":"90c390ec1de806bf945885cd0af51e90c3cd8cda0d0ff676051a56c20848c90f","size":6}'
        b'],"hashAlgorithm":"sha256","manifestType":"authoritative-design-docs","schemaVersion":1}\n'
      )
      self.assertEqual(expected, manifest.read_bytes())

  def test_generate_rejects_a_self_referential_manifest_location(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      write_design_tree(root)
      manifest = root / "docs" / "manifest.json"

      stderr = io.StringIO()
      with contextlib.redirect_stderr(stderr):
        self.assertEqual(1, main([
          "generate",
          "--root",
          str(root),
          "--manifest",
          str(manifest),
        ]))
      self.assertIn("outside CONTEXT.md and docs", stderr.getvalue())
      self.assertFalse(manifest.exists())

  def test_generate_rejects_symbolic_links_in_the_authoritative_set(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      write_design_tree(root)
      target = root / "outside.md"
      target.write_bytes(b"outside\n")
      link = root / "docs" / "linked.md"
      try:
        link.symlink_to(target)
      except OSError as error:
        self.skipTest(f"symbolic links are unavailable: {error}")

      stderr = io.StringIO()
      with contextlib.redirect_stderr(stderr):
        self.assertEqual(1, main([
          "generate",
          "--root",
          str(root),
          "--manifest",
          str(root / "manifest.json"),
        ]))
      self.assertIn("symbolic links are not allowed", stderr.getvalue())

  def test_verify_cli_rejects_content_and_membership_drift(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      guide = write_design_tree(root)
      manifest = root / "manifests" / "authoritative-design-docs.v1.json"
      generate = ["generate", "--root", str(root), "--manifest", str(manifest)]
      verify = ["verify", "--root", str(root), "--manifest", str(manifest)]

      self.assertEqual(0, main(generate))
      self.assertEqual(0, main(verify))

      guide.write_bytes(b"changed\n")
      stderr = io.StringIO()
      with contextlib.redirect_stderr(stderr):
        self.assertEqual(1, main(verify))
      self.assertIn("manifest does not match", stderr.getvalue())

      self.assertEqual(0, main(generate))
      (root / "docs" / "untracked.md").write_bytes(b"new\n")
      with contextlib.redirect_stderr(io.StringIO()):
        self.assertEqual(1, main(verify))

  @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is not available")
  def test_powershell_entrypoint_generates_and_verifies_the_manifest(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      write_design_tree(root)
      manifest = root / "manifest.json"
      script = REPOSITORY_ROOT / "scripts" / "design-docs.ps1"

      for command in ("Generate", "Verify"):
        result = subprocess.run(
          [
            "pwsh",
            "-NoProfile",
            "-File",
            str(script),
            "-Command",
            command,
            "-Root",
            str(root),
            "-Manifest",
            str(manifest),
          ],
          capture_output=True,
          encoding="utf-8",
          errors="replace",
          check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
  unittest.main()
