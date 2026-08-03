import io
import shutil
import struct
import subprocess
import sys
from pathlib import Path
import unittest
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from cef_evidence import (  # noqa: E402
  CefEvidenceError,
  chromium_grit_brotli,
  chromium_pak_resource,
  seven_zip_member_bytes,
)


def chromium_pak(resources, aliases=(), encoding=1, padding=b"\0\0\0", sentinel=0):
  index_end = 12 + (len(resources) + 1) * 6 + len(aliases) * 4
  position = index_end
  entries = []
  payloads = []
  for resource_id, payload in resources:
    entries.append((resource_id, position))
    payloads.append(payload)
    position += len(payload)
  return (
    struct.pack("<IB3sHH", 5, encoding, padding, len(resources), len(aliases))
    + b"".join(struct.pack("<HI", *entry) for entry in entries)
    + struct.pack("<HI", sentinel, position)
    + b"".join(struct.pack("<HH", *alias) for alias in aliases)
    + b"".join(payloads)
  )


class FakeProcess:
  def __init__(self, payload):
    self.stdout = io.BytesIO(payload)
    self.returncode = None
    self.killed = False

  def kill(self):
    self.killed = True
    self.returncode = -9

  def wait(self):
    if self.returncode is None:
      self.returncode = 0
    return self.returncode

  def poll(self):
    return self.returncode


class CefEvidenceTests(unittest.TestCase):
  def test_chromium_datapack_resolves_direct_and_alias_resources(self):
    payload = chromium_pak(
      [(31061, b"credits"), (63001, b"license")],
      aliases=[(64000, 1)],
    )

    self.assertEqual(b"credits", chromium_pak_resource(payload, 31061, "test"))
    self.assertEqual(b"license", chromium_pak_resource(payload, 64000, "test"))

  def test_chromium_datapack_rejects_malformed_header_and_sentinel(self):
    cases = (
      (chromium_pak([(1, b"data")], encoding=3), "encoding"),
      (chromium_pak([(1, b"data")], padding=b"\0\1\0"), "padding"),
      (chromium_pak([(1, b"data")], sentinel=9), "sentinel"),
    )
    for payload, message in cases:
      with self.subTest(message=message), self.assertRaisesRegex(
        CefEvidenceError, message
      ):
        chromium_pak_resource(payload, 1, "test")

  def test_chromium_datapack_rejects_malformed_resource_and_alias_tables(self):
    cases = (
      (chromium_pak([(2, b"a"), (1, b"b")]), "resource identifiers"),
      (chromium_pak([(1, b"a"), (1, b"b")]), "resource identifiers"),
      (chromium_pak([(1, b"a")], aliases=[(2, 1)]), "alias index"),
      (
        chromium_pak([(1, b"a")], aliases=[(3, 0), (2, 0)]),
        "alias identifiers",
      ),
      (
        chromium_pak([(1, b"a")], aliases=[(2, 0), (2, 0)]),
        "alias identifiers",
      ),
      (chromium_pak([(1, b"a")], aliases=[(1, 0)]), "duplicate identifier"),
    )
    for payload, message in cases:
      with self.subTest(message=message), self.assertRaisesRegex(
        CefEvidenceError, message
      ):
        chromium_pak_resource(payload, 1, "test")

  def test_seven_zip_output_is_stopped_at_the_bound(self):
    process = FakeProcess(b"0123456789")
    with patch("cef_evidence.subprocess.Popen", return_value=process):
      with self.assertRaisesRegex(CefEvidenceError, "too large"):
        seven_zip_member_bytes(
          b"archive", "resources.pak", "test", executable="7z", max_bytes=4
        )
    self.assertTrue(process.killed)

  @unittest.skipUnless(shutil.which("node"), "Node.js is unavailable")
  def test_chromium_grit_brotli_validates_magic_size_and_trailing_data(self):
    plain = b"credits\n"
    compressed = subprocess.run(
      [
        "node",
        "-e",
        "const z=require('node:zlib'),c=[];process.stdin.on('data',x=>c.push(x));"
        "process.stdin.on('end',()=>process.stdout.write("
        "z.brotliCompressSync(Buffer.concat(c))))",
      ],
      input=plain,
      capture_output=True,
      check=True,
    ).stdout
    framed = b"\x1e\x9b" + len(plain).to_bytes(6, "little") + compressed

    self.assertEqual(plain, chromium_grit_brotli(framed, "test"))
    for invalid, message in (
      (b"\0\0" + framed[2:], "magic"),
      (framed[:2] + (len(plain) + 1).to_bytes(6, "little") + compressed, "length"),
      (framed + b"trailing", "Brotli"),
    ):
      with self.subTest(message=message), self.assertRaisesRegex(
        CefEvidenceError, message
      ):
        chromium_grit_brotli(invalid, "test")


if __name__ == "__main__":
  unittest.main()
