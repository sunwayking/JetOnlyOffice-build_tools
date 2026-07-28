import os
from pathlib import Path
import shutil
import subprocess
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MODULE = REPOSITORY_ROOT / "qa" / "android" / "device-facts.psm1"
GOOGLE_WEBVIEW_SHA256 = (
  "6faf3c4140407473400934d117815a21af1cfefc5c0bee61c858bc3d72ba6fe5"
)


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell is not available")
class AndroidDeviceFactsTests(unittest.TestCase):
  def parse_certificate(self, fixture):
    environment = dict(os.environ)
    environment["JETONLYOFFICE_APKSIGNER_FIXTURE"] = fixture
    environment["JETONLYOFFICE_DEVICE_FACTS_MODULE"] = str(MODULE)
    command = (
      "Import-Module ([Environment]::GetEnvironmentVariable("
      "'JETONLYOFFICE_DEVICE_FACTS_MODULE')) -Force; "
      "$lines = [Environment]::GetEnvironmentVariable("
      "'JETONLYOFFICE_APKSIGNER_FIXTURE') -split \"`n\"; "
      "Get-ApkSignerCertificateSha256 -SignerOutput $lines"
    )
    return subprocess.run(
      ["pwsh", "-NoProfile", "-Command", command],
      capture_output=True,
      encoding="utf-8",
      errors="replace",
      env=environment,
      check=False,
    )

  def test_parser_accepts_current_build_tools_v3_output(self):
    result = self.parse_certificate(
      "V3.0 Signer: certificate DN: CN=webview\n"
      f"V3.0 Signer: certificate SHA-256 digest: {GOOGLE_WEBVIEW_SHA256}\n"
      "Source Stamp Signer: certificate SHA-256 digest: " + "a" * 64
    )

    self.assertEqual(0, result.returncode, result.stderr)
    self.assertEqual(GOOGLE_WEBVIEW_SHA256, result.stdout.strip())

  def test_parser_keeps_support_for_legacy_signer_number_output(self):
    result = self.parse_certificate(
      f"Signer #1 certificate SHA-256 digest: {GOOGLE_WEBVIEW_SHA256}"
    )

    self.assertEqual(0, result.returncode, result.stderr)
    self.assertEqual(GOOGLE_WEBVIEW_SHA256, result.stdout.strip())

  def test_parser_does_not_treat_source_stamp_as_apk_signer(self):
    result = self.parse_certificate(
      "Source Stamp Signer: certificate SHA-256 digest: " + "a" * 64
    )

    self.assertEqual(0, result.returncode, result.stderr)
    self.assertEqual("", result.stdout.strip())


if __name__ == "__main__":
  unittest.main()
