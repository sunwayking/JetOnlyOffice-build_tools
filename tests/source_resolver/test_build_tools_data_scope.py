from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_ROOT = REPOSITORY_ROOT / "scripts"
CORE_COMMON_ROOT = SCRIPTS_ROOT / "core_common"
MODULES_ROOT = CORE_COMMON_ROOT / "modules"
sys.path.insert(0, str(SCRIPTS_ROOT))
sys.path.insert(0, str(CORE_COMMON_ROOT))
sys.path.insert(0, str(MODULES_ROOT))

import base  # noqa: E402
import build_sln  # noqa: E402
import config  # noqa: E402
import make_common  # noqa: E402


def load_v8_module():
  spec = importlib.util.spec_from_file_location(
    "jetonlyoffice_build_profile_v8",
    MODULES_ROOT / "v8.py",
  )
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


def load_glew_module():
  spec = importlib.util.spec_from_file_location(
    "jetonlyoffice_build_profile_glew",
    MODULES_ROOT / "glew.py",
  )
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


class BuildToolsDataScopeTests(unittest.TestCase):
  def test_formal_release_entrypoint_fixes_the_audited_profile(self):
    entrypoint = (
      REPOSITORY_ROOT / "scripts" / "container" / "build-baseline.sh"
    ).read_text(encoding="utf-8")

    self.assertIn("--module server", entrypoint)
    self.assertIn("--platform linux_64", entrypoint)
    self.assertIn("--sysroot 0", entrypoint)
    self.assertIn("tools/linux/python3/bin/python3", entrypoint)
    self.assertNotIn("extract.sh", entrypoint)

  def test_formal_linux_profile_disables_sysroot_fetch(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      scripts = root / "scripts"
      scripts.mkdir()
      (root / "config").write_text(
        'module="server"\n'
        'platform="linux_64"\n'
        'sysroot="0"\n',
        encoding="utf-8",
        newline="\n",
      )

      with (
        patch.dict(os.environ, {}, clear=False),
        patch.object(base, "get_script_dir", return_value=str(scripts)),
        patch.object(base, "host_platform", return_value="linux"),
        patch.object(base, "get_gcc_version", return_value=13000),
        patch.object(base, "cmd_in_dir") as fetch,
      ):
        with warnings.catch_warnings():
          warnings.simplefilter("ignore", ResourceWarning)
          config.parse()

      self.assertEqual("", config.option("sysroot"))
      fetch.assert_not_called()

  def test_formal_linux_profile_does_not_enter_android_v8_payload(self):
    v8 = load_v8_module()

    with (
      patch.object(v8.config, "option", side_effect=lambda name: {
        "platform": "linux_64",
        "config": "",
      }.get(name, "")),
      patch.object(v8.config, "check_option", side_effect=lambda name, value: (
        name == "platform" and value == "linux_64"
      )),
      patch.object(v8.base, "host_platform", return_value="linux"),
      patch.object(v8.base, "cmd_in_dir") as command,
      patch.object(v8.v8_89, "make") as make_linux_v8,
    ):
      v8.make()

    make_linux_v8.assert_called_once_with()
    command.assert_not_called()

  def test_formal_linux_profile_does_not_enter_windows_mobile_glew_payload(self):
    glew = load_glew_module()

    with (
      patch.object(glew.base, "host_platform", return_value="linux"),
      patch.object(glew.base, "download") as download,
    ):
      glew.make()

    download.assert_not_called()

  def test_formal_server_profile_enters_cef_preparation(self):
    module_names = [
      "boost", "cef", "icu", "openssl", "v8", "html2", "iwork", "md",
      "hunspell", "harfbuzz", "glew", "hyphen", "googletest", "oo_brotli",
      "heif",
    ]

    with ExitStack() as stack:
      module_makes = {
        name: stack.enter_context(
          patch.object(getattr(make_common, name), "make")
        )
        for name in module_names
      }
      stack.enter_context(
        patch.object(make_common.config, "check_option", return_value=False)
      )
      make_common.make()

    module_makes["cef"].assert_called_once_with()

  def test_formal_server_profile_requires_qmake_projects(self):
    with (
      patch.object(build_sln.config, "option", return_value="linux_64"),
      patch.object(build_sln.config, "platforms", ["linux_64"], create=True),
      patch.object(
        build_sln.sln,
        "get_projects",
        return_value=["core/Common/kernel.pro"],
      ),
      patch.object(build_sln.qmake, "make") as qmake,
    ):
      build_sln.make()

    qmake.assert_called_once_with("linux_64", "core/Common/kernel.pro", "")


if __name__ == "__main__":
  unittest.main()
