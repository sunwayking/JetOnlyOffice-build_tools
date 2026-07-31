import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from offline_baseline import pinned_image_reference  # noqa: E402

with (REPOSITORY_ROOT / "locks" / "images.lock.json").open(encoding="utf-8") as stream:
  IMAGE_LOCK = json.load(stream)
BUILDER_IMAGE = next(item for item in IMAGE_LOCK["images"] if item["role"] == "builder")
UBUNTU_IMAGE = pinned_image_reference(BUILDER_IMAGE)


def docker_has_locked_image():
  docker = shutil.which("docker")
  if not docker:
    return False
  result = subprocess.run(
    [docker, "image", "inspect", UBUNTU_IMAGE],
    capture_output=True,
    check=False,
  )
  return result.returncode == 0


@unittest.skipUnless(docker_has_locked_image(), "locked Ubuntu image is unavailable")
class ContainerMaterializationTests(unittest.TestCase):
  @unittest.skipUnless(os.name == "posix", "POSIX mount permissions are unavailable")
  def test_work_mount_is_writable_by_unprivileged_builder_user(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      cache = root / "cache"
      cache.mkdir()
      work = self.prepare_container_directory(root / "work")
      result = self.run_materializer(
        cache,
        work,
        "test \"$(id -u):$(id -g)\" = 65534:65534; "
        "touch /work/unprivileged-write",
        user="65534:65534",
      )
      self.assertEqual(0, result.returncode, result.stderr + result.stdout)
      self.assertTrue((work / "unprivileged-write").is_file())

  def prepare_container_directory(self, path):
    path.mkdir()
    if os.name == "posix":
      path.chmod(0o777)
    return path

  def run_materializer(self, cache, work, command, user=None):
    arguments = [
      shutil.which("docker"),
      "run",
      "--rm",
      "--pull",
      "never",
      "--network",
      "none",
      "--read-only",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--tmpfs",
      "/tmp:rw,nosuid,nodev",
    ]
    if user is None and hasattr(os, "getuid") and hasattr(os, "getgid"):
      user = f"{os.getuid()}:{os.getgid()}"
    if user:
      arguments += ["--user", user]
    arguments += [
        "--env",
        "JETONLYOFFICE_NETWORK_POLICY=none",
        "--mount",
        "type=bind,src=" + cache.as_posix() + ",dst=/input/cache,readonly",
        "--mount",
        "type=bind,src=" + work.as_posix() + ",dst=/work",
        "--mount",
        "type=bind,src="
        + (REPOSITORY_ROOT / "scripts" / "container").as_posix()
        + ",dst=/jetonlyoffice/container,readonly",
        UBUNTU_IMAGE,
        "/bin/sh",
        "-c",
        command,
      ]
    return subprocess.run(
      arguments,
      capture_output=True,
      encoding="utf-8",
      errors="replace",
      check=False,
    )

  def prepare_file_plan(self, root):
    payload = b"locked compiler\n"
    digest = hashlib.sha256(payload).hexdigest()
    cache = root / "cache"
    source = cache / "toolchain" / "compiler" / digest
    source.parent.mkdir(parents=True)
    source.write_bytes(payload)
    (cache / "materialization-plan.tsv").write_bytes(
      (
        "file\ttoolchain/compiler/" + digest
        + "\ttoolchain\tusr/bin/compiler\t0\t0755\n"
      ).encode("ascii")
    )
    work = self.prepare_container_directory(root / "work")
    return cache, work

  def test_materializer_places_locked_file_in_private_toolchain_root(self):
    with tempfile.TemporaryDirectory() as directory:
      cache, work = self.prepare_file_plan(Path(directory))
      result = self.run_materializer(
        cache,
        work,
        ". /jetonlyoffice/container/materialize-toolchain.sh; "
        "test \"$(cat /work/toolchain-root/usr/bin/compiler)\" = 'locked compiler'; "
        "test \"$(stat -c '%a' /work/toolchain-root/usr/bin/compiler)\" = 755",
      )
      self.assertEqual(0, result.returncode, result.stderr + result.stdout)

  def test_materializer_exports_offline_package_cache_locations(self):
    with tempfile.TemporaryDirectory() as directory:
      cache, work = self.prepare_file_plan(Path(directory))
      result = self.run_materializer(
        cache,
        work,
        ". /jetonlyoffice/container/materialize-toolchain.sh; "
        "test \"$NPM_CONFIG_CACHE\" = /work/offline-cache/npm; "
        "test \"$PIP_FIND_LINKS\" = /work/offline-cache/pip; "
        "test \"$PKG_CACHE_PATH\" = /work/offline-cache/pkg",
      )
      self.assertEqual(0, result.returncode, result.stderr + result.stdout)

  def test_materializer_rejects_symbolic_link_parent_alias(self):
    with tempfile.TemporaryDirectory() as directory:
      cache, work = self.prepare_file_plan(Path(directory))
      result = self.run_materializer(
        cache,
        work,
        "mkdir -p /work/toolchain-root /work/escaped; "
        "ln -s /work/escaped /work/toolchain-root/usr; "
        ". /jetonlyoffice/container/materialize-toolchain.sh",
      )
      self.assertEqual(3, result.returncode, result.stderr)
      self.assertFalse((work / "escaped" / "bin" / "compiler").exists())

  def test_materialized_tools_are_available_to_later_archive_steps(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      cache = root / "cache"
      fake_xz = cache / "toolchain" / "00-xz" / ("a" * 64)
      fake_xz.parent.mkdir(parents=True)
      fake_xz.write_text("#!/bin/sh\ncat\n", encoding="ascii", newline="\n")
      archive = cache / "toolchain" / "10-payload" / ("b" * 64)
      archive.parent.mkdir(parents=True)
      with tarfile.open(archive, "w") as stream:
        member = tarfile.TarInfo("payload.txt")
        payload = b"materialized in order\n"
        member.size = len(payload)
        member.mode = 0o644
        stream.addfile(member, io.BytesIO(payload))
      (cache / "materialization-plan.tsv").write_bytes(
        (
          "file\ttoolchain/00-xz/" + ("a" * 64)
          + "\ttoolchain\tusr/bin/xz\t0\t0755\n"
          + "tar-xz\ttoolchain/10-payload/" + ("b" * 64)
          + "\ttoolchain\topt/payload\t0\t-\n"
        ).encode("ascii")
      )
      work = self.prepare_container_directory(root / "work")
      result = self.run_materializer(
        cache,
        work,
        ". /jetonlyoffice/container/materialize-toolchain.sh; "
        "test \"$(cat /work/toolchain-root/opt/payload/payload.txt)\" "
        "= 'materialized in order'",
      )
      self.assertEqual(0, result.returncode, result.stderr + result.stdout)

  def test_build_entrypoint_uses_only_materialized_python(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      cache = root / "cache"
      fake_python = cache / "toolchain" / "python" / ("a" * 64)
      fake_python.parent.mkdir(parents=True)
      fake_python.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "printf '%s\\n' \"$*\" >> /work/python-invocations\n"
        "case \"$1\" in\n"
        "  make.py)\n"
        "    mkdir -p out/packaging\n"
        "    printf '#!/bin/sh\\nexit 0\\n' > out/packaging/package.sh\n"
        "    chmod 0755 out/packaging/package.sh\n"
        "    ;;\n"
        "  */write-build-manifest.py) printf '{}\\n' > \"$JETONLYOFFICE_BUILD_MANIFEST_PATH\" ;;\n"
        "esac\n",
        encoding="ascii",
        newline="\n",
      )
      (cache / "materialization-plan.tsv").write_bytes(
        (
          "file\ttoolchain/python/" + ("a" * 64)
          + "\tsources\tsources/build_tools/tools/linux/python3/bin/python3"
          + "\t0\t0755\n"
        ).encode("ascii")
      )
      (cache / "bootstrap-manifest.json").write_text("{}\n", encoding="ascii")
      sources = root / "sources" / "sources" / "build_tools"
      sources.mkdir(parents=True)
      (sources / "configure.py").write_text("# locked fixture\n", encoding="ascii")
      (sources / "make.py").write_text("# locked fixture\n", encoding="ascii")
      (sources / ".gitignore").write_text("out/\n", encoding="ascii")
      git_directory = sources / ".git"
      git_directory.mkdir()
      (git_directory / "config").write_text("checkout-local metadata\n", encoding="ascii")
      container_scripts = sources / "scripts" / "container"
      container_scripts.mkdir(parents=True)
      (container_scripts / "package-driver.py").write_text(
        "#!/usr/bin/env python3\n", encoding="ascii"
      )
      (container_scripts / "jwt-entrypoint.sh").write_text(
        "#!/bin/sh\nexit 78\n", encoding="ascii"
      )
      fake_zstd = cache / "toolchain" / "zstd" / ("b" * 64)
      fake_zstd.parent.mkdir(parents=True)
      fake_zstd.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "output=\n"
        "while test $# -gt 0; do\n"
        "  if test \"$1\" = -o; then output=$2; shift 2; else shift; fi\n"
        "done\n"
        "test -n \"$output\"\n"
        "cat > \"$output\"\n",
        encoding="ascii",
        newline="\n",
      )
      with (cache / "materialization-plan.tsv").open("a", encoding="ascii", newline="\n") as plan:
        plan.write(
          "file\ttoolchain/zstd/" + ("b" * 64)
          + "\ttoolchain\tusr/bin/zstd\t0\t0755\n"
        )
      output = self.prepare_container_directory(root / "output")
      work = self.prepare_container_directory(root / "work")
      docker_user = []
      if hasattr(os, "getuid") and hasattr(os, "getgid"):
        docker_user = ["--user", f"{os.getuid()}:{os.getgid()}"]
      locks = root / "locks"
      locks.mkdir()
      for name in ("sources.lock.json", "toolchain.lock.json", "images.lock.json"):
        (locks / name).write_text("{}\n", encoding="ascii")
      result = subprocess.run(
        [
          shutil.which("docker"),
          "run",
          *docker_user,
          "--rm",
          "--pull",
          "never",
          "--network",
          "none",
          "--read-only",
          "--cap-drop",
          "ALL",
          "--security-opt",
          "no-new-privileges",
          "--tmpfs",
          "/tmp:rw,nosuid,nodev",
          "--env",
          "JETONLYOFFICE_NETWORK_POLICY=none",
          "--env",
          "SOURCE_DATE_EPOCH=200",
          "--env",
          "JETONLYOFFICE_BUILD_MANIFEST_PATH=/output/build-manifest.json",
          "--mount",
          "type=bind,src=" + (root / "sources").as_posix() + ",dst=/input/sources,readonly",
          "--mount",
          "type=bind,src=" + (locks / "sources.lock.json").as_posix() + ",dst=/input/sources.lock.json,readonly",
          "--mount",
          "type=bind,src=" + (locks / "toolchain.lock.json").as_posix() + ",dst=/input/toolchain.lock.json,readonly",
          "--mount",
          "type=bind,src=" + (locks / "images.lock.json").as_posix() + ",dst=/input/images.lock.json,readonly",
          "--mount",
          "type=bind,src=" + cache.as_posix() + ",dst=/input/cache,readonly",
          "--mount",
          "type=bind,src=" + output.as_posix() + ",dst=/output",
          "--mount",
          "type=bind,src=" + work.as_posix() + ",dst=/work",
          "--mount",
          "type=bind,src="
          + (REPOSITORY_ROOT / "scripts" / "container").as_posix()
          + ",dst=/jetonlyoffice/container,readonly",
          UBUNTU_IMAGE,
          "/bin/sh",
          "/jetonlyoffice/container/build-baseline.sh",
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
      )
      diagnostics = result.stderr + result.stdout
      diagnostics += "\nwork=" + repr([
        path.relative_to(work).as_posix() for path in work.rglob("*")
      ])
      if (work / "python-invocations").is_file():
        diagnostics += "\ninvocations=" + (work / "python-invocations").read_text(
          encoding="utf-8"
        )
      self.assertEqual(0, result.returncode, diagnostics)
      self.assertEqual(
        [
          "/jetonlyoffice/container/prepare-source-archive.py --source /work/sources --manifest /work/sources/source-tree-manifest.json",
          "configure.py --update 0 --branch detached --clean 1 --module server --platform linux_64 --sysroot 0",
          "make.py",
          "/jetonlyoffice/container/write-build-manifest.py",
        ],
        (work / "python-invocations").read_text(encoding="utf-8").splitlines(),
      )
      with tarfile.open(output / "build-output" / "source-archive.tar.zst", "r:") as archive:
        names = {
          name.removeprefix("./")
          for name in archive.getnames()
          if name.removeprefix("./")
        }
      self.assertIn("sources/build_tools/.gitignore", names)
      self.assertFalse(any(".git" in PurePosixPath(name).parts for name in names))
      self.assertTrue({"sources.lock.json", "toolchain.lock.json", "images.lock.json"} <= names)


if __name__ == "__main__":
  unittest.main()
