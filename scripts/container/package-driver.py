#!/usr/bin/env python3
"""Assemble the locked build output into deterministic release artifacts."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import posixpath
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile


class PackageError(RuntimeError):
  pass


def fail(message):
  raise PackageError(message)


def canonical_bytes(value):
  return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":")) + "\n").encode("utf-8")


def sha256_bytes(payload):
  return hashlib.sha256(payload).hexdigest()


def sha256_file(path):
  digest = hashlib.sha256()
  with Path(path).open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
      digest.update(chunk)
  return digest.hexdigest()


def md5_file(path):
  digest = hashlib.md5()
  with Path(path).open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
      digest.update(chunk)
  return digest.hexdigest()


def require_file(path, description):
  path = Path(path)
  if not path.is_file() or path.is_symlink():
    fail(f"{description} is missing or aliased: {path}")
  return path


def load_json(path, description):
  try:
    return json.loads(require_file(path, description).read_text(encoding="utf-8"))
  except (OSError, json.JSONDecodeError) as error:
    fail(f"{description} is invalid: {error}")


def run(command, description, env=None, cwd=None):
  try:
    result = subprocess.run(command, check=False, capture_output=True,
                            text=True, env=env, cwd=cwd)
  except OSError as error:
    fail(f"{description} cannot start: {error}")
  if result.returncode != 0:
    detail = result.stderr.strip() or result.stdout.strip() or "command failed"
    fail(f"{description} failed: {detail}")
  return result


def ensure_command(name):
  if shutil.which(name) is None:
    fail(f"required packaging command is missing: {name}")


def normalize_path(path, root):
  path = Path(path)
  root = Path(root).resolve()
  try:
    relative = path.resolve(strict=False).relative_to(root)
  except ValueError as error:
    fail(f"path escapes packaging root: {path}")
  if any(part in ("", ".", "..") for part in relative.parts):
    fail(f"path is not normalized: {path}")
  return relative.as_posix()


def safe_destination(root, relative, description):
  root = Path(root).resolve()
  destination = root / relative
  try:
    destination.resolve(strict=False).relative_to(root)
  except ValueError as error:
    fail(f"{description} escapes package root: {relative}")
  return destination


def normalize_tree(root, epoch):
  root = Path(root)
  for path in sorted(root.rglob("*"), key=lambda item: item.as_posix(), reverse=True):
    try:
      if path.is_symlink():
        target = os.readlink(path)
        if target.startswith("/"):
          candidate = target.lstrip("/")
        else:
          parent = path.relative_to(root).parent.as_posix()
          candidate = posixpath.join(parent, target)
        normalized = PurePosixPath(posixpath.normpath(candidate))
        if normalized.is_absolute() or ".." in normalized.parts:
          fail(f"package tree symlink escapes rootfs: {path} -> {target}")
        os.utime(path, (epoch, epoch), follow_symlinks=False)
      elif path.is_file():
        os.utime(path, (epoch, epoch))
      elif path.is_dir():
        os.utime(path, (epoch, epoch))
    except (OSError, ValueError, RuntimeError) as error:
      fail(f"cannot normalize package tree entry {path}: {error}")


def copy_tree(source, destination, exclude_names=()):
  source = Path(source).resolve()
  destination = Path(destination)
  if not source.is_dir():
    fail(f"build output directory is missing: {source}")
  excluded = set(exclude_names)
  runtime_files = [
    item for item in source.rglob("*")
    if item.relative_to(source).parts[0] not in excluded
    and (item.is_file() or item.is_symlink())
  ]
  if not runtime_files:
    fail("locked build output contains no runtime files")
  for item in sorted(runtime_files, key=lambda value: value.as_posix()):
    if not item.is_symlink():
      continue
    try:
      item.resolve(strict=True).relative_to(source)
    except (OSError, ValueError, RuntimeError) as error:
      fail(f"build output symlink escapes source: {item}")
  for entry in sorted(source.iterdir(), key=lambda item: item.name):
    if entry.name in excluded:
      continue
    target = destination / entry.name
    if entry.is_symlink():
      resolved = entry.resolve(strict=True)
      try:
        resolved.relative_to(source)
      except ValueError as error:
        fail(f"build output symlink escapes source: {entry}")
      target.parent.mkdir(parents=True, exist_ok=True)
      target.symlink_to(os.readlink(entry), target_is_directory=entry.is_dir())
    elif entry.is_dir():
      shutil.copytree(entry, target, symlinks=True)
    elif entry.is_file():
      target.parent.mkdir(parents=True, exist_ok=True)
      shutil.copyfile(entry, target)
      target.chmod(stat.S_IMODE(entry.stat().st_mode))
    else:
      fail(f"unsupported build output entry: {entry}")


def write_bytes(path, payload, mode=0o644):
  path = Path(path)
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_bytes(payload)
  path.chmod(mode)


def tar_directory(source, output, epoch, compressed=False):
  ensure_command("tar")
  source = Path(source).resolve()
  output = Path(output)
  output.parent.mkdir(parents=True, exist_ok=True)
  options = ["--sort=name", f"--mtime=@{epoch}", "--owner=0", "--group=0",
             "--numeric-owner", "--format=posix",
             "--pax-option=delete=atime,delete=ctime"]
  if compressed:
    ensure_command("zstd")
    tar_process = subprocess.Popen(
      ["tar", *options, "-cf", "-", "-C", str(source), "."],
      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    zstd_process = subprocess.Popen(
      ["zstd", "--quiet", "--threads=1", "-19", "-o", str(output)],
      stdin=tar_process.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    tar_process.stdout.close()
    _, zstd_stderr = zstd_process.communicate()
    tar_stderr = tar_process.stderr.read()
    tar_process.stderr.close()
    tar_code = tar_process.wait()
    if tar_code or zstd_process.returncode:
      detail = (zstd_stderr or tar_stderr).decode("utf-8", "replace").strip()
      fail(f"deterministic tar.zst failed: {detail}")
  else:
    run(["tar", *options, "-cf", str(output), "-C", str(source), "."],
        "deterministic tar")


def extract_source_snapshot(build_output, work):
  archive = require_file(Path(build_output) / "source-archive.tar.zst",
                         "locked source archive")
  destination = Path(work) / "source-snapshot"
  destination.mkdir(parents=True, exist_ok=True)
  ensure_command("tar")
  ensure_command("zstd")
  run(["tar", "--use-compress-program=zstd", "-xf", str(archive),
       "-C", str(destination)], "extract locked source archive")
  return destination


def locked_repository(source_tree, source_lock, identifier):
  record = next(
    (item for item in source_lock["repositories"]
     if item["id"] == identifier and item["active"] and item["buildInput"]),
    None,
  )
  if record is None:
    fail(f"source lock has no active {identifier} package input")
  checkout = safe_destination(source_tree, record["checkoutPath"],
                              f"{identifier} checkout")
  if not checkout.is_dir() or checkout.is_symlink():
    fail(f"locked {identifier} checkout is missing or aliased")
  return checkout


def build_upstream_deb(build_output, source_tree, source_lock, product_version, epoch):
  ensure_command("make")
  server_candidates = sorted(
    Path(build_output).glob("linux_64/*/documentserver"),
    key=lambda item: item.as_posix(),
  )
  if len(server_candidates) != 1:
    fail("locked build must contain exactly one linux_64 branding/documentserver payload")
  build_tools_output = source_tree / "sources" / "build_tools" / "out" \
    / "linux_64" / "onlyoffice" / "documentserver"
  if build_tools_output.exists() or build_tools_output.is_symlink():
    fail("source snapshot unexpectedly contains staged DocumentServer output")
  copy_tree(server_candidates[0], build_tools_output)

  package_source = locked_repository(
    source_tree, source_lock, "document-server-package"
  )
  require_file(package_source / "Makefile", "locked document-server-package Makefile")
  env = os.environ.copy()
  env.update({
    "SOURCE_DATE_EPOCH": str(epoch),
    "TZ": "UTC",
    "LC_ALL": "C.UTF-8",
    "LANG": "C.UTF-8",
    "PRODUCT_VERSION": product_version,
    "BUILD_NUMBER": "0",
  })
  year = iso_time(epoch)[:4]
  run(
    ["make", "-j1", "deb", "COMPANY_NAME=ONLYOFFICE",
     "PRODUCT_NAME=DocumentServer", f"PRODUCT_VERSION={product_version}",
     "BUILD_NUMBER=0", f"M4_CURRENT_YEAR={year}"],
    "locked upstream DEB build",
    env=env,
    cwd=package_source,
  )
  candidates = sorted(
    (path for path in (package_source / "deb").glob("*.deb")
     if not path.name.endswith(".ddeb")),
    key=lambda path: path.name,
  )
  if len(candidates) != 1:
    fail("locked document-server-package must produce exactly one DEB")
  return candidates[0]


def brand_upstream_deb(upstream_deb, product_version, release_id,
                       source_lock_digest, work, output, epoch):
  ensure_command("dpkg-deb")
  debroot = Path(work) / "debroot"
  debroot.mkdir(parents=True, exist_ok=True)
  run(["dpkg-deb", "--raw-extract", str(upstream_deb), str(debroot)],
      "extract locked upstream DEB")
  require_file(
    debroot / "var" / "www" / "onlyoffice" / "documentserver"
    / "server" / "DocService" / "docservice",
    "upstream DEB DocService",
  )
  config_directory = debroot / "etc" / "onlyoffice" / "documentserver"
  if not config_directory.is_dir() or not any(config_directory.glob("*.json")):
    fail("upstream DEB has no DocumentServer configuration")
  require_file(
    debroot / "usr" / "lib" / "systemd" / "system" / "ds-docservice.service",
    "upstream DEB DocService unit",
  )
  control_directory = debroot / "DEBIAN"
  for maintainer_script in ("postinst", "prerm"):
    require_file(
      control_directory / maintainer_script,
      f"upstream DEB {maintainer_script} script",
    )
  control_path = require_file(control_directory / "control", "upstream DEB control")
  control_lines = control_path.read_text(encoding="utf-8").splitlines()
  if not any(line.startswith("Depends:") for line in control_lines):
    fail("upstream DEB does not declare runtime dependencies")
  branded = []
  inserted_compatibility = False
  for line in control_lines:
    if line.startswith("Package:"):
      branded.append("Package: jetonlyoffice")
    elif line.startswith("Maintainer:"):
      branded.append("Maintainer: JetOnlyOffice build team")
    elif line.startswith("Description:"):
      if not inserted_compatibility:
        branded += [
          "Provides: onlyoffice-documentserver",
          "Conflicts: onlyoffice-documentserver",
          "Replaces: onlyoffice-documentserver",
        ]
        inserted_compatibility = True
      branded.append("Description: JetOnlyOffice DocumentServer")
    else:
      branded.append(line)
  if not inserted_compatibility:
    fail("upstream DEB control has no Description field")
  write_bytes(control_path, ("\n".join(branded) + "\n").encode("utf-8"))
  release_metadata = {
    "product": "JetOnlyOffice",
    "productVersion": product_version,
    "releaseId": release_id,
    "sourceLockSha256": source_lock_digest,
    "jwt": {"enabled": True, "secretSource": "JWT_SECRET"},
  }
  write_bytes(debroot / "etc" / "jetonlyoffice" / "release.json",
              canonical_bytes(release_metadata))
  entrypoint_source = Path(__file__).resolve().with_name("jwt-entrypoint.sh")
  require_file(entrypoint_source, "JWT entrypoint source")
  target = debroot / "usr" / "local" / "bin" / "jetonlyoffice-entrypoint"
  target.parent.mkdir(parents=True, exist_ok=True)
  shutil.copyfile(entrypoint_source, target)
  target.chmod(0o755)
  normalize_tree(debroot, epoch)
  env = os.environ.copy()
  env["SOURCE_DATE_EPOCH"] = str(epoch)
  Path(output).parent.mkdir(parents=True, exist_ok=True)
  run(["dpkg-deb", "--build", "--root-owner-group", "--uniform-compression",
       "-Zxz", "-z9", "--threads-max=1",
       str(debroot), str(output)],
      "deterministic DEB", env)


def install_docker_runtime(rootfs, source_tree, source_lock):
  docker_source = locked_repository(
    source_tree, source_lock, "docker-documentserver"
  )
  runtime_source = require_file(
    docker_source / "run-document-server.sh", "locked Community runtime entrypoint"
  )
  runtime_target = rootfs / "app" / "ds" / "run-document-server.sh"
  runtime_target.parent.mkdir(parents=True, exist_ok=True)
  shutil.copyfile(runtime_source, runtime_target)
  runtime_target.chmod(0o755)

  supervisor_source = require_file(
    docker_source / "config" / "supervisor" / "supervisor",
    "locked supervisor init script",
  )
  supervisor_target = rootfs / "etc" / "init.d" / "supervisor"
  supervisor_target.parent.mkdir(parents=True, exist_ok=True)
  shutil.copyfile(supervisor_source, supervisor_target)
  supervisor_target.chmod(0o755)
  supervisor_configs = sorted(
    (docker_source / "config" / "supervisor" / "ds").glob("*.conf"),
    key=lambda path: path.name,
  )
  if not supervisor_configs:
    fail("locked Docker runtime has no supervisor service configuration")
  destination = rootfs / "etc" / "supervisor" / "conf.d"
  destination.mkdir(parents=True, exist_ok=True)
  for source in supervisor_configs:
    payload = require_file(source, "locked supervisor configuration").read_bytes()
    write_bytes(destination / source.name, payload.replace(b"COMPANY_NAME", b"onlyoffice"))
  admin_panel = destination / "ds-adminpanel.conf"
  admin_panel.unlink(missing_ok=True)
  group_config = destination / "ds.conf"
  if group_config.is_file():
    group_config.write_bytes(group_config.read_bytes().replace(b",adminpanel", b""))


def package_rootfs(deb, runtime_rootfs, cache, toolchain, source_tree, source_lock,
                   work, epoch):
  rootfs = Path(work) / "rootfs"
  rootfs.mkdir(parents=True, exist_ok=True)
  require_file(runtime_rootfs, "locked runtime rootfs")
  ensure_command("tar")
  run(["tar", "--no-same-owner", "--no-same-permissions",
       "--exclude=.dockerenv", "--exclude=dev", "--exclude=proc", "--exclude=sys",
       "-xf", str(runtime_rootfs), "-C", str(rootfs)],
      "extract locked runtime rootfs")
  for directory in ("dev", "proc", "sys"):
    (rootfs / directory).mkdir(exist_ok=True)

  for tool in toolchain.get("tools", []):
    if "runtime" not in tool.get("consumers", []):
      continue
    materialization = tool.get("materialization", {})
    materialization_type = materialization.get("type")
    source = Path(cache) / "toolchain" / tool["id"] / tool["sha256"]
    if not source.is_file() or source.is_symlink():
      fail(f"runtime toolchain input is missing: {tool['id']}")
    if materialization_type == "file":
      destination = safe_destination(rootfs, materialization.get("destination", ""),
                                     f"runtime materialization {tool['id']}")
      destination.parent.mkdir(parents=True, exist_ok=True)
      shutil.copyfile(source, destination)
      destination.chmod(int(materialization.get("mode", "0644"), 8))
    elif materialization_type == "deb":
      ensure_command("dpkg-deb")
      run(["dpkg-deb", "--extract", str(source), str(rootfs)],
          f"extract runtime package {tool['id']}")
    elif materialization_type in {"tar", "tar-gzip", "tar-xz"}:
      destination = safe_destination(rootfs, materialization.get("destination", ""),
                                     f"runtime materialization {tool['id']}")
      destination.mkdir(parents=True, exist_ok=True)
      command = ["tar", "--no-same-owner", "--no-same-permissions"]
      strip = materialization.get("stripComponents")
      if strip is not None:
        command.append(f"--strip-components={strip}")
      command += ["-xf", str(source), "-C", str(destination)]
      run(command, f"extract runtime archive {tool['id']}")
    else:
      fail(f"unsupported runtime materialization type: {materialization_type}")

  ensure_command("dpkg-deb")
  run(["dpkg-deb", "--extract", str(require_file(deb, "JetOnlyOffice DEB")),
       str(rootfs)], "install JetOnlyOffice DEB into rootfs")
  install_docker_runtime(rootfs, source_tree, source_lock)
  normalize_tree(rootfs, epoch)
  return rootfs


def build_oci(rootfs, runtime_image, source_lock, product_version, work, output, epoch):
  oci = Path(work) / "oci"
  blobs = oci / "blobs" / "sha256"
  blobs.mkdir(parents=True, exist_ok=True)
  layer = Path(work) / "oci-layer.tar"
  tar_directory(rootfs, layer, epoch)
  layer_digest = sha256_file(layer)
  shutil.copyfile(layer, blobs / layer_digest)
  runtime = next((item for item in runtime_image.get("images", [])
                  if item.get("role") == "runtime"), None)
  if runtime is None:
    fail("image lock has no runtime image")
  config = {
    "architecture": "amd64", "os": "linux",
    "config": {
      "Entrypoint": ["/usr/local/bin/jetonlyoffice-entrypoint"],
      "Env": [
        "BASE_VERSION=24.04",
        "COMPANY_NAME=onlyoffice",
        "DEBIAN_FRONTEND=noninteractive",
        "DS_DOCKER_INSTALLATION=true",
        "DS_PLUGIN_INSTALLATION=false",
        "JWT_ENABLED=true",
        "LANG=en_US.UTF-8",
        "LANGUAGE=en_US:en",
        "LC_ALL=en_US.UTF-8",
        "PG_VERSION=16",
        "PRODUCT_EDITION=",
        "PRODUCT_NAME=documentserver",
      ],
      "Labels": {
        "org.opencontainers.image.title": "JetOnlyOffice",
        "org.opencontainers.image.version": product_version,
        "org.opencontainers.image.base.name": runtime["reference"],
        "org.opencontainers.image.base.digest": runtime["digest"],
      },
    },
    "created": iso_time(epoch),
    "rootfs": {"type": "layers", "diff_ids": ["sha256:" + layer_digest]},
    "history": [{"created": iso_time(epoch), "created_by": "JetOnlyOffice deterministic package driver"}],
  }
  config_bytes = canonical_bytes(config)
  config_digest = sha256_bytes(config_bytes)
  write_bytes(blobs / config_digest, config_bytes)
  manifest = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
               "digest": "sha256:" + config_digest, "size": len(config_bytes)},
    "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                 "digest": "sha256:" + layer_digest, "size": layer.stat().st_size}],
    "annotations": {"org.opencontainers.image.ref.name": "jetonlyoffice:" + product_version},
  }
  manifest_bytes = canonical_bytes(manifest)
  manifest_digest = sha256_bytes(manifest_bytes)
  write_bytes(blobs / manifest_digest, manifest_bytes)
  write_bytes(oci / "oci-layout", b'{"imageLayoutVersion":"1.0.0"}\n')
  write_bytes(oci / "index.json", canonical_bytes({
    "schemaVersion": 2,
    "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:" + manifest_digest,
                    "size": len(manifest_bytes),
                    "annotations": {"org.opencontainers.image.ref.name": "latest"}}],
  }))
  normalize_tree(oci, epoch)
  tar_directory(oci, output, epoch)
  return "sha256:" + manifest_digest


def source_archive(build_output, output):
  source = Path(build_output) / "source-archive.tar.zst"
  require_file(source, "locked source archive")
  Path(output).parent.mkdir(parents=True, exist_ok=True)
  shutil.copyfile(source, output)


def iso_time(epoch):
  from datetime import datetime, timezone
  return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def artifact_record(identifier, artifact_type, path, artifact_root, subjects,
                    media_type, oci_digest=None):
  path = Path(path).resolve()
  artifact_root = Path(artifact_root).resolve()
  try:
    relative = path.relative_to(artifact_root).as_posix()
  except ValueError as error:
    fail(f"artifact path escapes output root: {path}")
  record = {"id": identifier, "type": artifact_type,
            "path": relative, "size": path.stat().st_size,
            "sha256": sha256_file(path), "mediaType": media_type,
            "subjects": sorted(set(subjects))}
  if oci_digest is not None:
    record["ociDigest"] = oci_digest
  return record


def spdx_identifier(prefix, value):
  sanitized = "".join(character if character.isalnum() or character in ".-" else "-"
                      for character in value)
  return prefix + sanitized


def read_uint16(content, offset, context):
  if offset < 0 or offset + 2 > len(content):
    fail(f"{context}: truncated font metadata")
  return struct.unpack_from(">H", content, offset)[0]


def read_uint32(content, offset, context):
  if offset < 0 or offset + 4 > len(content):
    fail(f"{context}: truncated font metadata")
  return struct.unpack_from(">I", content, offset)[0]


def font_name_texts(content, name_id, context):
  if content[:4] == b"ttcf":
    font_count = read_uint32(content, 8, context)
    if font_count < 1 or font_count > 1024:
      fail(f"{context}: invalid TrueType collection")
    offset_end = 12 + (font_count * 4)
    if offset_end > len(content):
      fail(f"{context}: truncated TrueType collection")
    font_offsets = [
      read_uint32(content, 12 + (index * 4), context)
      for index in range(font_count)
    ]
  elif content[:4] in {b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1"}:
    font_offsets = [0]
  else:
    fail(f"{context}: unsupported font payload")
  texts = set()
  for font_offset in font_offsets:
    table_count = read_uint16(content, font_offset + 4, context)
    directory_end = font_offset + 12 + (table_count * 16)
    if table_count < 1 or table_count > 4096 or directory_end > len(content):
      fail(f"{context}: invalid font table directory")
    name_offset = None
    name_length = None
    for table_index in range(table_count):
      record_offset = font_offset + 12 + (table_index * 16)
      if content[record_offset:record_offset + 4] != b"name":
        continue
      name_offset = read_uint32(content, record_offset + 8, context)
      name_length = read_uint32(content, record_offset + 12, context)
      break
    if name_offset is None or name_offset + name_length > len(content):
      fail(f"{context}: font has no valid name table")
    record_count = read_uint16(content, name_offset + 2, context)
    string_offset = read_uint16(content, name_offset + 4, context)
    records_end = name_offset + 6 + (record_count * 12)
    storage_offset = name_offset + string_offset
    if records_end > len(content) or storage_offset > name_offset + name_length:
      fail(f"{context}: invalid font name table")
    for record_index in range(record_count):
      record_offset = name_offset + 6 + (record_index * 12)
      platform_id, _, _, record_name_id, length, offset = struct.unpack_from(
        ">6H", content, record_offset
      )
      if record_name_id != name_id or platform_id not in {0, 1, 3}:
        continue
      text_start = storage_offset + offset
      text_end = text_start + length
      if text_end > name_offset + name_length or text_end > len(content):
        fail(f"{context}: invalid font name string")
      encoding = "utf-16-be" if platform_id in {0, 3} else "mac_roman"
      try:
        text = content[text_start:text_end].decode(encoding)
      except UnicodeDecodeError as error:
        fail(f"{context}: invalid font name encoding: {error}")
      if text:
        texts.add(text)
  if not texts:
    fail(f"{context}: font license name record is missing")
  return sorted(texts)


def component_evidence_bytes(checkout, repository, evidence):
  context = f"{repository['id']}:{evidence['path']}:{evidence['locator']}"
  payload = require_file(
    safe_destination(checkout, evidence["path"], context), context
  ).read_bytes()
  lfs_object = next(
    (
      item for item in repository.get("lfsObjects", [])
      if evidence["path"] in item["paths"]
    ),
    None,
  )
  expected_payload_digest = (
    lfs_object["oid"] if lfs_object is not None else evidence["sha256"]
  )
  if hashlib.sha256(payload).hexdigest() != expected_payload_digest:
    fail(f"{context}: payload digest does not match source lock")
  if lfs_object is not None and len(payload) != lfs_object["size"]:
    fail(f"{context}: payload size does not match source lock")
  if evidence["type"] == "git-blob":
    material = require_file(
      safe_destination(checkout, evidence["locator"], context), context
    ).read_bytes()
  elif evidence["type"] == "font-name":
    name_id = int(evidence["locator"].split(":", 1)[1])
    matching = [
      text.encode("utf-8")
      for text in font_name_texts(payload, name_id, context)
      if hashlib.sha256(text.encode("utf-8")).hexdigest()
      == evidence["evidenceSha256"]
    ]
    if len(matching) != 1:
      fail(f"{context}: license evidence digest does not match source lock")
    material = matching[0]
  else:
    try:
      with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
        matching = [
          info for info in archive.infolist()
          if info.filename == evidence["locator"] and not info.is_dir()
        ]
        if len(matching) != 1 or matching[0].flag_bits & 1:
          fail(f"{context}: archive license member is invalid")
        if matching[0].file_size > 4 * 1024 * 1024:
          fail(f"{context}: archive license member is too large")
        material = archive.read(matching[0])
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as error:
      fail(f"{context}: invalid ZIP license evidence: {error}")
  if hashlib.sha256(material).hexdigest() != evidence["evidenceSha256"]:
    fail(f"{context}: license evidence digest does not match source lock")
  return material


def license_references(expression):
  return sorted(set(re.findall(r"LicenseRef-[A-Za-z0-9.-]+", expression)))


def make_license_artifacts(source_tree, source_lock, toolchain, source_lock_digest,
                           work, archive_output, notice_output, epoch):
  license_root = Path(work) / "license-bundle"
  license_root.mkdir(parents=True, exist_ok=True)
  repository_records = []
  notice_lines = [
    "JetOnlyOffice third-party notices",
    "",
    "This derived product includes software from ONLYOFFICE and other projects.",
    "JetOnlyOffice is not an official ONLYOFFICE distribution.",
    f"Source lock SHA-256: {source_lock_digest}",
    "",
    "Source repositories:",
  ]
  extracted_materials = {}
  for repository in sorted(
    source_lock["repositories"],
    key=lambda item: item["id"],
  ):
    checkout = locked_repository(source_tree, source_lock, repository["id"])
    if repository["license"].get("scope") == "component":
      component_records = []
      for component in repository["license"]["components"]:
        evidence_records = []
        for evidence in component["license"]["evidence"]:
          material = component_evidence_bytes(checkout, repository, evidence)
          destination = license_root / "repositories" / repository["id"] \
            / "components" / component["id"] / "evidence" \
            / (evidence["evidenceSha256"] + ".license")
          destination.parent.mkdir(parents=True, exist_ok=True)
          if destination.exists():
            if destination.read_bytes() != material:
              fail(f"{repository['id']} component license evidence conflicts")
          else:
            write_bytes(destination, material)
            destination.chmod(0o644)
          evidence_records.append({
            **dict(evidence),
            "licensePath": destination.relative_to(license_root).as_posix(),
          })
          for identifier in license_references(component["license"]["spdx"]):
            try:
              text = material.decode("utf-8")
            except UnicodeDecodeError as error:
              fail(f"{identifier} license evidence is not UTF-8: {error}")
            extracted_materials.setdefault(identifier, set()).add(text)
        component_records.append({
          "id": component["id"],
          "payloadPaths": list(component["payloadPaths"]),
          "license": {
            "spdx": component["license"]["spdx"],
            "evidence": evidence_records,
          },
        })
        notice_lines.append(
          f"- {repository['id']}/{component['id']} | "
          f"{component['license']['spdx']} | {repository['origin']} | "
          f"{repository['commit']}"
        )
      repository_records.append({
        "id": repository["id"],
        "commit": repository["commit"],
        "origin": repository["origin"],
        "scope": "component",
        "payloadPatterns": list(repository["license"]["payloadPatterns"]),
        "components": component_records,
      })
    else:
      license_source = safe_destination(
        checkout, repository["license"]["path"], f"{repository['id']} license"
      )
      require_file(license_source, f"{repository['id']} license")
      actual_digest = sha256_file(license_source)
      if actual_digest != repository["license"]["sha256"]:
        fail(f"{repository['id']} license digest does not match source lock")
      destination = license_root / "repositories" / repository["id"] \
        / Path(repository["license"]["path"]).name
      destination.parent.mkdir(parents=True, exist_ok=True)
      shutil.copyfile(license_source, destination)
      destination.chmod(0o644)
      repository_records.append({
        "id": repository["id"],
        "commit": repository["commit"],
        "origin": repository["origin"],
        "spdx": repository["license"]["spdx"],
        "licensePath": destination.relative_to(license_root).as_posix(),
        "licenseSha256": actual_digest,
      })
      notice_lines.append(
        f"- {repository['id']} | {repository['license']['spdx']} | "
        f"{repository['origin']} | {repository['commit']}"
      )
  tool_records = []
  notice_lines += ["", "Locked toolchain and runtime inputs:"]
  for tool in sorted(toolchain.get("tools", []), key=lambda item: item["id"]):
    tool_records.append({
      "id": tool["id"],
      "name": tool["name"],
      "version": tool["version"],
      "license": tool["license"],
      "sourceUrl": tool["sourceUrl"],
      **({"sha256": tool["sha256"]} if "sha256" in tool else {}),
    })
    notice_lines.append(
      f"- {tool['id']} | {tool['license']} | {tool['sourceUrl']} | {tool['version']}"
    )
  manifest = {
    "schemaVersion": 1,
    "sourceLockSha256": source_lock_digest,
    "repositories": repository_records,
    "tools": tool_records,
  }
  write_bytes(license_root / "manifest.json", canonical_bytes(manifest))
  normalize_tree(license_root, epoch)
  tar_directory(license_root, archive_output, epoch, compressed=True)
  write_bytes(notice_output, ("\n".join(notice_lines) + "\n").encode("utf-8"))
  return {
    identifier: "\n\n".join(sorted(materials))
    for identifier, materials in sorted(extracted_materials.items())
  }


def source_license_units(source_lock):
  for repository in source_lock["repositories"]:
    if repository["license"].get("scope") == "component":
      for component in repository["license"]["components"]:
        evidence_references = [
          f"{item['type']}:{item['path']}:{item['locator']}:sha256:{item['evidenceSha256']}"
          for item in component["license"]["evidence"]
        ]
        yield {
          "id": repository["id"] + "-" + component["id"],
          "bomRef": "repo:" + repository["id"] + ":" + component["id"],
          "name": repository["id"] + "/" + component["id"],
          "version": repository["commit"],
          "origin": repository["origin"],
          "spdx": component["license"]["spdx"],
          "repository": repository["id"],
          "payloadPaths": list(component["payloadPaths"]),
          "evidenceReferences": evidence_references,
        }
    else:
      yield {
        "id": repository["id"],
        "bomRef": "repo:" + repository["id"],
        "name": repository["id"],
        "version": repository["commit"],
        "origin": repository["origin"],
        "spdx": repository["license"]["spdx"],
        "repository": repository["id"],
        "payloadPaths": [],
        "evidenceReferences": [
          f"git-blob:{repository['license']['path']}:sha256:{repository['license']['sha256']}"
        ],
      }


def make_sbom(kind, source_lock, toolchain, carriers, source_lock_digest, output,
              extracted_licenses=None):
  extracted_licenses = dict(extracted_licenses or {})
  source_units = list(source_license_units(source_lock))
  required_references = sorted({
    identifier
    for unit in source_units
    for identifier in license_references(unit["spdx"])
  }.union(
    identifier
    for tool in toolchain.get("tools", [])
    for identifier in license_references(tool["license"])
  ))
  missing_references = sorted(set(required_references) - set(extracted_licenses))
  if missing_references:
    fail("missing extracted license text: " + ", ".join(missing_references))
  if kind == "spdx":
    packages = []
    for unit in source_units:
      package = {"SPDXID": spdx_identifier("SPDXRef-", unit["id"]),
                       "name": unit["name"], "versionInfo": unit["version"],
                       "downloadLocation": unit["origin"],
                       "licenseConcluded": unit["spdx"],
                       "licenseDeclared": unit["spdx"],
                       "filesAnalyzed": False,
                       "copyrightText": "Copyright holders identified in source"}
      if unit["payloadPaths"]:
        package["comment"] = (
          "Payloads: " + ", ".join(unit["payloadPaths"])
          + "; License evidence: " + ", ".join(unit["evidenceReferences"])
        )
      packages.append(package)
    for tool in toolchain.get("tools", []):
      packages.append({"SPDXID": spdx_identifier("SPDXRef-tool-", tool["id"]),
                       "name": tool["name"], "versionInfo": tool["version"],
                       "downloadLocation": tool["sourceUrl"],
                       "licenseConcluded": tool["license"],
                       "licenseDeclared": tool["license"],
                       "filesAnalyzed": False,
                       "copyrightText": "Copyright holders identified in locked input"})
    value = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
             "SPDXID": "SPDXRef-DOCUMENT", "name": "JetOnlyOffice",
             "documentNamespace": "https://jetonlyoffice.dev/spdx/" + source_lock_digest,
             "creationInfo": {"created": iso_time(source_lock["sourceDateEpoch"]),
                               "creators": ["Tool: JetOnlyOffice package-driver"]},
             "packages": sorted(packages, key=lambda item: item["SPDXID"]),
             "documentDescribes": [item["SPDXID"] for item in
                                   sorted(packages, key=lambda item: item["SPDXID"])]}
    if extracted_licenses:
      value["hasExtractedLicensingInfos"] = [
        {"licenseId": identifier, "extractedText": extracted_licenses[identifier]}
        for identifier in sorted(extracted_licenses)
      ]
  else:
    components = []
    for unit in source_units:
      component = {"type": "library", "bom-ref": unit["bomRef"],
                   "name": unit["name"], "version": unit["version"],
                   "externalReferences": [{"type": "vcs", "url": unit["origin"]}],
                   "licenses": [{"expression": unit["spdx"]}]}
      if unit["payloadPaths"]:
        component["properties"] = [
          {"name": "jetonlyoffice.repository", "value": unit["repository"]},
          {"name": "jetonlyoffice.payloadPaths", "value": ",".join(unit["payloadPaths"])},
          *[
            {"name": "jetonlyoffice.licenseEvidence", "value": reference}
            for reference in unit["evidenceReferences"]
          ],
        ]
      components.append(component)
    for tool in toolchain.get("tools", []):
      components.append({"type": "library", "bom-ref": "tool:" + tool["id"],
                         "name": tool["name"], "version": tool["version"],
                         "externalReferences": [{"type": "distribution", "url": tool["sourceUrl"]}],
                         "licenses": [{"expression": tool["license"]}]})
    value = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
             "metadata": {"timestamp": iso_time(source_lock["sourceDateEpoch"]),
                          "component": {"type": "application", "name": "JetOnlyOffice",
                                        "version": source_lock["productVersion"]},
                          "properties": [{"name": "jetonlyoffice.sourceLockSha256", "value": source_lock_digest},
                                         {"name": "jetonlyoffice.artifacts", "value": ",".join(carriers)}]},
             "components": sorted(components, key=lambda item: item["bom-ref"])}
  write_bytes(output, canonical_bytes(value))


def make_provenance(source_lock, build_manifest, carriers, artifact_records, output):
  subjects = [{"name": item["id"], "digest": {"sha256": item["sha256"]}}
              for item in artifact_records if item["id"] in carriers]
  value = {"_type": "https://in-toto.io/Statement/v1", "subject": subjects,
           "predicateType": "https://slsa.dev/provenance/v1",
           "predicate": {
             "buildDefinition": {
               "buildType": "https://jetonlyoffice.dev/build/offline-v1",
               "externalParameters": {
                 "sourceLockSha256": build_manifest["sourceLockSha256"],
                 "toolchainLockSha256": build_manifest["toolchainLockSha256"],
                 "imageLockSha256": build_manifest["imageLockSha256"],
                 "sourceDateEpoch": build_manifest["sourceDateEpoch"],
                 "network": "none",
               },
               "resolvedDependencies": [{"uri": repo["origin"], "digest": {"gitCommit": repo["commit"]}}
                                        for repo in source_lock["repositories"]],
             },
             "runDetails": {"builder": {"id": "jetonlyoffice://builder@" + build_manifest["builderImageDigest"]},
                            "metadata": {"invocationId": build_manifest["buildId"]}},
           }}
  write_bytes(output, canonical_bytes(value))


def package(args):
  build_manifest = load_json(args.build_manifest, "build manifest")
  source_lock = load_json(args.source_lock, "source lock")
  toolchain = load_json(args.toolchain_lock, "toolchain lock")
  image_lock = load_json(args.image_lock, "image lock")
  source_lock_digest = sha256_bytes(canonical_bytes(source_lock).rstrip(b"\n"))
  if source_lock_digest != build_manifest["sourceLockSha256"]:
    fail("source lock digest does not match build manifest")
  if build_manifest["toolchainLockSha256"] != sha256_bytes(canonical_bytes(toolchain).rstrip(b"\n")):
    fail("toolchain lock digest does not match build manifest")
  if build_manifest["imageLockSha256"] != sha256_bytes(canonical_bytes(image_lock).rstrip(b"\n")):
    fail("image lock digest does not match build manifest")
  epoch = int(build_manifest["sourceDateEpoch"])
  product_version = source_lock["productVersion"]
  release_id = "jetonlyoffice-v" + product_version
  output_root = Path(args.output).resolve()
  work = Path(args.work).resolve()
  work.mkdir(parents=True, exist_ok=True)
  build_output = output_root / "build-output"
  cache = Path(args.cache).resolve()
  with tempfile.TemporaryDirectory(dir=work, prefix="package-root-") as temporary:
    source_tree = extract_source_snapshot(build_output, temporary)
    upstream_deb = build_upstream_deb(
      build_output, source_tree, source_lock, product_version, epoch,
    )
    deb = output_root / "packages" / "jetonlyoffice.deb"
    rootfs_archive = output_root / "packages" / "rootfs.tar.zst"
    oci_archive = output_root / "images" / "jetonlyoffice.oci.tar"
    brand_upstream_deb(
      upstream_deb, product_version, release_id, source_lock_digest,
      temporary, deb, epoch,
    )
    rootfs = package_rootfs(
      deb, args.runtime_rootfs, cache, toolchain, source_tree, source_lock,
      temporary, epoch,
    )
    tar_directory(rootfs, rootfs_archive, epoch, compressed=True)
    oci_digest = build_oci(rootfs, image_lock, source_lock, product_version, temporary, oci_archive, epoch)
    source = output_root / "sources" / "jetonlyoffice-source.tar.zst"
    source_archive(build_output, source)
    carrier_ids = ["jetonlyoffice-deb", "jetonlyoffice-oci", "jetonlyoffice-rootfs"]
    records = [
      artifact_record("jetonlyoffice-deb", "deb", deb, output_root, [], "application/vnd.debian.binary-package"),
      artifact_record("jetonlyoffice-oci", "oci", oci_archive, output_root, [], "application/vnd.oci.image.layout.v1+tar", oci_digest),
      artifact_record("jetonlyoffice-rootfs", "rootfs", rootfs_archive, output_root, [], "application/zstd"),
      artifact_record("jetonlyoffice-source", "source", source, output_root, carrier_ids, "application/zstd"),
    ]
    license_archive = output_root / "licenses" / "jetonlyoffice-licenses.tar.zst"
    notice = output_root / "licenses" / "NOTICE.txt"
    extracted_licenses = make_license_artifacts(
      source_tree, source_lock, toolchain, source_lock_digest, temporary,
      license_archive, notice, epoch,
    )
    records += [
      artifact_record(
        "jetonlyoffice-licenses", "licenses", license_archive, output_root,
        carrier_ids, "application/zstd",
      ),
      artifact_record(
        "jetonlyoffice-notice", "notice", notice, output_root,
        carrier_ids, "text/plain",
      ),
    ]
    spdx = output_root / "sbom" / "jetonlyoffice.spdx.json"
    cdx = output_root / "sbom" / "jetonlyoffice.cdx.json"
    make_sbom(
      "spdx", source_lock, toolchain, carrier_ids, source_lock_digest, spdx,
      extracted_licenses,
    )
    make_sbom(
      "cyclonedx", source_lock, toolchain, carrier_ids, source_lock_digest, cdx,
      extracted_licenses,
    )
    records += [artifact_record("jetonlyoffice-spdx", "spdx", spdx, output_root, carrier_ids, "application/spdx+json"),
                artifact_record("jetonlyoffice-cyclonedx", "cyclonedx", cdx, output_root, carrier_ids, "application/vnd.cyclonedx+json")]
    provenance = output_root / "provenance" / "jetonlyoffice.intoto.jsonl"
    make_provenance(source_lock, build_manifest, carrier_ids, records, provenance)
    records.append(artifact_record("jetonlyoffice-provenance", "provenance", provenance, output_root, carrier_ids, "application/vnd.in-toto+json"))
    records.sort(key=lambda item: item["id"])
    checksums = output_root / "checksums" / "SHA256SUMS"
    lines = [f"{item['sha256']}  {item['path']}" for item in records]
    write_bytes(checksums, ("\n".join(lines) + "\n").encode("ascii"))
    records.append(artifact_record("jetonlyoffice-checksums", "checksums", checksums,
                                   output_root, [item["id"] for item in records], "text/plain"))
    records.sort(key=lambda item: item["id"])
    manifest = {"schemaVersion": 1, "manifestType": "artifact", "releaseId": release_id,
                "productVersion": product_version, "platform": "linux-amd64",
                "sourceLockSha256": source_lock_digest,
                "buildManifestSha256": sha256_bytes(canonical_bytes(build_manifest).rstrip(b"\n")),
                "artifacts": records}
    manifest_path = safe_destination(output_root, args.output_manifest,
                                     "artifact manifest output")
    write_bytes(manifest_path, canonical_bytes(manifest))


def main(argv=None):
  parser = argparse.ArgumentParser()
  parser.add_argument("--build-manifest", required=True)
  parser.add_argument("--source-lock", required=True)
  parser.add_argument("--toolchain-lock", required=True)
  parser.add_argument("--image-lock", required=True)
  parser.add_argument("--runtime-rootfs", required=True)
  parser.add_argument("--cache", required=True)
  parser.add_argument("--work", required=True)
  parser.add_argument("--output", required=True)
  parser.add_argument("--output-manifest", default="artifact-manifest.json")
  args = parser.parse_args(argv)
  try:
    package(args)
  except PackageError as error:
    print(f"package driver: {error}", file=sys.stderr)
    return 4
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
