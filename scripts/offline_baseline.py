#!/usr/bin/env python3

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlparse
from urllib.request import urlopen

from contracts.contract_tool import ContractError, load_json, validate_contract
from contracts.contract_tool import canonical_json_bytes, canonical_sha256
from source_resolver import ResolutionError, verify_materialized
from qa.qa_tool import aggregate_release_evidence


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class BaselineError(ValueError):
  def __init__(self, message, exit_code):
    super().__init__(message)
    self.exit_code = exit_code


def require_file(path, description, exit_code=3):
  path = Path(path)
  if not path.is_file():
    raise BaselineError(f"{description} is missing: {path}", exit_code)
  return path


def load_contract(path, contract, description, schema_dir):
  path = require_file(path, description)
  value = load_json(path)
  validate_contract(value, contract, schema_dir)
  return value


def preflight_bootstrap(args):
  load_contract(args.source_lock, "source-lock", "locked source input", args.schema_dir)
  toolchain = load_contract(
    args.toolchain_lock,
    "toolchain-lock",
    "locked toolchain input",
    args.schema_dir,
  )
  locked_zstd_tool(toolchain)
  load_contract(args.image_lock, "image-lock", "locked image input", args.schema_dir)


def sha256_file(path):
  digest = hashlib.sha256()
  with Path(path).open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
      digest.update(chunk)
  return digest.hexdigest()


def path_is_alias(path):
  path = Path(path)
  if path.is_symlink():
    return True
  is_junction = getattr(path, "is_junction", None)
  if is_junction and is_junction():
    return True
  if os.name == "nt" and path.exists():
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
  return False


def resolve_unaliased_root(path, description, exit_code):
  absolute = Path(os.path.abspath(path))
  current = absolute
  while True:
    if path_is_alias(current):
      raise BaselineError(
        f"{description} must not be an alias: {current}", exit_code
      )
    parent = current.parent
    if parent == current:
      break
    current = parent
  return absolute.resolve()


def verify_unaliased_parents(path, root, description, exit_code):
  root = Path(root).resolve()
  path = Path(path)
  if not path.is_absolute():
    path = Path(os.path.abspath(path))
  try:
    relative = path.relative_to(root)
  except ValueError as error:
    raise BaselineError(f"{description} path escapes root: {path}", exit_code) from error
  if ".." in relative.parts:
    raise BaselineError(f"{description} path escapes root: {path}", exit_code)
  current = root
  for part in relative.parts[:-1]:
    current /= part
    if path_is_alias(current):
      raise BaselineError(
        f"{description} parent must not be a symbolic link or junction: {current}",
        exit_code,
      )
    if current.exists() and not current.is_dir():
      raise BaselineError(f"{description} parent is not a directory: {current}", exit_code)
  return path


def cache_toolchain_input(tool, path, cache_root):
  path = Path(path)
  cache_root = resolve_unaliased_root(
    cache_root, "locked toolchain cache root", 3
  )
  verify_unaliased_parents(path, cache_root, "locked toolchain cache", 3)
  if path_is_alias(path):
    raise BaselineError(
      f"locked toolchain cache must not be a symbolic link or junction: {path}", 3
    )
  if path.exists():
    if not path.is_file():
      raise BaselineError(f"locked toolchain cache is not a file: {path}", 3)
    return

  path.parent.mkdir(parents=True, exist_ok=True)
  verify_unaliased_parents(path, cache_root, "locked toolchain cache", 3)
  temporary = None
  try:
    with tempfile.NamedTemporaryFile(
      dir=path.parent,
      prefix="." + path.name + ".",
      suffix=".part",
      delete=False,
    ) as stream:
      temporary = Path(stream.name)
      digest = hashlib.sha256()
      size = 0
      with urlopen(tool["sourceUrl"], timeout=60) as response:
        final_url = response.geturl()
        parsed_url = urlparse(final_url)
        if parsed_url.scheme != "https":
          raise BaselineError(
            f"locked toolchain download redirected outside HTTPS for {tool['id']}", 3
          )
        if not parsed_url.netloc or parsed_url.username or parsed_url.password:
          raise BaselineError(
            f"locked toolchain download must use a credential-free HTTPS URL for {tool['id']}",
            3,
          )
        content_length = response.headers.get("Content-Length")
        if content_length is not None and int(content_length) != tool["size"]:
          raise BaselineError(
            f"locked toolchain download size header mismatch for {tool['id']}", 3
          )
        while True:
          chunk = response.read(1024 * 1024)
          if not chunk:
            break
          size += len(chunk)
          if size > tool["size"]:
            raise BaselineError(
              f"locked toolchain download exceeded declared size for {tool['id']}", 3
            )
          digest.update(chunk)
          stream.write(chunk)
    if size != tool["size"]:
      raise BaselineError(
        f"locked toolchain download size mismatch for {tool['id']}: "
        f"expected {tool['size']}, got {size}",
        3,
      )
    actual_digest = digest.hexdigest()
    if actual_digest != tool["sha256"]:
      raise BaselineError(
        f"locked toolchain download digest mismatch for {tool['id']}: "
        f"expected {tool['sha256']}, got {actual_digest}",
        3,
      )
    verify_unaliased_parents(path, cache_root, "locked toolchain cache", 3)
    try:
      os.link(temporary, path)
    except FileExistsError:
      if path_is_alias(path):
        raise BaselineError(
          f"locked toolchain cache must not be a symbolic link or junction: {path}", 3
        )
      if path.stat().st_size != tool["size"] or sha256_file(path) != tool["sha256"]:
        raise BaselineError(f"concurrent toolchain cache mismatch for {tool['id']}", 3)
    else:
      verify_unaliased_parents(path, cache_root, "locked toolchain cache", 3)
      temporary.unlink()
      temporary = None
  except BaselineError:
    raise
  except (OSError, ValueError) as error:
    raise BaselineError(
      f"locked toolchain download failed for {tool['id']}: {error}", 3
    ) from error
  finally:
    if temporary is not None:
      temporary.unlink(missing_ok=True)


def run_external(command, description, exit_code=3):
  try:
    result = subprocess.run(
      command,
      capture_output=True,
      encoding="utf-8",
      errors="replace",
      check=False,
    )
  except OSError as error:
    raise BaselineError(f"{description} cannot start: {error}", exit_code) from error
  if result.returncode != 0:
    detail = result.stderr.strip() or result.stdout.strip() or "command failed"
    raise BaselineError(f"{description} failed: {detail}", exit_code)
  return result.stdout.strip()


def pinned_image_reference(image):
  reference = image["reference"]
  last_slash = reference.rfind("/")
  last_colon = reference.rfind(":")
  repository = reference[:last_colon] if last_colon > last_slash else reference
  return repository + "@" + image["digest"]


def docker_user_args():
  """Keep bind-mounted build outputs owned by the invoking POSIX user."""
  if hasattr(os, "getuid") and hasattr(os, "getgid"):
    return ["--user", f"{os.getuid()}:{os.getgid()}"]
  return []


def verify_local_image(docker, image):
  pinned = pinned_image_reference(image)
  output = run_external(
    [docker, "image", "inspect", pinned],
    f"locked image inspect for {image['id']}",
  )
  try:
    records = json.loads(output)
  except json.JSONDecodeError as error:
    raise BaselineError(
      f"locked image inspect returned invalid JSON for {image['id']}", 3
    ) from error
  if not isinstance(records, list) or len(records) != 1:
    raise BaselineError(
      f"locked image inspect returned an unexpected record count for {image['id']}", 3
    )
  record = records[0]
  if not isinstance(record, dict):
    raise BaselineError(
      f"locked image inspect returned an unexpected image record for {image['id']}", 3
    )
  platform = str(record.get("Os", "")) + "/" + str(record.get("Architecture", ""))
  if platform != "linux/amd64":
    raise BaselineError(
      f"locked image platform mismatch for {image['id']}: expected linux/amd64, got {platform}",
      3,
    )
  if record.get("Id") != image["configDigest"]:
    raise BaselineError(
      f"locked image config digest mismatch for {image['id']}", 3
    )
  repository_digests = record.get("RepoDigests")
  if not isinstance(repository_digests, list) or not all(
    isinstance(value, str) for value in repository_digests
  ):
    raise BaselineError(
      f"locked image inspect returned an unexpected image record for {image['id']}", 3
    )
  expected_repository_digest = pinned_image_reference(image)
  if expected_repository_digest not in repository_digests:
    raise BaselineError(
      f"locked image repository digest mismatch for {image['id']}", 3
    )


@contextmanager
def export_locked_runtime_rootfs(docker, image, parent_directory):
  pinned = pinned_image_reference(image)
  container_id = run_external(
    [docker, "create", "--pull=never", "--platform", "linux/amd64", pinned],
    "locked runtime container creation",
  ).strip()
  if not container_id:
    raise BaselineError("locked runtime container creation returned no id", 3)
  try:
    with tempfile.TemporaryDirectory(
      dir=parent_directory, prefix=".runtime-rootfs-"
    ) as directory:
      archive = Path(directory) / "runtime-rootfs.tar"
      run_external(
        [docker, "export", "--output", str(archive), container_id],
        "locked runtime rootfs export",
      )
      if not archive.is_file() or archive.stat().st_size == 0:
        raise BaselineError("locked runtime rootfs export is empty", 3)
      yield archive
  finally:
    subprocess.run(
      [docker, "rm", "--force", container_id],
      capture_output=True,
      check=False,
    )


def write_canonical(path, value):
  path = Path(path)
  path.parent.mkdir(parents=True, exist_ok=True)
  temporary = path.with_name(path.name + ".tmp")
  temporary.write_bytes(canonical_json_bytes(value) + b"\n")
  os.replace(temporary, path)


def prepare_fresh_output(path, root, description):
  root = Path(root).resolve()
  output = Path(os.path.abspath(path))
  verify_unaliased_parents(output, root, description, 2)
  if path_is_alias(output):
    raise BaselineError(
      f"{description} must not be a symbolic link or junction: {output}", 2
    )
  try:
    relative = output.relative_to(root)
  except ValueError as error:
    raise BaselineError(f"{description} path escapes artifact root: {output}", 2) from error
  if output.exists():
    if not output.is_file():
      raise BaselineError(f"{description} is not a file: {output}", 2)
    output.unlink()
  return output, relative.as_posix()


def bootstrap(args):
  source_lock = load_contract(
    args.source_lock, "source-lock", "locked source input", args.schema_dir
  )
  toolchain_lock = load_contract(
    args.toolchain_lock,
    "toolchain-lock",
    "locked toolchain input",
    args.schema_dir,
  )
  image_lock = load_contract(args.image_lock, "image-lock", "locked image input", args.schema_dir)
  if source_lock["sourceDateEpoch"] != toolchain_lock["sourceDateEpoch"]:
    raise BaselineError("source and toolchain sourceDateEpoch values do not match", 3)

  cache_directory = resolve_unaliased_root(
    args.cache_directory, "locked toolchain cache root", 3
  )
  cache_directory.mkdir(parents=True, exist_ok=True)
  if not cache_directory.is_dir():
    raise BaselineError(f"locked toolchain cache root is not a directory: {cache_directory}", 3)
  toolchain_files = []
  for tool in toolchain_lock["tools"]:
    relative_path = Path("toolchain") / tool["id"] / tool["sha256"]
    path = cache_directory / relative_path
    cache_toolchain_input(tool, path, cache_directory)
    if not path.is_file():
      raise BaselineError(f"locked toolchain cache is missing: {path}", 3)
    actual_size = path.stat().st_size
    if actual_size != tool["size"]:
      raise BaselineError(
        f"locked toolchain cache size mismatch for {tool['id']}: expected {tool['size']}, got {actual_size}",
        3,
      )
    actual_digest = sha256_file(path)
    if actual_digest != tool["sha256"]:
      raise BaselineError(
        f"locked toolchain cache digest mismatch for {tool['id']}: expected {tool['sha256']}, got {actual_digest}",
        3,
      )
    toolchain_files.append({
      "id": tool["id"],
      "path": relative_path.as_posix(),
      "size": actual_size,
      "sha256": actual_digest,
    })

  image_records = []
  docker = args.docker
  for image in image_lock["images"]:
    pinned = pinned_image_reference(image)
    run_external(
      [docker, "pull", "--platform", "linux/amd64", pinned],
      f"locked image pull for {image['id']}",
    )
    verify_local_image(docker, image)
    image_records.append({
      "id": image["id"],
      "role": image["role"],
      "reference": image["reference"],
      "digest": image["digest"],
      "configDigest": image["configDigest"],
    })

  manifest = {
    "schemaVersion": 1,
    "manifestType": "bootstrap",
    "platform": "linux-amd64",
    "sourceLockSha256": canonical_sha256(source_lock),
    "toolchainLockSha256": canonical_sha256(toolchain_lock),
    "imageLockSha256": canonical_sha256(image_lock),
    "sourceDateEpoch": source_lock["sourceDateEpoch"],
    "environment": toolchain_lock["environment"],
    "network": "online-only",
    "toolchainFiles": toolchain_files,
    "images": image_records,
  }
  validate_contract(manifest, "bootstrap-manifest", args.schema_dir)
  write_canonical(args.output, manifest)


def verify_toolchain_files(toolchain_lock, cache_directory, manifest):
  cache_directory = resolve_unaliased_root(
    cache_directory, "locked toolchain cache root", 3
  )
  expected = []
  for tool in toolchain_lock["tools"]:
    relative_path = Path("toolchain") / tool["id"] / tool["sha256"]
    path = cache_directory / relative_path
    verify_unaliased_parents(path, cache_directory, "locked toolchain cache", 3)
    if path_is_alias(path):
      raise BaselineError(
        f"locked toolchain cache must not be a symbolic link or junction: {path}", 3
      )
    if not path.is_file():
      raise BaselineError(f"locked toolchain cache is missing: {path}", 3)
    if path.stat().st_size != tool["size"] or sha256_file(path) != tool["sha256"]:
      raise BaselineError(f"locked toolchain cache digest mismatch for {tool['id']}", 3)
    expected.append({
      "id": tool["id"],
      "path": relative_path.as_posix(),
      "size": tool["size"],
      "sha256": tool["sha256"],
    })
  if manifest["toolchainFiles"] != expected:
    raise BaselineError("bootstrap toolchain cache inventory does not match the lock", 3)


def locked_zstd_tool(toolchain_lock):
  candidates = [
    tool for tool in toolchain_lock["tools"]
    if tool["id"] == "zstd"
  ]
  if len(candidates) != 1:
    raise BaselineError(
      "toolchain lock must contain exactly one zstd verifier", 2
    )
  tool = candidates[0]
  materialization = tool["materialization"]
  declared_mode = int(materialization.get("mode", "0000"), 8)
  if (
    tool["platform"] != toolchain_lock["platform"]
    or "package" not in tool["consumers"]
    or materialization["root"] != "toolchain"
    or materialization["type"] != "file"
    or PurePosixPath(materialization["destination"]).name != "zstd"
    or declared_mode & 0o111 == 0
  ):
    raise BaselineError(
      "locked zstd verifier must be an executable package-consumer file", 2
    )
  return tool


@contextmanager
def locked_zstd_verifier(toolchain_lock, cache_directory):
  tool = locked_zstd_tool(toolchain_lock)

  if not cache_directory:
    raise BaselineError("locked zstd verifier cache directory is required", 3)
  cache_input = resolve_unaliased_root(
    cache_directory, "locked zstd verifier cache root", 3
  )
  if not cache_input.is_dir():
    raise BaselineError(
      f"locked zstd verifier cache directory is missing: {cache_input}", 3
    )
  cache_root = cache_input
  source = cache_root / "toolchain" / tool["id"] / tool["sha256"]
  verify_unaliased_parents(source, cache_root, "locked zstd verifier", 3)
  if path_is_alias(source):
    raise BaselineError(
      f"locked zstd verifier must not be a symbolic link or junction: {source}", 3
    )
  if not source.is_file():
    raise BaselineError(f"locked zstd verifier is missing: {source}", 3)
  if source.stat().st_size != tool["size"] or sha256_file(source) != tool["sha256"]:
    raise BaselineError("locked zstd verifier digest does not match toolchain lock", 3)

  with tempfile.TemporaryDirectory(prefix="jetonlyoffice-zstd-verify-") as directory:
    Path(directory).chmod(0o755)
    executable = Path(directory) / "zstd"
    shutil.copyfile(source, executable)
    executable.chmod(0o755)
    if (
      executable.stat().st_size != tool["size"]
      or sha256_file(executable) != tool["sha256"]
    ):
      raise BaselineError("materialized zstd verifier digest does not match", 4)
    yield executable


@contextmanager
def locked_cache_view(toolchain_lock, cache_directory, bootstrap_manifest, consumers):
  cache_directory = resolve_unaliased_root(
    cache_directory, "locked toolchain cache root", 3
  )
  with tempfile.TemporaryDirectory(prefix="jetonlyoffice-locked-cache-") as directory:
    root = Path(directory)
    selected_tools = [
      tool for tool in toolchain_lock["tools"]
      if set(tool["consumers"]) & set(consumers)
    ]
    for tool in selected_tools:
      relative = Path("toolchain") / tool["id"] / tool["sha256"]
      source = cache_directory / relative
      verify_unaliased_parents(source, cache_directory, "locked toolchain cache", 3)
      if path_is_alias(source):
        raise BaselineError(
          f"locked toolchain cache must not be a symbolic link or junction: {source}", 3
        )
      destination = root / relative
      destination.parent.mkdir(parents=True, exist_ok=True)
      shutil.copyfile(source, destination)
      if destination.stat().st_size != tool["size"] or sha256_file(destination) != tool["sha256"]:
        raise BaselineError(f"locked toolchain cache view mismatch for {tool['id']}", 3)
    materialization_entries = []
    materialization_lines = []
    for tool in selected_tools:
      materialization = tool["materialization"]
      source = (Path("toolchain") / tool["id"] / tool["sha256"]).as_posix()
      entry = {
        "id": tool["id"],
        "source": source,
        "root": materialization["root"],
        "type": materialization["type"],
        "destination": materialization["destination"],
      }
      if "stripComponents" in materialization:
        entry["stripComponents"] = materialization["stripComponents"]
      if "mode" in materialization:
        entry["mode"] = materialization["mode"]
      materialization_entries.append(entry)
      materialization_lines.append("\t".join((
        materialization["type"],
        source,
        materialization["root"],
        materialization["destination"],
        str(materialization.get("stripComponents", 0)),
        materialization.get("mode", "-"),
      )))
    materialization_plan = {
      "schemaVersion": 1,
      "planType": "toolchain-materialization",
      "consumers": sorted(consumers),
      "toolchainLockSha256": canonical_sha256(toolchain_lock),
      "entries": materialization_entries,
    }
    materialization_tsv = ("\n".join(materialization_lines) + "\n").encode("utf-8")
    write_canonical(root / "materialization-plan.json", materialization_plan)
    (root / "materialization-plan.tsv").write_bytes(materialization_tsv)
    write_canonical(root / "bootstrap-manifest.json", bootstrap_manifest)
    write_canonical(root / "toolchain.lock.json", toolchain_lock)
    write_canonical(root / "cache-view.json", {
      "schemaVersion": 1,
      "viewType": "toolchain-cache",
      "consumers": sorted(consumers),
      "toolchainLockSha256": canonical_sha256(toolchain_lock),
      "materializationPlanSha256": canonical_sha256(materialization_plan),
      "materializationPlanTsvSha256": hashlib.sha256(materialization_tsv).hexdigest(),
      "toolchainFiles": [
        {
          "id": tool["id"],
          "path": (Path("toolchain") / tool["id"] / tool["sha256"]).as_posix(),
          "sha256": tool["sha256"],
          "size": tool["size"],
        }
        for tool in selected_tools
      ],
    })
    yield root


def verify_bootstrap_bindings(bootstrap_manifest, source_lock, toolchain_lock, image_lock):
  expected_hashes = {
    "sourceLockSha256": canonical_sha256(source_lock),
    "toolchainLockSha256": canonical_sha256(toolchain_lock),
    "imageLockSha256": canonical_sha256(image_lock),
  }
  for key, expected in expected_hashes.items():
    if bootstrap_manifest[key] != expected:
      raise BaselineError(f"bootstrap manifest {key} does not match its lock", 3)
  if bootstrap_manifest["sourceDateEpoch"] != source_lock["sourceDateEpoch"]:
    raise BaselineError("bootstrap manifest sourceDateEpoch does not match source lock", 3)
  if source_lock["sourceDateEpoch"] != toolchain_lock["sourceDateEpoch"]:
    raise BaselineError("source and toolchain sourceDateEpoch values do not match", 3)
  if bootstrap_manifest["environment"] != toolchain_lock["environment"]:
    raise BaselineError("bootstrap environment does not match toolchain lock", 3)
  expected_images = [
    {
      "id": image["id"],
      "role": image["role"],
      "reference": image["reference"],
      "digest": image["digest"],
      "configDigest": image["configDigest"],
    }
    for image in image_lock["images"]
  ]
  if bootstrap_manifest["images"] != expected_images:
    raise BaselineError("bootstrap image inventory does not match the lock", 3)


def locked_image(image_lock, role):
  matches = [image for image in image_lock["images"] if image["role"] == role]
  if len(matches) != 1:
    raise BaselineError(f"image lock must contain exactly one {role} image", 3)
  return matches[0]


def verify_build_bindings(manifest, source_lock, toolchain_lock, image_lock, exit_code):
  builder = locked_image(image_lock, "builder")
  expected = {
    "sourceLockSha256": canonical_sha256(source_lock),
    "toolchainLockSha256": canonical_sha256(toolchain_lock),
    "imageLockSha256": canonical_sha256(image_lock),
    "builderImageDigest": builder["digest"],
    "sourceDateEpoch": source_lock["sourceDateEpoch"],
    "environment": toolchain_lock["environment"],
  }
  labels = {
    "sourceLockSha256": "source lock",
    "toolchainLockSha256": "toolchain lock",
    "imageLockSha256": "image lock",
    "builderImageDigest": "builder image",
    "sourceDateEpoch": "sourceDateEpoch",
    "environment": "toolchain environment",
  }
  for key, value in expected.items():
    if manifest[key] != value:
      raise BaselineError(
        f"build manifest {labels[key]} does not match the lock", exit_code
      )
  return builder


def build(args):
  bootstrap_manifest = load_contract(
    args.bootstrap_manifest,
    "bootstrap-manifest",
    "locked bootstrap input",
    args.schema_dir,
  )
  source_lock = load_contract(
    args.source_lock, "source-lock", "locked source input", args.schema_dir
  )
  toolchain_lock = load_contract(
    args.toolchain_lock,
    "toolchain-lock",
    "locked toolchain input",
    args.schema_dir,
  )
  image_lock = load_contract(args.image_lock, "image-lock", "locked image input", args.schema_dir)
  verify_bootstrap_bindings(bootstrap_manifest, source_lock, toolchain_lock, image_lock)
  verify_toolchain_files(toolchain_lock, args.cache_directory, bootstrap_manifest)

  builder = locked_image(image_lock, "builder")
  source_directory = Path(args.source_directory).resolve()
  cache_directory = Path(args.cache_directory).resolve()
  artifact_directory = Path(args.artifact_directory).resolve()
  container_scripts = Path(__file__).resolve().parent / "container"
  if not source_directory.is_dir():
    raise BaselineError(f"locked source workspace is missing: {source_directory}", 3)
  try:
    verify_materialized(source_lock, source_directory)
  except ResolutionError as error:
    raise BaselineError(str(error), error.exit_code) from error
  verify_local_image(args.docker, builder)
  artifact_directory.mkdir(parents=True, exist_ok=True)
  output, output_relative = prepare_fresh_output(
    args.output, artifact_directory, "offline build output"
  )
  with tempfile.TemporaryDirectory(
    dir=artifact_directory, prefix=".build-stage-"
  ) as staging_directory, tempfile.TemporaryDirectory(
    dir=artifact_directory, prefix=".build-work-"
  ) as work_directory, locked_cache_view(
    toolchain_lock, cache_directory, bootstrap_manifest, {"build"}
  ) as cache_view:
    staging_directory = Path(staging_directory)
    command = [
      args.docker,
      "run",
      *docker_user_args(),
      "--rm",
      "--pull",
      "never",
      "--network",
      "none",
      "--platform",
      "linux/amd64",
      "--read-only",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--tmpfs",
      "/tmp:rw,nosuid,nodev",
      "--env",
      "SOURCE_DATE_EPOCH=" + str(source_lock["sourceDateEpoch"]),
      "--env",
      "TZ=UTC",
      "--env",
      "LANG=C.UTF-8",
      "--env",
      "LC_ALL=C.UTF-8",
      "--env",
      "PYTHONHASHSEED=0",
      "--env",
      "JETONLYOFFICE_NETWORK_POLICY=none",
      "--env",
      "NPM_CONFIG_OFFLINE=true",
      "--env",
      "NPM_CONFIG_AUDIT=false",
      "--env",
      "NPM_CONFIG_FUND=false",
      "--env",
      "PIP_NO_INDEX=1",
      "--env",
      "CARGO_NET_OFFLINE=true",
      "--env",
      "YARN_ENABLE_NETWORK=0",
      "--env",
      "GIT_TERMINAL_PROMPT=0",
      "--env",
      "JETONLYOFFICE_BUILD_ID=jetonlyoffice-9.4.0-linux-amd64",
      "--env",
      "JETONLYOFFICE_SOURCE_LOCK_SHA256=" + canonical_sha256(source_lock),
      "--env",
      "JETONLYOFFICE_TOOLCHAIN_LOCK_SHA256=" + canonical_sha256(toolchain_lock),
      "--env",
      "JETONLYOFFICE_IMAGE_LOCK_SHA256=" + canonical_sha256(image_lock),
      "--env",
      "JETONLYOFFICE_BUILDER_IMAGE_DIGEST=" + builder["digest"],
      "--env",
      "JETONLYOFFICE_BUILD_MANIFEST_PATH=/output/" + output_relative,
      "--mount",
      "type=bind,src=" + source_directory.as_posix() + ",dst=/input/sources,readonly",
      "--mount",
      "type=bind,src=" + Path(args.source_lock).resolve().as_posix() + ",dst=/input/sources.lock.json,readonly",
      "--mount",
      "type=bind,src=" + Path(args.toolchain_lock).resolve().as_posix() + ",dst=/input/toolchain.lock.json,readonly",
      "--mount",
      "type=bind,src=" + Path(args.image_lock).resolve().as_posix() + ",dst=/input/images.lock.json,readonly",
      "--mount",
      "type=bind,src=" + cache_view.as_posix() + ",dst=/input/cache,readonly",
      "--mount",
      "type=bind,src=" + staging_directory.as_posix() + ",dst=/output",
      "--mount",
      "type=bind,src=" + Path(work_directory).as_posix() + ",dst=/work",
      "--mount",
      "type=bind,src=" + container_scripts.as_posix() + ",dst=/jetonlyoffice/container,readonly",
      pinned_image_reference(builder),
      "/bin/sh",
      "/jetonlyoffice/container/build-baseline.sh",
    ]
    run_external(command, "offline build container", exit_code=4)
    staged_output = require_file(
      staging_directory / output_relative, "offline build output", exit_code=4
    )
    try:
      manifest = load_json(staged_output)
      validate_contract(manifest, "build-manifest", args.schema_dir)
    except ContractError as error:
      raise BaselineError(f"offline build output is invalid: {error}", 4) from error
    verify_build_bindings(manifest, source_lock, toolchain_lock, image_lock, 4)
    verify_manifest_files(manifest, staging_directory, "offline build output")
    promote_manifest_files(
      manifest, staging_directory, artifact_directory, output, "offline build output"
    )


def verify_manifest_files(manifest, root, description):
  root = Path(root).resolve()
  file_inventory = "files" in manifest
  records = manifest["files"] if file_inventory else manifest.get("artifacts", [])
  for record in records:
    path = root / record["path"]
    record_type = record["type"] if file_inventory else "file"
    if record_type not in {"file", "symlink"}:
      raise BaselineError(f"{description} has unknown file type: {record_type}", 2)
    verify_unaliased_parents(path, root, description, 2)
    if record_type == "symlink":
      if not path.is_symlink():
        raise BaselineError(f"{description} symlink is missing: {path}", 3)
      target = os.readlink(path)
      if target != record["symlinkTarget"]:
        raise BaselineError(
          f"{description} symlink target mismatch for {record['path']}", 3
        )
      try:
        resolved_target = (path.parent / target).resolve(strict=True)
        resolved_target.relative_to(root)
      except ValueError as error:
        raise BaselineError(
          f"{description} symlink target escapes root: {record['path']}", 2
        ) from error
      except (OSError, RuntimeError) as error:
        raise BaselineError(
          f"{description} symlink target cannot be resolved: {record['path']}", 3
        ) from error
      payload = target.encode("utf-8")
      size = len(payload)
      digest = hashlib.sha256(payload).hexdigest()
    else:
      if path_is_alias(path):
        raise BaselineError(
          f"{description} regular file is a symbolic link or junction: {path}", 3
        )
      if not path.is_file():
        raise BaselineError(f"{description} is missing: {path}", 3)
      size = path.stat().st_size
      digest = sha256_file(path)
    if size != record["size"]:
      raise BaselineError(
        f"{description} size mismatch for {record['path']}: expected {record['size']}, got {size}",
        3,
      )
    if digest != record["sha256"]:
      raise BaselineError(
        f"{description} digest mismatch for {record['path']}: expected {record['sha256']}, got {digest}",
        3,
      )


def promote_manifest_files(manifest, staging_root, artifact_root, output, description):
  staging_root = Path(staging_root).resolve()
  artifact_root = Path(artifact_root).resolve()
  output = verify_unaliased_parents(output, artifact_root, description, 2)
  records = manifest.get("files", manifest.get("artifacts", []))
  promotions = []
  for record in records:
    source = staging_root / record["path"]
    destination = artifact_root / record["path"]
    verify_unaliased_parents(source, staging_root, description, 2)
    verify_unaliased_parents(destination, artifact_root, description, 2)
    if destination == output:
      raise BaselineError(
        f"{description} artifact conflicts with manifest output: {record['path']}", 2
      )
    if destination.exists() or destination.is_symlink():
      raise BaselineError(f"{description} destination already exists: {destination}", 4)
    promotions.append((source, destination))

  for source, destination in promotions:
    verify_unaliased_parents(source, staging_root, description, 2)
    verify_unaliased_parents(destination, artifact_root, description, 2)
    destination.parent.mkdir(parents=True, exist_ok=True)
    verify_unaliased_parents(destination, artifact_root, description, 2)
    try:
      os.replace(source, destination)
    except OSError as error:
      raise BaselineError(
        f"{description} promotion failed for {source}: {error}", 4
      ) from error
  verify_unaliased_parents(output, artifact_root, description, 2)
  write_canonical(output, manifest)


def one_artifact(manifest, artifact_type):
  matches = [item for item in manifest["artifacts"] if item["type"] == artifact_type]
  if len(matches) != 1:
    raise BaselineError(
      f"artifact manifest must contain exactly one {artifact_type} artifact", 4
    )
  return matches[0]


def sbom_identifier(prefix, value):
  sanitized = "".join(
    character if character.isalnum() or character in ".-" else "-"
    for character in value
  )
  return prefix + sanitized


def component_evidence_reference(item, repositories_by_id):
  if item["type"] == "repository-git-blob":
    repository = repositories_by_id[item["repository"]]
    return (
      f"{item['type']}:{item['path']}:sha256:{item['sha256']}:"
      f"repository:{item['repository']}@{repository['commit']}:"
      f"tree:{repository['tree']}:"
      f"reference:{item['referencePath']}@{item['referenceBlob']}:"
      f"sha256:{item['referenceSha256']}:"
      f"license:{item['locator']}@{item['evidenceBlob']}:"
      f"sha256:{item['evidenceSha256']}"
    )
  return (
    f"{item['type']}:{item['path']}:{item['locator']}:"
    f"sha256:{item['evidenceSha256']}"
  )


def locked_license_units(source_lock, toolchain):
  units = []
  repositories_by_id = {
    repository["id"]: repository for repository in source_lock["repositories"]
  }
  for repository in source_lock["repositories"]:
    if not repository["active"] or not repository["buildInput"]:
      continue
    license_record = repository["license"]
    if license_record.get("scope") == "component":
      for component in license_record["components"]:
        units.append({
          "spdxId": sbom_identifier(
            "SPDXRef-", repository["id"] + "-" + component["id"]
          ),
          "bomRef": "repo:" + repository["id"] + ":" + component["id"],
          "name": repository["id"] + "/" + component["id"],
          "version": repository["commit"],
          "origin": repository["origin"],
          "spdx": component["license"]["spdx"],
          "repository": repository["id"],
          "payloadPaths": list(component["payloadPaths"]),
          "evidence": [
            component_evidence_reference(item, repositories_by_id)
            for item in component["license"]["evidence"]
          ],
          "externalType": "vcs",
        })
    else:
      units.append({
        "spdxId": sbom_identifier("SPDXRef-", repository["id"]),
        "bomRef": "repo:" + repository["id"],
        "name": repository["id"],
        "version": repository["commit"],
        "origin": repository["origin"],
        "spdx": license_record["spdx"],
        "repository": repository["id"],
        "payloadPaths": [],
        "evidence": [],
        "externalType": "vcs",
      })
  for tool in toolchain.get("tools", []):
    units.append({
      "spdxId": sbom_identifier("SPDXRef-tool-", tool["id"]),
      "bomRef": "tool:" + tool["id"],
      "name": tool["name"],
      "version": tool["version"],
      "origin": tool["sourceUrl"],
      "spdx": tool["license"],
      "repository": None,
      "payloadPaths": [],
      "evidence": [],
      "externalType": "distribution",
    })
  return units


def license_references(expression):
  return sorted(set(re.findall(r"LicenseRef-[A-Za-z0-9.-]+", expression)))


def evidence_license_references(expression, evidence):
  return evidence.get("licenseRefs", license_references(expression))


def load_supply_chain_json(manifest, artifact_root, artifact_type):
  record = one_artifact(manifest, artifact_type)
  try:
    return load_json(Path(artifact_root) / record["path"])
  except ContractError as error:
    raise BaselineError(f"{artifact_type} artifact is invalid: {error}", 4) from error


def verify_spdx_artifact(
  manifest, artifact_root, source_lock, toolchain, expected_extracted_licenses=None
):
  value = load_supply_chain_json(manifest, artifact_root, "spdx")
  if value.get("spdxVersion") != "SPDX-2.3":
    raise BaselineError("SPDX artifact is not SPDX 2.3", 4)
  expected_namespace = (
    "https://jetonlyoffice.dev/spdx/" + canonical_sha256(source_lock)
  )
  if value.get("documentNamespace") != expected_namespace:
    raise BaselineError("SPDX source lock binding does not match", 4)
  packages = value.get("packages")
  if not isinstance(packages, list):
    raise BaselineError("SPDX artifact has no package inventory", 4)
  packages_by_id = {
    item.get("SPDXID"): item for item in packages if isinstance(item, dict)
  }
  expected_package_ids = {unit["spdxId"] for unit in locked_license_units(source_lock, toolchain)}
  if len(packages_by_id) != len(packages) or set(packages_by_id) != expected_package_ids:
    raise BaselineError("SPDX artifact has duplicate or invalid package ids", 4)
  units = locked_license_units(source_lock, toolchain)
  for unit in units:
    package = packages_by_id.get(unit["spdxId"])
    if package is None:
      raise BaselineError(f"SPDX artifact is missing {unit['name']}", 4)
    expected = {
      "name": unit["name"],
      "versionInfo": unit["version"],
      "downloadLocation": unit["origin"],
      "licenseConcluded": unit["spdx"],
      "licenseDeclared": unit["spdx"],
    }
    if any(package.get(key) != expected_value for key, expected_value in expected.items()):
      raise BaselineError(f"SPDX artifact metadata does not match {unit['name']}", 4)
    if unit["payloadPaths"] and any(
      text not in package.get("comment", "")
      for text in unit["payloadPaths"] + unit["evidence"]
    ):
      raise BaselineError(
        f"SPDX artifact license evidence does not match {unit['name']}", 4
      )
  described = value.get("documentDescribes", [])
  expected_described = sorted(unit["spdxId"] for unit in units)
  if described != expected_described:
    raise BaselineError("SPDX artifact described inventory does not match locks", 4)
  required_references = sorted({
    identifier
    for unit in units
    for identifier in license_references(unit["spdx"])
  })
  extracted = value.get("hasExtractedLicensingInfos", [])
  extracted_by_id = {
    item.get("licenseId"): item.get("extractedText")
    for item in extracted
    if isinstance(item, dict)
  }
  if len(extracted_by_id) != len(extracted):
    raise BaselineError("SPDX artifact has duplicate or invalid extracted licenses", 4)
  if any(
    not isinstance(extracted_by_id.get(identifier), str)
    or not extracted_by_id[identifier]
    for identifier in required_references
  ):
    raise BaselineError("SPDX artifact is missing extracted license text", 4)
  if set(extracted_by_id) != set(required_references):
    raise BaselineError("SPDX extracted license inventory does not match locks", 4)
  if (
    expected_extracted_licenses is not None
    and extracted_by_id != expected_extracted_licenses
  ):
    raise BaselineError("SPDX extracted license text does not match license bundle", 4)


def verify_cyclonedx_artifact(manifest, artifact_root, source_lock, toolchain):
  value = load_supply_chain_json(manifest, artifact_root, "cyclonedx")
  if value.get("bomFormat") != "CycloneDX" or value.get("specVersion") != "1.5":
    raise BaselineError("CycloneDX artifact is not version 1.5", 4)
  components = value.get("components")
  if not isinstance(components, list):
    raise BaselineError("CycloneDX artifact has no component inventory", 4)
  components_by_ref = {
    item.get("bom-ref"): item for item in components if isinstance(item, dict)
  }
  expected_component_refs = {
    unit["bomRef"] for unit in locked_license_units(source_lock, toolchain)
  }
  if (
    len(components_by_ref) != len(components)
    or set(components_by_ref) != expected_component_refs
  ):
    raise BaselineError("CycloneDX artifact has duplicate or invalid bom-ref values", 4)
  source_lock_property = [
    item.get("value")
    for item in value.get("metadata", {}).get("properties", [])
    if isinstance(item, dict)
    and item.get("name") == "jetonlyoffice.sourceLockSha256"
  ]
  if source_lock_property != [canonical_sha256(source_lock)]:
    raise BaselineError("CycloneDX source lock binding does not match", 4)
  for unit in locked_license_units(source_lock, toolchain):
    component = components_by_ref.get(unit["bomRef"])
    if component is None:
      raise BaselineError(f"CycloneDX artifact is missing {unit['name']}", 4)
    if (
      component.get("name") != unit["name"]
      or component.get("version") != unit["version"]
      or component.get("licenses") != [{"expression": unit["spdx"]}]
    ):
      raise BaselineError(
        f"CycloneDX artifact metadata does not match {unit['name']}", 4
      )
    references = component.get("externalReferences", [])
    if {"type": unit["externalType"], "url": unit["origin"]} not in references:
      raise BaselineError(
        f"CycloneDX artifact origin does not match {unit['name']}", 4
      )
    if unit["payloadPaths"]:
      properties = component.get("properties", [])
      property_pairs = [
        (item.get("name"), item.get("value"))
        for item in properties if isinstance(item, dict)
      ]
      expected_pairs = [
        ("jetonlyoffice.repository", unit["repository"]),
        ("jetonlyoffice.payloadPaths", ",".join(unit["payloadPaths"])),
        *[
          ("jetonlyoffice.licenseEvidence", reference)
          for reference in unit["evidence"]
        ],
      ]
      if property_pairs != expected_pairs:
        raise BaselineError(
          f"CycloneDX artifact license evidence does not match {unit['name']}", 4
        )


def verify_checksums_artifact(manifest, artifact_root):
  record = one_artifact(manifest, "checksums")
  path = Path(artifact_root) / record["path"]
  try:
    actual = path.read_text(encoding="ascii").splitlines()
  except (OSError, UnicodeError) as error:
    raise BaselineError(f"checksums artifact is invalid: {error}", 4) from error
  expected = [
    f"{item['sha256']}  {item['path']}"
    for item in sorted(manifest["artifacts"], key=lambda value: value["id"])
    if item["type"] != "checksums"
  ]
  if actual != expected:
    raise BaselineError("checksums artifact does not bind the artifact manifest", 4)


def verify_provenance_artifact(
  manifest, artifact_root, source_lock, toolchain, image_lock
):
  record = one_artifact(manifest, "provenance")
  try:
    value = load_json(Path(artifact_root) / record["path"])
  except ContractError as error:
    raise BaselineError(f"provenance artifact is invalid: {error}", 4) from error
  carriers = sorted(
    (item for item in manifest["artifacts"] if item["type"] in {"deb", "rootfs", "oci"}),
    key=lambda item: item["id"],
  )
  expected_subject = [
    {"name": item["id"], "digest": {"sha256": item["sha256"]}}
    for item in carriers
  ]
  if value.get("_type") != "https://in-toto.io/Statement/v1":
    raise BaselineError("provenance artifact is not an in-toto v1 statement", 4)
  if value.get("predicateType") != "https://slsa.dev/provenance/v1":
    raise BaselineError("provenance artifact is not SLSA provenance v1", 4)
  if value.get("subject") != expected_subject:
    raise BaselineError("provenance artifact subjects do not match release carriers", 4)
  predicate = value.get("predicate", {})
  build_definition = predicate.get("buildDefinition", {})
  if build_definition.get("buildType") != "https://jetonlyoffice.dev/build/offline-v1":
    raise BaselineError("provenance artifact build type does not match", 4)
  external = build_definition.get("externalParameters", {})
  expected_external = {
    "sourceLockSha256": canonical_sha256(source_lock),
    "toolchainLockSha256": canonical_sha256(toolchain),
    "imageLockSha256": canonical_sha256(image_lock),
    "sourceDateEpoch": source_lock["sourceDateEpoch"],
    "network": "none",
  }
  if external != expected_external:
    mismatched_fields = [
      field for field, expected in expected_external.items()
      if external.get(field) != expected
    ]
    if mismatched_fields:
      raise BaselineError(
        f"provenance artifact {mismatched_fields[0]} does not match", 4
      )
    raise BaselineError(
      "provenance artifact external parameters contain unlocked fields", 4
    )
  builder = locked_image(image_lock, "builder")
  expected_builder = "jetonlyoffice://builder@" + builder["digest"]
  if predicate.get("runDetails", {}).get("builder", {}).get("id") != expected_builder:
    raise BaselineError("provenance artifact builder identity does not match", 4)
  resolved_dependencies = build_definition.get("resolvedDependencies")
  expected_dependencies = [
    {"uri": repository["origin"], "digest": {"gitCommit": repository["commit"]}}
    for repository in source_lock["repositories"]
    if repository["active"] and repository["buildInput"]
  ]
  if resolved_dependencies != expected_dependencies:
    raise BaselineError(
      "provenance artifact resolved dependencies do not match build inputs", 4
    )


def safe_tar_members(archive, description):
  members = archive.getmembers()
  result = {}
  for member in members:
    name = member.name
    if "\\" in name:
      raise BaselineError(f"{description} contains an unsafe path: {name}", 4)
    normalized = name
    while normalized.startswith("./"):
      normalized = normalized[2:]
    if normalized in ("", "."):
      continue
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute() or ".." in candidate.parts:
      raise BaselineError(f"{description} contains an unsafe path: {name}", 4)
    if normalized in result:
      raise BaselineError(f"{description} contains a duplicate path: {normalized}", 4)
    result[normalized] = member
  return result


def read_tar_member(archive, members, name, description):
  member = members.get(name)
  if member is None or not member.isfile():
    raise BaselineError(f"{description} is missing: {name}", 4)
  stream = archive.extractfile(member)
  if stream is None:
    raise BaselineError(f"{description} cannot be read: {name}", 4)
  return stream.read()


@contextmanager
def open_zstd_tar_archive(
  path,
  description,
  toolchain=None,
  cache_directory=None,
  image_lock=None,
  docker="docker",
):
  path = Path(path)
  try:
    with path.open("rb") as stream:
      magic = stream.read(4)
  except OSError as error:
    raise BaselineError(f"{description} cannot be read: {error}", 4) from error
  if magic != b"\x28\xb5\x2f\xfd":
    raise BaselineError(f"{description} is not a zstd frame", 4)
  if toolchain is None:
    raise BaselineError(f"{description} requires the locked zstd verifier", 4)
  if image_lock is None:
    raise BaselineError(f"{description} requires the locked verifier image", 3)
  builder = locked_image(image_lock, "builder")
  with tempfile.TemporaryDirectory(prefix="jetonlyoffice-archive-verify-") as directory:
    expanded = Path(directory) / "expanded.tar"
    try:
      with locked_zstd_verifier(toolchain, cache_directory) as zstd:
        with expanded.open("wb") as output:
          command = [
            docker,
            "run",
            *docker_user_args(),
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev",
            "--mount",
            "type=bind,src=" + zstd.parent.as_posix()
            + ",dst=/verifier,readonly",
            "--mount",
            "type=bind,src=" + path.resolve().as_posix()
            + ",dst=/input/archive.tar.zst,readonly",
            pinned_image_reference(builder),
            "/verifier/zstd",
            "--decompress",
            "--stdout",
            "/input/archive.tar.zst",
          ]
          result = subprocess.run(
            command,
            stdout=output,
            stderr=subprocess.PIPE,
            check=False,
          )
    except OSError as error:
      raise BaselineError(f"locked zstd verifier failed: {error}", 3) from error
    if result.returncode != 0:
      detail = result.stderr.decode("utf-8", errors="replace").strip()
      raise BaselineError(
        f"{description} decompression failed" + (f": {detail}" if detail else ""),
        4,
      )
    try:
      with tarfile.open(expanded, "r:") as archive:
        yield archive
    except (OSError, tarfile.TarError) as error:
      raise BaselineError(f"{description} is invalid: {error}", 4) from error


@contextmanager
def open_license_archive(
  path,
  toolchain=None,
  cache_directory=None,
  image_lock=None,
  docker="docker",
):
  with open_zstd_tar_archive(
    path,
    "license archive",
    toolchain,
    cache_directory,
    image_lock,
    docker,
  ) as archive:
    yield archive


def verify_license_artifact(
  manifest,
  artifact_root,
  source_lock,
  toolchain,
  cache_directory=None,
  image_lock=None,
  docker="docker",
):
  record = one_artifact(manifest, "licenses")
  path = Path(artifact_root) / record["path"]
  extracted_materials = {}
  with open_license_archive(
    path, toolchain, cache_directory, image_lock, docker
  ) as archive:
    members = safe_tar_members(archive, "license archive")
    expected_files = {"manifest.json"}
    manifest_bytes = read_tar_member(
      archive, members, "manifest.json", "license archive"
    )
    try:
      license_manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
      raise BaselineError(f"license archive manifest is invalid: {error}", 4) from error
    if manifest_bytes != canonical_json_bytes(license_manifest) + b"\n":
      raise BaselineError("license archive manifest is not canonical", 4)
    if license_manifest.get("sourceLockSha256") != canonical_sha256(source_lock):
      raise BaselineError("license archive source lock binding does not match", 4)
    repository_records = license_manifest.get("repositories")
    if not isinstance(repository_records, list):
      raise BaselineError("license archive has no repository inventory", 4)
    by_id = {
      item.get("id"): item for item in repository_records if isinstance(item, dict)
    }
    locked_repositories = [
      item for item in source_lock["repositories"]
      if item["active"] and item["buildInput"]
    ]
    expected_ids = sorted(item["id"] for item in locked_repositories)
    if sorted(by_id) != expected_ids or len(by_id) != len(repository_records):
      raise BaselineError("license archive repository inventory does not match source lock", 4)
    for repository in locked_repositories:
      bundled = by_id[repository["id"]]
      if (
        bundled.get("commit") != repository["commit"]
        or bundled.get("origin") != repository["origin"]
      ):
        raise BaselineError(
          f"license archive metadata does not match {repository['id']}", 4
        )
      license_record = repository["license"]
      if license_record.get("scope") == "component":
        if (
          bundled.get("scope") != "component"
          or bundled.get("payloadPatterns") != license_record["payloadPatterns"]
        ):
          raise BaselineError(
            f"license archive component scope does not match {repository['id']}", 4
          )
        bundled_components = bundled.get("components")
        if not isinstance(bundled_components, list):
          raise BaselineError(
            f"license archive has no components for {repository['id']}", 4
          )
        components_by_id = {
          item.get("id"): item
          for item in bundled_components if isinstance(item, dict)
        }
        expected_component_ids = [
          item["id"] for item in license_record["components"]
        ]
        if (
          sorted(components_by_id) != expected_component_ids
          or len(components_by_id) != len(bundled_components)
        ):
          raise BaselineError(
            f"license archive component inventory does not match {repository['id']}", 4
          )
        for component in license_record["components"]:
          bundled_component = components_by_id[component["id"]]
          if (
            bundled_component.get("payloadPaths") != component["payloadPaths"]
            or bundled_component.get("license", {}).get("spdx")
            != component["license"]["spdx"]
          ):
            raise BaselineError(
              f"license archive component metadata does not match "
              f"{repository['id']}/{component['id']}", 4
            )
          bundled_evidence = bundled_component.get("license", {}).get("evidence")
          if not isinstance(bundled_evidence, list):
            raise BaselineError(
              f"license archive has no evidence for "
              f"{repository['id']}/{component['id']}", 4
            )
          if len(bundled_evidence) != len(component["license"]["evidence"]):
            raise BaselineError(
              f"license archive evidence inventory does not match "
              f"{repository['id']}/{component['id']}", 4
            )
          for expected, actual in zip(
            component["license"]["evidence"], bundled_evidence
          ):
            if any(actual.get(key) != value for key, value in expected.items()):
              raise BaselineError(
                f"license archive evidence metadata does not match "
                f"{repository['id']}/{component['id']}", 4
              )
            evidence_path = actual.get("licensePath")
            if not isinstance(evidence_path, str):
              raise BaselineError("license archive evidence path is missing", 4)
            expected_files.add(evidence_path)
            evidence_bytes = read_tar_member(
              archive, members, evidence_path, "license archive evidence"
            )
            if hashlib.sha256(evidence_bytes).hexdigest() != expected["evidenceSha256"]:
              raise BaselineError("license archive evidence digest does not match", 4)
            for identifier in evidence_license_references(
              component["license"]["spdx"], expected
            ):
              try:
                evidence_text = evidence_bytes.decode("utf-8")
              except UnicodeDecodeError as error:
                raise BaselineError(
                  f"{identifier} license evidence is not UTF-8: {error}", 4
                ) from error
              extracted_materials.setdefault(identifier, set()).add(evidence_text)
      else:
        if (
          bundled.get("spdx") != license_record["spdx"]
          or bundled.get("licenseSha256") != license_record.get(
            "materializedSha256", license_record["sha256"]
          )
        ):
          raise BaselineError(
            f"license archive declaration does not match {repository['id']}", 4
          )
        license_path = bundled.get("licensePath")
        if not isinstance(license_path, str):
          raise BaselineError("license archive repository license path is missing", 4)
        expected_files.add(license_path)
        license_bytes = read_tar_member(
          archive, members, license_path, "repository license"
        )
        expected_digest = license_record.get(
          "materializedSha256", license_record["sha256"]
        )
        if hashlib.sha256(license_bytes).hexdigest() != expected_digest:
          raise BaselineError("license archive repository license digest does not match", 4)
        for identifier in license_references(license_record["spdx"]):
          try:
            license_text = license_bytes.decode("utf-8")
          except UnicodeDecodeError as error:
            raise BaselineError(
              f"{identifier} license evidence is not UTF-8: {error}", 4
            ) from error
          extracted_materials.setdefault(identifier, set()).add(license_text)
    bundled_tools = license_manifest.get("tools")
    if not isinstance(bundled_tools, list):
      raise BaselineError("license archive has no toolchain inventory", 4)
    expected_tools = [
      {
        "id": tool["id"],
        "name": tool["name"],
        "version": tool["version"],
        "license": tool["license"],
        "sourceUrl": tool["sourceUrl"],
        **({"sha256": tool["sha256"]} if "sha256" in tool else {}),
      }
      for tool in sorted(toolchain.get("tools", []), key=lambda item: item["id"])
    ]
    if bundled_tools != expected_tools:
      raise BaselineError("license archive toolchain inventory does not match lock", 4)
    expected_members = set(expected_files)
    for file_path in expected_files:
      parent = PurePosixPath(file_path).parent
      while parent != PurePosixPath("."):
        expected_members.add(parent.as_posix())
        parent = parent.parent
    if set(members) != expected_members:
      raise BaselineError(
        "license archive member inventory does not match manifest", 4
      )
    if any(not members[name].isfile() for name in expected_files) or any(
      not members[name].isdir() for name in expected_members - expected_files
    ):
      raise BaselineError("license archive contains unsupported member types", 4)
  return {
    identifier: "\n\n".join(sorted(materials))
    for identifier, materials in sorted(extracted_materials.items())
  }


def extract_tar_member(archive, members, name, description, output):
  member = members.get(name)
  if member is None or not member.isfile():
    raise BaselineError(f"{description} is missing: {name}", 4)
  source = archive.extractfile(member)
  if source is None:
    raise BaselineError(f"{description} cannot be read: {name}", 4)
  digest = hashlib.sha256()
  size = 0
  with Path(output).open("wb") as destination:
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
      destination.write(chunk)
      digest.update(chunk)
      size += len(chunk)
  return digest.hexdigest(), size


def verify_oci_artifact(manifest, artifact_root):
  record = one_artifact(manifest, "oci")
  path = Path(artifact_root) / record["path"]
  try:
    with tempfile.TemporaryDirectory(prefix="jetonlyoffice-oci-verify-") as directory:
      layer_path = Path(directory) / "layer.tar"
      with tarfile.open(path, "r:") as archive:
        members = safe_tar_members(archive, "OCI layout")
        index_bytes = read_tar_member(archive, members, "index.json", "OCI layout")
        index = json.loads(index_bytes.decode("utf-8"))
        descriptors = index.get("manifests", [])
        if len(descriptors) != 1:
          raise BaselineError("OCI layout must contain exactly one image manifest", 4)
        descriptor = descriptors[0]
        if descriptor.get("digest") != record["ociDigest"]:
          raise BaselineError("OCI layout digest does not match artifact manifest", 4)
        digest = record["ociDigest"].removeprefix("sha256:")
        manifest_bytes = read_tar_member(
          archive, members, "blobs/sha256/" + digest, "OCI image manifest"
        )
        if hashlib.sha256(manifest_bytes).hexdigest() != digest:
          raise BaselineError("OCI image manifest digest is invalid", 4)
        image_manifest = json.loads(manifest_bytes.decode("utf-8"))
        config_descriptor = image_manifest.get("config", {})
        config_digest = str(config_descriptor.get("digest", "")).removeprefix("sha256:")
        config_bytes = read_tar_member(
          archive, members, "blobs/sha256/" + config_digest, "OCI image config"
        )
        if hashlib.sha256(config_bytes).hexdigest() != config_digest:
          raise BaselineError("OCI image config digest is invalid", 4)
        config = json.loads(config_bytes.decode("utf-8"))
        image_config = config.get("config", {})
        if image_config.get("Entrypoint") != ["/usr/local/bin/jetonlyoffice-entrypoint"]:
          raise BaselineError("OCI image does not use the JWT fail-closed entrypoint", 4)
        environment = image_config.get("Env", [])
        if "JWT_ENABLED=true" not in environment or any(
          item.startswith("JWT_SECRET=") for item in environment
        ):
          raise BaselineError("OCI image embeds an unsafe JWT configuration", 4)
        layers = image_manifest.get("layers", [])
        if len(layers) != 1:
          raise BaselineError("OCI image must contain exactly one normalized rootfs layer", 4)
        layer_digest = str(layers[0].get("digest", "")).removeprefix("sha256:")
        actual_digest, actual_size = extract_tar_member(
          archive, members, "blobs/sha256/" + layer_digest,
          "OCI rootfs layer", layer_path,
        )
        if actual_digest != layer_digest or actual_size != layers[0].get("size"):
          raise BaselineError("OCI rootfs layer digest or size is invalid", 4)
      with tarfile.open(layer_path, "r:") as layer:
        layer_members = safe_tar_members(layer, "OCI rootfs layer")
        entrypoint = read_tar_member(
          layer, layer_members, "usr/local/bin/jetonlyoffice-entrypoint",
          "OCI JWT entrypoint",
        )
  except BaselineError:
    raise
  except (OSError, tarfile.TarError, UnicodeError, json.JSONDecodeError) as error:
    raise BaselineError(f"OCI artifact is invalid: {error}", 4) from error
  expected_entrypoint = require_file(
    Path(__file__).resolve().parent / "container" / "jwt-entrypoint.sh",
    "JWT entrypoint source",
    exit_code=4,
  ).read_bytes()
  if entrypoint != expected_entrypoint:
    raise BaselineError("OCI JWT entrypoint does not match the locked source", 4)


def git_object_oid(object_type, payload):
  header = f"{object_type} {len(payload)}\0".encode("ascii")
  return hashlib.sha1(header + payload).hexdigest()


def hash_source_member(archive, member, git_blob=False):
  stream = archive.extractfile(member)
  if stream is None:
    raise BaselineError(
      f"source archive member cannot be read: {member.name}", 4
    )
  sha256 = hashlib.sha256()
  git_digest = hashlib.sha1()
  if git_blob:
    git_digest.update(f"blob {member.size}\0".encode("ascii"))
  size = 0
  for chunk in iter(lambda: stream.read(1024 * 1024), b""):
    sha256.update(chunk)
    if git_blob:
      git_digest.update(chunk)
    size += len(chunk)
  return size, sha256.hexdigest(), git_digest.hexdigest() if git_blob else None


def git_tree_oid(entries):
  ordered = sorted(
    entries,
    key=lambda item: item["name"].encode("utf-8")
    + (b"/" if item["type"] == "directory" else b"\0"),
  )
  payload = b"".join(
    (
      ("40000" if item["type"] == "directory" else item["mode"])
      + " "
      + item["name"]
    ).encode("utf-8")
    + b"\0"
    + bytes.fromhex(item["oid"])
    for item in ordered
  )
  return git_object_oid("tree", payload)


def verify_source_tree_repository(
  archive, members, repository, tree_repository, relationships
):
  identity = {
    key: repository[key]
    for key in ("id", "checkoutPath", "commit", "tree")
  }
  if any(tree_repository.get(key) != value for key, value in identity.items()):
    raise BaselineError(
      f"source tree manifest repository does not match {repository['id']}", 4
    )
  checkout = repository["checkoutPath"]
  entries = tree_repository["entries"]
  entry_by_path = {item["path"]: item for item in entries}
  lfs_by_path = {
    path: item
    for item in repository["lfsObjects"]
    for path in item["paths"]
  }
  materialized_paths = {
    item["path"] for item in entries if "materialized" in item
  }
  if materialized_paths != set(lfs_by_path):
    raise BaselineError(
      f"source tree manifest LFS paths do not match {repository['id']}", 4
    )

  expected_gitlinks = {
    relationship["path"]: next(
      item["commit"]
      for item in relationships["repositories"]
      if item["id"] == relationship["child"]
    )
    for relationship in relationships["relationships"]
    if relationship["parent"] == repository["id"]
  }
  actual_gitlinks = {
    item["path"]: item["oid"]
    for item in entries if item["type"] == "gitlink"
  }
  if actual_gitlinks != expected_gitlinks:
    raise BaselineError(
      f"source tree manifest gitlinks do not match {repository['id']}", 4
    )

  for entry in entries:
    path = entry["path"]
    member_name = checkout + "/" + path
    member = members.get(member_name)
    entry_type = entry["type"]
    context = f"{repository['id']}:{path}"
    if entry_type == "gitlink":
      if member is None or not member.isdir() or member.mode != 0o755:
        raise BaselineError(
          f"source archive tree does not match {context}: gitlink directory",
          4,
        )
      continue
    if member is None:
      raise BaselineError(
        f"source archive tree does not match {context}: member is missing", 4
      )
    if entry_type == "directory":
      if not member.isdir() or member.mode != 0o755:
        raise BaselineError(
          f"source archive tree does not match {context}: directory mode or type",
          4,
        )
      continue
    if entry_type == "symlink":
      if not member.issym():
        raise BaselineError(
          f"source archive tree does not match {context}: expected symlink", 4
        )
      payload = os.fsencode(member.linkname)
      if (
        len(payload) != entry["size"]
        or hashlib.sha256(payload).hexdigest() != entry["sha256"]
        or git_object_oid("blob", payload) != entry["oid"]
      ):
        raise BaselineError(
          f"source archive tree does not match {context}: symlink blob", 4
        )
      continue
    if not member.isfile():
      raise BaselineError(
        f"source archive tree does not match {context}: expected regular file", 4
      )
    expected_mode = 0o755 if entry["mode"] == "100755" else 0o644
    if member.mode != expected_mode:
      raise BaselineError(
        f"source archive tree does not match {context}: Git mode", 4
      )
    materialized = entry.get("materialized")
    size, digest, blob_oid = hash_source_member(
      archive, member, git_blob=materialized is None
    )
    if materialized is None:
      expected_size = entry["size"]
      expected_digest = entry["sha256"]
      expected_oid = entry["oid"]
    else:
      lfs_object = lfs_by_path[path]
      if materialized != {
        "size": lfs_object["size"], "sha256": lfs_object["oid"]
      }:
        raise BaselineError(
          f"source tree manifest LFS materialization does not match {context}", 4
        )
      expected_size = materialized["size"]
      expected_digest = materialized["sha256"]
      pointer = (
        "version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{materialized['sha256']}\n"
        f"size {materialized['size']}\n"
      ).encode("ascii")
      if (
        len(pointer) != entry["size"]
        or hashlib.sha256(pointer).hexdigest() != entry["sha256"]
        or git_object_oid("blob", pointer) != entry["oid"]
      ):
        raise BaselineError(
          f"source archive tree does not match {context}: LFS pointer blob", 4
        )
    if size != expected_size or digest != expected_digest \
        or (materialized is None and blob_oid != expected_oid):
      raise BaselineError(
        f"source archive tree does not match {context}: file blob", 4
      )

  for directory in sorted(
    (item for item in entries if item["type"] == "directory"),
    key=lambda item: item["path"].count("/"),
    reverse=True,
  ):
    children = [
      {
        **item,
        "name": PurePosixPath(item["path"]).name,
      }
      for item in entries
      if PurePosixPath(item["path"]).parent.as_posix() == directory["path"]
    ]
    if git_tree_oid(children) != directory["oid"]:
      raise BaselineError(
        f"source archive tree does not match {repository['id']}:{directory['path']}",
        4,
      )
  root_entries = [
    {**item, "name": PurePosixPath(item["path"]).name}
    for item in entries
    if PurePosixPath(item["path"]).parent == PurePosixPath(".")
  ]
  if git_tree_oid(root_entries) != repository["tree"]:
    raise BaselineError(
      f"source archive tree does not match {repository['id']}:root", 4
    )


def verify_source_artifact(
  manifest,
  artifact_root,
  source_lock,
  toolchain,
  cache_directory=None,
  image_lock=None,
  docker="docker",
):
  record = one_artifact(manifest, "source")
  path = Path(artifact_root) / record["path"]
  with open_zstd_tar_archive(
    path,
    "source archive",
    toolchain,
    cache_directory,
    image_lock,
    docker,
  ) as archive:
    members = safe_tar_members(archive, "source archive")
    lock_values = {
      "sources.lock.json": source_lock,
      "toolchain.lock.json": toolchain,
      "images.lock.json": image_lock,
    }
    for name, expected in lock_values.items():
      payload = read_tar_member(archive, members, name, "source archive lock")
      if payload != canonical_json_bytes(expected) + b"\n":
        raise BaselineError(
          f"source archive lock does not match: {name}", 4
        )
    tree_record = source_lock["sourceTreeManifest"]
    tree_payload = read_tar_member(
      archive,
      members,
      tree_record["path"],
      "source tree manifest",
    )
    if (
      len(tree_payload) != tree_record["size"]
      or hashlib.sha256(tree_payload).hexdigest() != tree_record["sha256"]
    ):
      raise BaselineError(
        "source tree manifest does not match the source lock", 4
      )
    try:
      tree_manifest = json.loads(tree_payload.decode("utf-8"))
      validate_contract(
        tree_manifest, "source-tree-manifest", REPOSITORY_ROOT / "schemas"
      )
    except (UnicodeError, json.JSONDecodeError, ContractError) as error:
      raise BaselineError(f"source tree manifest is invalid: {error}", 4) from error
    expected_repositories = [
      item["id"] for item in source_lock["repositories"]
    ]
    if [item["id"] for item in tree_manifest["repositories"]] != expected_repositories:
      raise BaselineError(
        "source tree manifest repository inventory does not match the source lock",
        4,
      )
    relationship_context = {
      "repositories": source_lock["repositories"],
      "relationships": source_lock["relationships"],
    }
    for repository, tree_repository in zip(
      source_lock["repositories"], tree_manifest["repositories"]
    ):
      verify_source_tree_repository(
        archive,
        members,
        repository,
        tree_repository,
        relationship_context,
      )

    expected_members = set(lock_values) | {tree_record["path"]}
    for repository, tree_repository in zip(
      source_lock["repositories"], tree_manifest["repositories"]
    ):
      checkout = PurePosixPath(repository["checkoutPath"])
      for index in range(1, len(checkout.parts) + 1):
        expected_members.add(PurePosixPath(*checkout.parts[:index]).as_posix())
      for entry in tree_repository["entries"]:
        expected_members.add((checkout / entry["path"]).as_posix())
    if set(members) != expected_members:
      raise BaselineError(
        "source archive member inventory does not match the locked source tree",
        4,
      )
    for name in lock_values:
      if not members[name].isfile() or members[name].mode != 0o644:
        raise BaselineError("source archive lock member type or mode is invalid", 4)
    tree_member = members[tree_record["path"]]
    if not tree_member.isfile() or tree_member.mode != 0o644:
      raise BaselineError("source tree manifest member type or mode is invalid", 4)
    for name in expected_members - set(lock_values) - {tree_record["path"]}:
      if name in members and any(
        name == repository["checkoutPath"]
        or repository["checkoutPath"].startswith(name + "/")
        for repository in source_lock["repositories"]
      ):
        if not members[name].isdir() or members[name].mode != 0o755:
          raise BaselineError(
            "source archive checkout directory type or mode is invalid", 4
          )


def verify_supply_chain_artifacts(
  manifest,
  artifact_root,
  source_lock,
  toolchain,
  cache_directory=None,
  image_lock=None,
  docker="docker",
):
  for artifact_type in (
    "deb", "rootfs", "oci", "source", "spdx", "cyclonedx", "provenance",
    "checksums", "licenses", "notice",
  ):
    one_artifact(manifest, artifact_type)
  verify_source_artifact(
    manifest,
    artifact_root,
    source_lock,
    toolchain,
    cache_directory,
    image_lock,
    docker,
  )
  verify_checksums_artifact(manifest, artifact_root)
  extracted_licenses = verify_license_artifact(
    manifest,
    artifact_root,
    source_lock,
    toolchain,
    cache_directory,
    image_lock,
    docker,
  )
  verify_spdx_artifact(
    manifest, artifact_root, source_lock, toolchain, extracted_licenses
  )
  verify_cyclonedx_artifact(manifest, artifact_root, source_lock, toolchain)
  verify_provenance_artifact(
    manifest, artifact_root, source_lock, toolchain, image_lock
  )
  verify_oci_artifact(manifest, artifact_root)


def reproducibility_mismatches(manifest, reference_manifest):
  mismatches = []
  for artifact_type in ("deb", "rootfs", "oci"):
    primary = [item for item in manifest["artifacts"] if item["type"] == artifact_type]
    reference = [
      item for item in reference_manifest["artifacts"] if item["type"] == artifact_type
    ]
    if len(primary) != 1 or len(reference) != 1:
      raise BaselineError(
        f"expected exactly one {artifact_type} artifact per build", 4
      )
    differences = []
    if primary[0]["sha256"] != reference[0]["sha256"]:
      differences.append("sha256")
    if artifact_type == "oci" and primary[0]["ociDigest"] != reference[0]["ociDigest"]:
      differences.append("ociDigest")
    if differences:
      mismatches.append({
        "artifactType": artifact_type,
        "differences": differences,
        "primary": {
          "path": primary[0]["path"],
          "sha256": primary[0]["sha256"],
          **({"ociDigest": primary[0]["ociDigest"]} if artifact_type == "oci" else {}),
        },
        "reference": {
          "path": reference[0]["path"],
          "sha256": reference[0]["sha256"],
          **({"ociDigest": reference[0]["ociDigest"]} if artifact_type == "oci" else {}),
        },
      })
  return mismatches


def generate_diffoscope_reports(
  mismatches, artifact_directory, reference_artifact_directory,
  executable, output_directory,
):
  output_directory = Path(output_directory).resolve()
  if output_directory.exists() and not output_directory.is_dir():
    raise BaselineError(
      f"diffoscope output is not a directory: {output_directory}", 4
    )
  output_directory.mkdir(parents=True, exist_ok=True)
  artifact_directory = Path(artifact_directory).resolve()
  reference_artifact_directory = Path(reference_artifact_directory).resolve()
  reports = []
  for mismatch in mismatches:
    artifact_type = mismatch["artifactType"]
    primary_path = artifact_directory / mismatch["primary"]["path"]
    reference_path = reference_artifact_directory / mismatch["reference"]["path"]
    report = output_directory / f"{artifact_type}.html"
    report.unlink(missing_ok=True)
    try:
      result = subprocess.run(
        [executable, "--html", str(report), str(primary_path), str(reference_path)],
        capture_output=True,
        text=True,
        check=False,
      )
    except OSError as error:
      summary = {
        "schemaVersion": 1,
        "outcome": "BLOCKED",
        "errorCode": "DIFFOSCOPE_UNAVAILABLE",
        "mismatches": mismatches,
      }
      write_canonical(output_directory / "reproducibility-report.json", summary)
      raise BaselineError(
        f"REPRODUCIBILITY_MISMATCH: diffoscope cannot start: {error}", 4
      ) from error
    if result.returncode not in (0, 1) or not report.is_file() or report.stat().st_size == 0:
      summary = {
        "schemaVersion": 1,
        "outcome": "BLOCKED",
        "errorCode": "DIFFOSCOPE_FAILED",
        "mismatches": mismatches,
      }
      write_canonical(output_directory / "reproducibility-report.json", summary)
      detail = result.stderr.strip() or result.stdout.strip() or "report was not produced"
      raise BaselineError(
        f"REPRODUCIBILITY_MISMATCH: diffoscope failed for {artifact_type}: {detail}", 4
      )
    reports.append({
      "artifactType": artifact_type,
      "path": report.name,
      "sha256": sha256_file(report),
      "size": report.stat().st_size,
    })
  summary = {
    "schemaVersion": 1,
    "outcome": "BLOCKED",
    "errorCode": "REPRODUCIBILITY_MISMATCH",
    "mismatches": mismatches,
    "reports": reports,
  }
  write_canonical(output_directory / "reproducibility-report.json", summary)
  return output_directory / "reproducibility-report.json"


def package(args):
  build_manifest = load_contract(
    args.build_manifest,
    "build-manifest",
    "locked build input",
    args.schema_dir,
  )
  bootstrap_manifest = load_contract(
    args.bootstrap_manifest,
    "bootstrap-manifest",
    "locked bootstrap input",
    args.schema_dir,
  )
  source_lock = load_contract(
    args.source_lock, "source-lock", "locked source input", args.schema_dir
  )
  toolchain_lock = load_contract(
    args.toolchain_lock,
    "toolchain-lock",
    "locked toolchain input",
    args.schema_dir,
  )
  image_lock = load_contract(args.image_lock, "image-lock", "locked image input", args.schema_dir)
  verify_bootstrap_bindings(bootstrap_manifest, source_lock, toolchain_lock, image_lock)
  verify_toolchain_files(toolchain_lock, args.cache_directory, bootstrap_manifest)
  builder = verify_build_bindings(
    build_manifest, source_lock, toolchain_lock, image_lock, 3
  )
  runtime = locked_image(image_lock, "runtime")
  driver = build_manifest["packageDriver"]
  driver_record = next(
    (item for item in build_manifest["files"] if item["path"] == driver["path"]),
    None,
  )
  if driver_record is None:
    raise BaselineError("locked package driver is missing from build manifest", 3)
  artifact_directory = Path(args.artifact_directory).resolve()
  build_output_directory = artifact_directory / "build-output"
  if not build_output_directory.is_dir():
    raise BaselineError(f"locked build output is missing: {build_output_directory}", 3)
  verify_manifest_files(build_manifest, artifact_directory, "locked build output")
  verify_local_image(args.docker, builder)
  verify_local_image(args.docker, runtime)
  output, output_relative = prepare_fresh_output(
    args.output, artifact_directory, "offline package output"
  )

  cache_directory = Path(args.cache_directory).resolve()
  if not cache_directory.is_dir():
    raise BaselineError(f"locked package cache is missing: {cache_directory}", 3)
  container_scripts = Path(__file__).resolve().parent / "container"
  with tempfile.TemporaryDirectory(
    dir=artifact_directory, prefix=".package-stage-"
  ) as staging_directory, tempfile.TemporaryDirectory(
    dir=artifact_directory, prefix=".package-work-"
  ) as work_directory, locked_cache_view(
    toolchain_lock, cache_directory, bootstrap_manifest, {"package", "runtime"}
  ) as cache_view, export_locked_runtime_rootfs(
    args.docker, runtime, artifact_directory
  ) as runtime_rootfs:
    staging_directory = Path(staging_directory)
    command = [
      args.docker,
      "run",
      *docker_user_args(),
      "--rm",
      "--pull",
      "never",
      "--network",
      "none",
      "--platform",
      "linux/amd64",
      "--read-only",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--tmpfs",
      "/tmp:rw,nosuid,nodev",
      "--env",
      "SOURCE_DATE_EPOCH=" + str(source_lock["sourceDateEpoch"]),
      "--env",
      "TZ=UTC",
      "--env",
      "LANG=C.UTF-8",
      "--env",
      "LC_ALL=C.UTF-8",
      "--env",
      "PYTHONHASHSEED=0",
      "--env",
      "JETONLYOFFICE_NETWORK_POLICY=none",
      "--env",
      "NPM_CONFIG_OFFLINE=true",
      "--env",
      "NPM_CONFIG_AUDIT=false",
      "--env",
      "NPM_CONFIG_FUND=false",
      "--env",
      "PIP_NO_INDEX=1",
      "--env",
      "CARGO_NET_OFFLINE=true",
      "--env",
      "YARN_ENABLE_NETWORK=0",
      "--env",
      "GIT_TERMINAL_PROMPT=0",
      "--env",
      "JETONLYOFFICE_ARTIFACT_MANIFEST_PATH=/artifacts/" + output_relative,
      "--env",
      "JETONLYOFFICE_PACKAGE_DRIVER_PATH=/artifacts/" + driver["path"],
      "--env",
      "JETONLYOFFICE_PACKAGE_DRIVER_MODE=" + driver["mode"],
      "--env",
      "JETONLYOFFICE_SOURCE_LOCK_PATH=/input/locks/sources.lock.json",
      "--env",
      "JETONLYOFFICE_TOOLCHAIN_LOCK_PATH=/input/locks/toolchain.lock.json",
      "--env",
      "JETONLYOFFICE_IMAGE_LOCK_PATH=/input/locks/images.lock.json",
      "--env",
      "JETONLYOFFICE_RUNTIME_ROOTFS_PATH=/input/runtime-rootfs.tar",
      "--mount",
      "type=bind,src=" + staging_directory.as_posix() + ",dst=/artifacts",
      "--mount",
      "type=bind,src=" + build_output_directory.as_posix() + ",dst=/artifacts/build-output,readonly",
      "--mount",
      "type=bind,src=" + Path(args.build_manifest).resolve().as_posix() + ",dst=/artifacts/build-manifest.json,readonly",
      "--mount",
      "type=bind,src=" + Path(args.source_lock).resolve().as_posix() + ",dst=/input/locks/sources.lock.json,readonly",
      "--mount",
      "type=bind,src=" + Path(args.toolchain_lock).resolve().as_posix() + ",dst=/input/locks/toolchain.lock.json,readonly",
      "--mount",
      "type=bind,src=" + Path(args.image_lock).resolve().as_posix() + ",dst=/input/locks/images.lock.json,readonly",
      "--mount",
      "type=bind,src=" + runtime_rootfs.as_posix() + ",dst=/input/runtime-rootfs.tar,readonly",
      "--mount",
      "type=bind,src=" + cache_view.as_posix() + ",dst=/input/cache,readonly",
      "--mount",
      "type=bind,src=" + Path(work_directory).as_posix() + ",dst=/work",
      "--mount",
      "type=bind,src=" + container_scripts.as_posix() + ",dst=/jetonlyoffice/container,readonly",
      pinned_image_reference(builder),
      "/bin/sh",
      "/jetonlyoffice/container/package-baseline.sh",
    ]
    run_external(command, "offline package container", exit_code=4)
    staged_output = require_file(
      staging_directory / output_relative, "offline package output", exit_code=4
    )
    try:
      manifest = load_json(staged_output)
      validate_contract(manifest, "artifact-manifest", args.schema_dir)
    except ContractError as error:
      raise BaselineError(f"offline package output is invalid: {error}", 4) from error
    if manifest["sourceLockSha256"] != canonical_sha256(source_lock):
      raise BaselineError("artifact manifest source lock does not match the lock", 4)
    if manifest["buildManifestSha256"] != canonical_sha256(build_manifest):
      raise BaselineError("artifact manifest build input does not match the build manifest", 4)
    verify_manifest_files(manifest, staging_directory, "packaged artifact")
    promote_manifest_files(
      manifest, staging_directory, artifact_directory, output, "packaged artifact"
    )


def verify(args):
  artifact_manifest = load_contract(
    args.artifact_manifest,
    "artifact-manifest",
    "locked artifact input",
    args.schema_dir,
  )
  source_lock = load_contract(
    args.source_lock, "source-lock", "locked source input", args.schema_dir
  )
  toolchain = load_contract(
    args.toolchain_lock,
    "toolchain-lock",
    "locked toolchain input",
    args.schema_dir,
  )
  image_lock = load_contract(
    args.image_lock, "image-lock", "locked image input", args.schema_dir
  )
  if artifact_manifest["sourceLockSha256"] != canonical_sha256(source_lock):
    raise BaselineError("artifact manifest source lock does not match the lock", 3)
  artifact_directory = Path(args.artifact_directory).resolve()
  verify_manifest_files(artifact_manifest, artifact_directory, "packaged artifact")

  reference_artifact_directory = Path(args.reference_artifact_directory).resolve()
  if (
    Path(args.artifact_manifest).resolve() == Path(args.reference_artifact_manifest).resolve()
    or artifact_directory == reference_artifact_directory
  ):
    raise BaselineError(
      "independent build must use a different manifest and artifact directory", 4
    )

  reference_manifest = load_contract(
    args.reference_artifact_manifest,
    "artifact-manifest",
    "independent artifact manifest",
    args.schema_dir,
  )
  verify_manifest_files(
    reference_manifest,
    args.reference_artifact_directory,
    "independent packaged artifact",
  )
  for field in (
    "releaseId", "productVersion", "platform", "sourceLockSha256",
    "buildManifestSha256",
  ):
    if reference_manifest[field] != artifact_manifest[field]:
      raise BaselineError(f"independent artifact manifest {field} does not match", 4)
  mismatches = reproducibility_mismatches(artifact_manifest, reference_manifest)
  if mismatches:
    output_directory = getattr(args, "diffoscope_directory", None)
    if not output_directory:
      output_directory = Path(args.output).resolve().parent / "diffoscope"
    summary = generate_diffoscope_reports(
      mismatches,
      artifact_directory,
      args.reference_artifact_directory,
      getattr(args, "diffoscope", "diffoscope"),
      output_directory,
    )
    types = ", ".join(item["artifactType"] for item in mismatches)
    raise BaselineError(
      f"REPRODUCIBILITY_MISMATCH: {types} differ; diffoscope evidence: {summary}", 4
    )

  locked_zstd_tool(toolchain)
  verifier_image = locked_image(image_lock, "builder")
  verify_local_image(args.docker, verifier_image)
  verify_supply_chain_artifacts(
    artifact_manifest,
    artifact_directory,
    source_lock,
    toolchain,
    getattr(args, "cache_directory", None),
    image_lock,
    args.docker,
  )
  verify_supply_chain_artifacts(
    reference_manifest,
    args.reference_artifact_directory,
    source_lock,
    toolchain,
    getattr(args, "cache_directory", None),
    image_lock,
    args.docker,
  )

  oci = next(item for item in artifact_manifest["artifacts"] if item["type"] == "oci")
  if args.image and oci["ociDigest"] != args.image:
    raise BaselineError("requested image digest does not match the artifact manifest", 3)

  policy = load_contract(
    args.release_policy,
    "release-policy",
    "locked release policy",
    args.schema_dir,
  )
  if policy["sourceLockSha256"] != canonical_sha256(source_lock):
    raise BaselineError("release policy source lock does not match the lock", 3)
  if policy["releaseId"] != artifact_manifest["releaseId"]:
    raise BaselineError("release policy releaseId does not match artifact manifest", 3)
  if policy["productVersion"] != artifact_manifest["productVersion"]:
    raise BaselineError("release policy productVersion does not match artifact manifest", 3)

  gate_directory = Path(args.gate_result_directory)
  if not gate_directory.is_dir():
    raise BaselineError(f"locked gate result directory is missing: {gate_directory}", 3)
  gate_paths = sorted(gate_directory.glob("*.json"))
  gate_results = [load_json(path) for path in gate_paths]
  evidence = aggregate_release_evidence(
    policy,
    gate_results,
    args.run_id,
    canonical_sha256(artifact_manifest),
    args.schema_dir,
    args.repository_root,
  )
  write_canonical(args.output, evidence)
  if evidence["outcome"] != "PASS":
    raise BaselineError("release evidence is BLOCKED", 4)


def main(argv=None):
  parser = argparse.ArgumentParser(description="Run the locked JetOnlyOffice baseline")
  subparsers = parser.add_subparsers(dest="command", required=True)

  bootstrap_parser = subparsers.add_parser("preflight-bootstrap")
  bootstrap_parser.add_argument("--source-lock", required=True)
  bootstrap_parser.add_argument("--toolchain-lock", required=True)
  bootstrap_parser.add_argument("--image-lock", required=True)
  bootstrap_parser.add_argument("--schema-dir", required=True)

  finalize_parser = subparsers.add_parser("bootstrap")
  finalize_parser.add_argument("--source-lock", required=True)
  finalize_parser.add_argument("--toolchain-lock", required=True)
  finalize_parser.add_argument("--image-lock", required=True)
  finalize_parser.add_argument("--cache-directory", required=True)
  finalize_parser.add_argument("--docker", default="docker")
  finalize_parser.add_argument("--schema-dir", required=True)
  finalize_parser.add_argument("--output", required=True)

  build_parser = subparsers.add_parser("build")
  build_parser.add_argument("--bootstrap-manifest", required=True)
  build_parser.add_argument("--source-lock", required=True)
  build_parser.add_argument("--toolchain-lock", required=True)
  build_parser.add_argument("--image-lock", required=True)
  build_parser.add_argument("--source-directory", required=True)
  build_parser.add_argument("--cache-directory", required=True)
  build_parser.add_argument("--artifact-directory", required=True)
  build_parser.add_argument("--docker", default="docker")
  build_parser.add_argument("--schema-dir", required=True)
  build_parser.add_argument("--output", required=True)

  package_parser = subparsers.add_parser("package")
  package_parser.add_argument("--build-manifest", required=True)
  package_parser.add_argument("--bootstrap-manifest", required=True)
  package_parser.add_argument("--source-lock", required=True)
  package_parser.add_argument("--toolchain-lock", required=True)
  package_parser.add_argument("--image-lock", required=True)
  package_parser.add_argument("--cache-directory", required=True)
  package_parser.add_argument("--artifact-directory", required=True)
  package_parser.add_argument("--docker", default="docker")
  package_parser.add_argument("--schema-dir", required=True)
  package_parser.add_argument("--output", required=True)

  verify_parser = subparsers.add_parser("verify")
  verify_parser.add_argument("--artifact-manifest", required=True)
  verify_parser.add_argument("--reference-artifact-manifest", required=True)
  verify_parser.add_argument("--source-lock", required=True)
  verify_parser.add_argument("--toolchain-lock", required=True)
  verify_parser.add_argument("--image-lock", required=True)
  verify_parser.add_argument("--cache-directory", required=True)
  verify_parser.add_argument("--artifact-directory", required=True)
  verify_parser.add_argument("--reference-artifact-directory", required=True)
  verify_parser.add_argument("--release-policy", required=True)
  verify_parser.add_argument("--gate-result-directory", required=True)
  verify_parser.add_argument("--run-id", required=True)
  verify_parser.add_argument("--image")
  verify_parser.add_argument("--docker", default="docker")
  verify_parser.add_argument("--diffoscope", default="diffoscope")
  verify_parser.add_argument("--diffoscope-directory")
  verify_parser.add_argument("--schema-dir", required=True)
  verify_parser.add_argument("--repository-root", default=str(REPOSITORY_ROOT))
  verify_parser.add_argument("--output", required=True)

  args = parser.parse_args(argv)
  try:
    if args.command == "preflight-bootstrap":
      preflight_bootstrap(args)
    elif args.command == "bootstrap":
      bootstrap(args)
    elif args.command == "build":
      build(args)
    elif args.command == "package":
      package(args)
    elif args.command == "verify":
      verify(args)
    return 0
  except (BaselineError, ContractError) as error:
    print("offline baseline error: " + str(error), file=sys.stderr)
    return error.exit_code if isinstance(error, BaselineError) else 2


if __name__ == "__main__":
  sys.exit(main())
