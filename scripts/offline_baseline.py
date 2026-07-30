#!/usr/bin/env python3

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
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
  load_contract(
    args.toolchain_lock,
    "toolchain-lock",
    "locked toolchain input",
    args.schema_dir,
  )
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
  return bool(is_junction and is_junction())


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
  cache_root = Path(cache_root).resolve()
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

  cache_directory = Path(args.cache_directory).resolve()
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
  cache_directory = Path(cache_directory).resolve()
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


@contextmanager
def locked_cache_view(toolchain_lock, cache_directory, bootstrap_manifest, consumers):
  cache_directory = Path(cache_directory).resolve()
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


def verify_provenance_artifact(manifest, artifact_root, source_lock):
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
  external = value.get("predicate", {}).get("buildDefinition", {}).get(
    "externalParameters", {}
  )
  if external.get("sourceLockSha256") != canonical_sha256(source_lock):
    raise BaselineError("provenance artifact source lock binding does not match", 4)
  if external.get("network") != "none":
    raise BaselineError("provenance artifact does not attest an offline build", 4)


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


def verify_supply_chain_artifacts(manifest, artifact_root, source_lock):
  for artifact_type in (
    "deb", "rootfs", "oci", "source", "spdx", "cyclonedx", "provenance",
    "checksums", "licenses", "notice",
  ):
    one_artifact(manifest, artifact_type)
  verify_checksums_artifact(manifest, artifact_root)
  verify_provenance_artifact(manifest, artifact_root, source_lock)
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

  verify_supply_chain_artifacts(artifact_manifest, artifact_directory, source_lock)
  verify_supply_chain_artifacts(
    reference_manifest, args.reference_artifact_directory, source_lock
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
  verify_parser.add_argument("--artifact-directory", required=True)
  verify_parser.add_argument("--reference-artifact-directory", required=True)
  verify_parser.add_argument("--release-policy", required=True)
  verify_parser.add_argument("--gate-result-directory", required=True)
  verify_parser.add_argument("--run-id", required=True)
  verify_parser.add_argument("--image")
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
