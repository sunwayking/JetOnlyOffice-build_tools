#!/usr/bin/env python3

import argparse
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from contracts.contract_tool import ContractError, load_json, validate_contract
from contracts.contract_tool import canonical_json_bytes, canonical_sha256
from source_resolver import ResolutionError, verify_materialized
from qa.qa_tool import aggregate_release_evidence


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


def write_canonical(path, value):
  path = Path(path)
  path.parent.mkdir(parents=True, exist_ok=True)
  temporary = path.with_name(path.name + ".tmp")
  temporary.write_bytes(canonical_json_bytes(value) + b"\n")
  os.replace(temporary, path)


def prepare_fresh_output(path, root, description):
  root = Path(root).resolve()
  output = Path(path)
  if output.is_symlink():
    raise BaselineError(f"{description} must not be a symbolic link: {output}", 2)
  output = output.resolve()
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
  toolchain_files = []
  for tool in toolchain_lock["tools"]:
    relative_path = Path("toolchain") / tool["id"] / tool["sha256"]
    path = cache_directory / relative_path
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
    pinned = image["reference"] + "@" + image["digest"]
    run_external(
      [docker, "pull", "--platform", "linux/amd64", pinned],
      f"locked image pull for {image['id']}",
    )
    platform = run_external(
      [docker, "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", pinned],
      f"locked image inspect for {image['id']}",
    )
    if platform != "linux/amd64":
      raise BaselineError(
        f"locked image platform mismatch for {image['id']}: expected linux/amd64, got {platform}",
        3,
      )
    image_records.append({
      "id": image["id"],
      "role": image["role"],
      "reference": image["reference"],
      "digest": image["digest"],
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
  expected = []
  for tool in toolchain_lock["tools"]:
    relative_path = Path("toolchain") / tool["id"] / tool["sha256"]
    path = Path(cache_directory) / relative_path
    if path.is_symlink():
      raise BaselineError(f"locked toolchain cache must not be a symbolic link: {path}", 3)
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
def locked_cache_view(toolchain_lock, cache_directory, bootstrap_manifest):
  with tempfile.TemporaryDirectory(prefix="jetonlyoffice-locked-cache-") as directory:
    root = Path(directory)
    for tool in toolchain_lock["tools"]:
      relative = Path("toolchain") / tool["id"] / tool["sha256"]
      source = Path(cache_directory) / relative
      destination = root / relative
      destination.parent.mkdir(parents=True, exist_ok=True)
      try:
        os.link(source, destination)
      except OSError:
        shutil.copyfile(source, destination)
      if destination.stat().st_size != tool["size"] or sha256_file(destination) != tool["sha256"]:
        raise BaselineError(f"locked toolchain cache view mismatch for {tool['id']}", 3)
    write_canonical(root / "bootstrap-manifest.json", bootstrap_manifest)
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
  artifact_directory.mkdir(parents=True, exist_ok=True)
  output, output_relative = prepare_fresh_output(
    args.output, artifact_directory, "offline build output"
  )
  work_directory = artifact_directory / "work"
  work_directory.mkdir(parents=True, exist_ok=True)
  with locked_cache_view(toolchain_lock, cache_directory, bootstrap_manifest) as cache_view:
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
      "type=bind,src=" + cache_view.as_posix() + ",dst=/input/cache,readonly",
      "--mount",
      "type=bind,src=" + artifact_directory.as_posix() + ",dst=/output",
      "--mount",
      "type=bind,src=" + work_directory.as_posix() + ",dst=/work",
      "--mount",
      "type=bind,src=" + container_scripts.as_posix() + ",dst=/jetonlyoffice/container,readonly",
      builder["reference"] + "@" + builder["digest"],
      "/bin/sh",
      "/jetonlyoffice/container/build-baseline.sh",
    ]
    run_external(command, "offline build container", exit_code=4)
  output = require_file(output, "offline build output", exit_code=4)
  try:
    manifest = load_json(output)
    validate_contract(manifest, "build-manifest", args.schema_dir)
  except ContractError as error:
    raise BaselineError(f"offline build output is invalid: {error}", 4) from error
  verify_build_bindings(manifest, source_lock, toolchain_lock, image_lock, 4)
  verify_manifest_files(manifest, artifact_directory, "offline build output")


def verify_manifest_files(manifest, root, description):
  root = Path(root).resolve()
  records = manifest.get("files", manifest.get("artifacts", []))
  for record in records:
    path = (root / record["path"]).resolve()
    try:
      path.relative_to(root)
    except ValueError as error:
      raise BaselineError(f"{description} path escapes root: {record['path']}", 2) from error
    if not path.is_file():
      raise BaselineError(f"{description} is missing: {path}", 3)
    size = path.stat().st_size
    if size != record["size"]:
      raise BaselineError(
        f"{description} size mismatch for {record['path']}: expected {record['size']}, got {size}",
        3,
      )
    digest = sha256_file(path)
    if digest != record["sha256"]:
      raise BaselineError(
        f"{description} digest mismatch for {record['path']}: expected {record['sha256']}, got {digest}",
        3,
      )


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
  artifact_directory = Path(args.artifact_directory).resolve()
  build_output_directory = artifact_directory / "build-output"
  if not build_output_directory.is_dir():
    raise BaselineError(f"locked build output is missing: {build_output_directory}", 3)
  verify_manifest_files(build_manifest, artifact_directory, "locked build output")
  output, output_relative = prepare_fresh_output(
    args.output, artifact_directory, "offline package output"
  )

  cache_directory = Path(args.cache_directory).resolve()
  if not cache_directory.is_dir():
    raise BaselineError(f"locked package cache is missing: {cache_directory}", 3)
  work_directory = artifact_directory / "package-work"
  work_directory.mkdir(parents=True, exist_ok=True)
  container_scripts = Path(__file__).resolve().parent / "container"
  with locked_cache_view(toolchain_lock, cache_directory, bootstrap_manifest) as cache_view:
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
      "JETONLYOFFICE_ARTIFACT_MANIFEST_PATH=/artifacts/" + output_relative,
      "--mount",
      "type=bind,src=" + artifact_directory.as_posix() + ",dst=/artifacts",
      "--mount",
      "type=bind,src=" + build_output_directory.as_posix() + ",dst=/artifacts/build-output,readonly",
      "--mount",
      "type=bind,src=" + Path(args.build_manifest).resolve().as_posix() + ",dst=/artifacts/build-manifest.json,readonly",
      "--mount",
      "type=bind,src=" + cache_view.as_posix() + ",dst=/input/cache,readonly",
      "--mount",
      "type=bind,src=" + work_directory.as_posix() + ",dst=/work",
      "--mount",
      "type=bind,src=" + container_scripts.as_posix() + ",dst=/jetonlyoffice/container,readonly",
      builder["reference"] + "@" + builder["digest"],
      "/bin/sh",
      "/jetonlyoffice/container/package-baseline.sh",
    ]
    run_external(command, "offline package container", exit_code=4)
  output = require_file(output, "offline package output", exit_code=4)
  try:
    manifest = load_json(output)
    validate_contract(manifest, "artifact-manifest", args.schema_dir)
  except ContractError as error:
    raise BaselineError(f"offline package output is invalid: {error}", 4) from error
  if manifest["sourceLockSha256"] != canonical_sha256(source_lock):
    raise BaselineError("artifact manifest source lock does not match the lock", 4)
  if manifest["buildManifestSha256"] != canonical_sha256(build_manifest):
    raise BaselineError("artifact manifest build input does not match the build manifest", 4)
  verify_manifest_files(manifest, artifact_directory, "packaged artifact")


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
  for field in ("releaseId", "productVersion", "platform", "sourceLockSha256"):
    if reference_manifest[field] != artifact_manifest[field]:
      raise BaselineError(f"independent artifact manifest {field} does not match", 4)
  for artifact_type in ("deb", "rootfs", "oci"):
    primary = [item for item in artifact_manifest["artifacts"] if item["type"] == artifact_type]
    reference = [item for item in reference_manifest["artifacts"] if item["type"] == artifact_type]
    if len(primary) != 1 or len(reference) != 1:
      raise BaselineError(f"expected exactly one {artifact_type} artifact per build", 4)
    if primary[0]["sha256"] != reference[0]["sha256"]:
      raise BaselineError(f"REPRODUCIBILITY_MISMATCH: {artifact_type} SHA-256 differs", 4)
    if artifact_type == "oci" and primary[0]["ociDigest"] != reference[0]["ociDigest"]:
      raise BaselineError("REPRODUCIBILITY_MISMATCH: OCI digest differs", 4)

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
  verify_parser.add_argument("--schema-dir", required=True)
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
