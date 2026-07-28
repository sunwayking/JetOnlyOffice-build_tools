#!/usr/bin/env python3

import argparse
import hashlib
from pathlib import Path
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
  sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.contracts.contract_tool import canonical_json_bytes


class ManifestError(ValueError):
  """Raised when the authoritative design-document set is invalid."""


def _digest(path):
  digest = hashlib.sha256()
  with path.open("rb") as source:
    for block in iter(lambda: source.read(1024 * 1024), b""):
      digest.update(block)
  return digest.hexdigest()


def build_manifest(root):
  root = root.resolve()
  context = root / "CONTEXT.md"
  docs = root / "docs"
  if not context.is_file():
    raise ManifestError(f"required design context is missing: {context}")
  if not docs.is_dir():
    raise ManifestError(f"required design directory is missing: {docs}")
  if context.is_symlink() or docs.is_symlink():
    raise ManifestError("symbolic links are not allowed in the authoritative set")

  source_files = [context]
  for path in docs.rglob("*"):
    if path.is_symlink():
      raise ManifestError(
        f"symbolic links are not allowed in the authoritative set: {path}",
      )
    if path.is_file():
      source_files.append(path)
  files = []
  for path in source_files:
    relative = path.relative_to(root).as_posix()
    files.append({
      "path": relative,
      "sha256": _digest(path),
      "size": path.stat().st_size,
    })
  files.sort(key=lambda item: item["path"].encode("utf-8"))
  return {
    "schemaVersion": 1,
    "manifestType": "authoritative-design-docs",
    "hashAlgorithm": "sha256",
    "files": files,
  }


def _validate_manifest_location(root, manifest_path):
  root = root.resolve()
  manifest_path = manifest_path.resolve()
  if (
    manifest_path == root / "CONTEXT.md"
    or manifest_path.is_relative_to(root / "docs")
  ):
    raise ManifestError(
      "manifest must be outside CONTEXT.md and docs to avoid self-reference",
    )


def write_manifest(root, manifest_path):
  _validate_manifest_location(root, manifest_path)
  value = build_manifest(root)
  manifest_path.parent.mkdir(parents=True, exist_ok=True)
  manifest_path.write_bytes(canonical_json_bytes(value) + b"\n")


def verify_manifest(root, manifest_path):
  _validate_manifest_location(root, manifest_path)
  expected = canonical_json_bytes(build_manifest(root)) + b"\n"
  if manifest_path.read_bytes() != expected:
    raise ManifestError(
      "manifest does not match the authoritative design-document bytes or file set",
    )


def build_parser():
  parser = argparse.ArgumentParser(
    description="Generate the JetOnlyOffice authoritative design-document manifest",
  )
  subparsers = parser.add_subparsers(dest="command", required=True)
  generate = subparsers.add_parser("generate")
  generate.add_argument("--root", type=Path, required=True)
  generate.add_argument("--manifest", type=Path, required=True)
  verify = subparsers.add_parser("verify")
  verify.add_argument("--root", type=Path, required=True)
  verify.add_argument("--manifest", type=Path, required=True)
  return parser


def main(argv=None):
  args = build_parser().parse_args(argv)
  try:
    if args.command == "generate":
      write_manifest(args.root, args.manifest)
    elif args.command == "verify":
      verify_manifest(args.root, args.manifest)
    else:
      raise AssertionError(f"unhandled command: {args.command}")
  except (ManifestError, OSError) as error:
    print(f"design-docs: error: {error}", file=sys.stderr)
    return 1
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
