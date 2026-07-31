#!/usr/bin/env python3
"""Normalize a verified source workspace for deterministic source archiving."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat


def fail(message):
  raise SystemExit("source archive preparation failed: " + message)


def safe_path(root, relative, description):
  root = Path(root).resolve()
  path = root / PurePosixPath(relative)
  try:
    path.resolve(strict=False).relative_to(root)
  except ValueError:
    fail(f"{description} escapes the source root: {relative}")
  return path


def path_is_alias(path):
  return Path(path).is_symlink()


def normalize_repository(root, repository):
  checkout = safe_path(root, repository["checkoutPath"], repository["id"])
  if not checkout.is_dir() or path_is_alias(checkout):
    fail(f"{repository['id']} checkout is missing or aliased")
  checkout.chmod(0o755)
  expected = {}
  for entry in repository["entries"]:
    path = entry["path"]
    if path in expected:
      fail(f"{repository['id']} has duplicate manifest path: {path}")
    expected[path] = entry

  def visit(directory, prefix=()):
    try:
      entries = sorted(os.scandir(directory), key=lambda item: item.name)
    except OSError as error:
      fail(f"cannot inspect {directory}: {error}")
    for item in entries:
      relative_parts = prefix + (item.name,)
      if relative_parts == (".git",):
        if item.is_symlink() or not item.is_dir(follow_symlinks=False):
          fail(f"{repository['id']} .git metadata is not a directory")
        continue
      relative = PurePosixPath(*relative_parts).as_posix()
      record = expected.get(relative)
      if record is None:
        fail(f"{repository['id']} contains unlocked path: {relative}")
      record_type = record["type"]
      path = Path(item.path)
      if record_type == "directory":
        if item.is_symlink() or not item.is_dir(follow_symlinks=False):
          fail(f"{repository['id']}:{relative}: expected directory")
        path.chmod(0o755)
        visit(path, relative_parts)
      elif record_type == "file":
        if item.is_symlink() or not item.is_file(follow_symlinks=False):
          fail(f"{repository['id']}:{relative}: expected regular file")
        path.chmod(0o755 if record["mode"] == "100755" else 0o644)
      elif record_type == "symlink":
        if item.is_symlink():
          target = os.fsencode(os.readlink(path))
        elif item.is_file(follow_symlinks=False):
          target = path.read_bytes()
          path.unlink()
          os.symlink(target, os.fsencode(path))
        else:
          fail(f"{repository['id']}:{relative}: expected symlink")
        if (
          len(target) != record["size"]
          or hashlib.sha256(target).hexdigest() != record["sha256"]
        ):
          fail(f"{repository['id']}:{relative}: symlink blob does not match")
      elif record_type == "gitlink":
        if item.is_symlink() or not item.is_dir(follow_symlinks=False):
          fail(f"{repository['id']}:{relative}: expected gitlink directory")
        try:
          if any(os.scandir(path)):
            fail(f"{repository['id']}:{relative}: gitlink directory is not empty")
        except OSError as error:
          fail(f"cannot inspect gitlink directory {path}: {error}")
        path.chmod(0o755)
      else:
        fail(f"{repository['id']}:{relative}: unsupported entry type")

  visit(checkout)
  missing = sorted(
    path for path, record in expected.items()
    if not os.path.lexists(checkout / PurePosixPath(path))
  )
  if missing:
    fail(f"{repository['id']} is missing locked paths: {', '.join(missing)}")


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("--source", required=True)
  parser.add_argument("--manifest", required=True)
  args = parser.parse_args()
  root = Path(args.source).resolve()
  manifest_path = Path(args.manifest).resolve()
  try:
    manifest_path.relative_to(root)
  except ValueError:
    fail("source tree manifest is outside the source root")
  try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
  except (OSError, UnicodeError, json.JSONDecodeError) as error:
    fail(f"source tree manifest is invalid: {error}")
  if manifest.get("schemaVersion") != 1 \
      or manifest.get("manifestType") != "source-tree":
    fail("source tree manifest identity is invalid")
  repositories = manifest.get("repositories")
  if not isinstance(repositories, list) or not repositories:
    fail("source tree manifest has no repositories")
  for repository in repositories:
    normalize_repository(root, repository)
  manifest_path.chmod(0o644)
  for path in sorted(root.rglob("*"), key=lambda item: len(item.parts)):
    if path.is_dir() and not path.is_symlink():
      path.chmod(0o755)


if __name__ == "__main__":
  main()
