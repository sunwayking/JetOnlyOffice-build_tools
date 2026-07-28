#!/usr/bin/env python3

import hashlib
import json
import os
from pathlib import Path
import stat


def sha256(path):
  digest = hashlib.sha256()
  with path.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
      digest.update(chunk)
  return digest.hexdigest()


root = Path("/output/build-output")
files = []
for path in sorted(
  item for item in root.rglob("*") if item.is_symlink() or item.is_file()
):
  relative = path.relative_to(root).as_posix()
  mode = stat.S_IMODE(path.lstat().st_mode)
  record = {
    "type": "symlink" if path.is_symlink() else "file",
    "path": "build-output/" + relative,
    "mode": format(mode, "04o"),
  }
  if path.is_symlink():
    target = os.readlink(path)
    target_bytes = target.encode("utf-8")
    record.update({
      "size": len(target_bytes),
      "sha256": hashlib.sha256(target_bytes).hexdigest(),
      "symlinkTarget": target,
    })
  else:
    record.update({
      "size": path.stat().st_size,
      "sha256": sha256(path),
    })
  files.append(record)
if not files:
  raise SystemExit("offline build produced no files")

driver_path = "build-output/packaging/package.sh"
driver = next((item for item in files if item["path"] == driver_path), None)
if driver is None:
  raise SystemExit("offline build did not produce the locked package driver")
if int(driver["mode"], 8) & 0o111 == 0:
  raise SystemExit("offline build package driver is not executable")

manifest = {
  "schemaVersion": 1,
  "manifestType": "build",
  "buildId": os.environ["JETONLYOFFICE_BUILD_ID"],
  "platform": "linux-amd64",
  "configuration": "Release",
  "sourceLockSha256": os.environ["JETONLYOFFICE_SOURCE_LOCK_SHA256"],
  "toolchainLockSha256": os.environ["JETONLYOFFICE_TOOLCHAIN_LOCK_SHA256"],
  "imageLockSha256": os.environ["JETONLYOFFICE_IMAGE_LOCK_SHA256"],
  "builderImageDigest": os.environ["JETONLYOFFICE_BUILDER_IMAGE_DIGEST"],
  "sourceDateEpoch": int(os.environ["SOURCE_DATE_EPOCH"]),
  "environment": {
    "timezone": "UTC",
    "locale": "C.UTF-8",
    "umask": "022",
    "pythonHashSeed": "0",
    "buildPath": "/work",
    "concurrency": 4,
  },
  "network": "none",
  "packageDriver": {
    "type": "file",
    "path": driver["path"],
    "mode": driver["mode"],
    "size": driver["size"],
    "sha256": driver["sha256"],
  },
  "files": files,
}
output = Path(os.environ["JETONLYOFFICE_BUILD_MANIFEST_PATH"])
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(
  json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
  encoding="utf-8",
)
