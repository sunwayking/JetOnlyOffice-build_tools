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
for path in sorted(item for item in root.rglob("*") if item.is_file()):
  relative = path.relative_to(root).as_posix()
  mode = stat.S_IMODE(path.stat().st_mode)
  files.append({
    "path": "build-output/" + relative,
    "mode": format(mode, "04o"),
    "size": path.stat().st_size,
    "sha256": sha256(path),
  })
if not files:
  raise SystemExit("offline build produced no files")

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
  "files": files,
}
Path("/output/build-manifest.json").write_text(
  json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
  encoding="utf-8",
)
