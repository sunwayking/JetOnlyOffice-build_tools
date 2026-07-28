#!/bin/sh
set -eu

test "${JETONLYOFFICE_NETWORK_POLICY:-}" = "none"
test -n "${JETONLYOFFICE_ARTIFACT_MANIFEST_PATH:-}"
driver=/artifacts/build-output/packaging/package.sh
if test ! -x "$driver"; then
  echo "locked package driver is missing from build output" >&2
  exit 3
fi
exec "$driver" \
  --build-manifest /artifacts/build-manifest.json \
  --cache /input/cache \
  --work /work \
  --output /artifacts
