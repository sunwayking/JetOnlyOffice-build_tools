#!/bin/sh
set -eu

test "${JETONLYOFFICE_NETWORK_POLICY:-}" = "none"
test -n "${JETONLYOFFICE_ARTIFACT_MANIFEST_PATH:-}"
test -n "${JETONLYOFFICE_PACKAGE_DRIVER_PATH:-}"
test -n "${JETONLYOFFICE_PACKAGE_DRIVER_MODE:-}"
driver=$JETONLYOFFICE_PACKAGE_DRIVER_PATH
case "$driver" in
  /artifacts/build-output/*) ;;
  *)
    echo "locked package driver path escapes build output" >&2
    exit 3
    ;;
esac
if test ! -x "$driver"; then
  echo "locked package driver is missing from build output" >&2
  exit 3
fi
actual_mode=$(stat -c '%a' "$driver")
case "$actual_mode" in
  ?) actual_mode="000$actual_mode" ;;
  ??) actual_mode="00$actual_mode" ;;
  ???) actual_mode="0$actual_mode" ;;
  ????) ;;
  *)
    echo "locked package driver mode cannot be read" >&2
    exit 3
    ;;
esac
if test "$actual_mode" != "$JETONLYOFFICE_PACKAGE_DRIVER_MODE"; then
  echo "locked package driver mode does not match build manifest" >&2
  exit 3
fi
exec "$driver" \
  --build-manifest /artifacts/build-manifest.json \
  --cache /input/cache \
  --work /work \
  --output /artifacts
