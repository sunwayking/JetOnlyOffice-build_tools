#!/bin/sh
set -eu

test "${JETONLYOFFICE_NETWORK_POLICY:-}" = "none"
test -n "${JETONLYOFFICE_ARTIFACT_MANIFEST_PATH:-}"
test -n "${JETONLYOFFICE_PACKAGE_DRIVER_PATH:-}"
test -n "${JETONLYOFFICE_PACKAGE_DRIVER_MODE:-}"
test -n "${JETONLYOFFICE_SOURCE_LOCK_PATH:-}"
test -n "${JETONLYOFFICE_TOOLCHAIN_LOCK_PATH:-}"
test -n "${JETONLYOFFICE_IMAGE_LOCK_PATH:-}"
test -n "${JETONLYOFFICE_RUNTIME_ROOTFS_PATH:-}"
. /jetonlyoffice/container/materialize-toolchain.sh /input/cache/materialization-plan.tsv
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
  --source-lock "$JETONLYOFFICE_SOURCE_LOCK_PATH" \
  --toolchain-lock "$JETONLYOFFICE_TOOLCHAIN_LOCK_PATH" \
  --image-lock "$JETONLYOFFICE_IMAGE_LOCK_PATH" \
  --runtime-rootfs "$JETONLYOFFICE_RUNTIME_ROOTFS_PATH" \
  --cache /input/cache \
  --work /work \
  --output /artifacts \
  --output-manifest "${JETONLYOFFICE_ARTIFACT_MANIFEST_PATH#/artifacts/}"
