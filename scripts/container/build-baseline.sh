#!/bin/sh
set -eu

test "${JETONLYOFFICE_NETWORK_POLICY:-}" = "none"
test -f /input/cache/bootstrap-manifest.json
mkdir -p /work/sources
cp -a /input/sources/. /work/sources/
build_tools=/work/sources/sources/build_tools
test -f "$build_tools/configure.py"

cd "$build_tools"
python3 configure.py \
  --update 0 \
  --branch detached \
  --clean 1 \
  --module server \
  --platform linux_64 \
  --sysroot 0
python3 make.py

test -d "$build_tools/out"
mkdir -p /output/build-output
cp -a "$build_tools/out/." /output/build-output/
python3 /jetonlyoffice/container/write-build-manifest.py
