#!/bin/sh
set -eu

test "${JETONLYOFFICE_NETWORK_POLICY:-}" = "none"
test -f /input/cache/bootstrap-manifest.json
mkdir -p /work/sources
cp -a /input/sources/. /work/sources/
. /jetonlyoffice/container/materialize-toolchain.sh /input/cache/materialization-plan.tsv
build_tools=/work/sources/sources/build_tools
test -f "$build_tools/configure.py"
python=$build_tools/tools/linux/python3/bin/python3
if test ! -x "$python"; then
  echo "locked materialized Python is missing" >&2
  exit 3
fi

cd "$build_tools"
"$python" configure.py \
  --update 0 \
  --branch detached \
  --clean 1 \
  --module server \
  --platform linux_64 \
  --sysroot 0
"$python" make.py

test -d "$build_tools/out"
mkdir -p /output/build-output
cp -a "$build_tools/out/." /output/build-output/
"$python" /jetonlyoffice/container/write-build-manifest.py
