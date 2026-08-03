#!/bin/sh
set -eu

test "${JETONLYOFFICE_NETWORK_POLICY:-}" = "none"
test -f /input/cache/bootstrap-manifest.json
test -f /input/sources.lock.json
test -f /input/toolchain.lock.json
test -f /input/images.lock.json
mkdir -p /work/sources
# Bind-mounted inputs can be owned by a host UID that the builder cannot
# reproduce. Preserve modes and links, but never request an ownership change.
cp -a --no-preserve=ownership /input/sources/. /work/sources/
. /jetonlyoffice/container/materialize-toolchain.sh /input/cache/materialization-plan.tsv
build_tools=/work/sources/sources/build_tools
test -f "$build_tools/configure.py"
python=$build_tools/tools/linux/python3/bin/python3
if test ! -x "$python"; then
  echo "locked materialized Python is missing" >&2
  exit 3
fi

"$python" /jetonlyoffice/container/prepare-source-archive.py \
  --source /work/sources \
  --manifest /work/sources/source-tree-manifest.json
cp /input/sources.lock.json /work/sources/sources.lock.json
cp /input/toolchain.lock.json /work/sources/toolchain.lock.json
cp /input/images.lock.json /work/sources/images.lock.json
chmod 0644 \
  /work/sources/sources.lock.json \
  /work/sources/toolchain.lock.json \
  /work/sources/images.lock.json
mkdir -p /output/build-output
source_tar=/work/jetonlyoffice-source.tar
tar \
  --sort=name \
  --mtime="@$SOURCE_DATE_EPOCH" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  --format=posix \
  --pax-option=delete=atime,delete=ctime \
  --exclude=.git \
  --exclude='*/.git' \
  -cf "$source_tar" \
  -C /work/sources .
zstd --quiet --threads=1 -19 -o /output/build-output/source-archive.tar.zst \
  < "$source_tar"
rm -f \
  "$source_tar" \
  /work/sources/sources.lock.json \
  /work/sources/toolchain.lock.json \
  /work/sources/images.lock.json

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
cp -a --no-preserve=ownership "$build_tools/out/." /output/build-output/

mkdir -p /output/build-output/packaging
cp "$build_tools/scripts/container/package-driver.py" \
  /output/build-output/packaging/package-driver.py
cp "$build_tools/scripts/cef_evidence.py" \
  /output/build-output/packaging/cef_evidence.py
cp "$build_tools/scripts/container/jwt-entrypoint.sh" \
  /output/build-output/packaging/jwt-entrypoint.sh
cat > /output/build-output/packaging/package.sh <<'EOF'
#!/bin/sh
set -eu
exec python3 "$(dirname "$0")/package-driver.py" "$@"
EOF
chmod 0755 \
  /output/build-output/packaging/package.sh \
  /output/build-output/packaging/package-driver.py \
  /output/build-output/packaging/jwt-entrypoint.sh

"$python" /jetonlyoffice/container/write-build-manifest.py
