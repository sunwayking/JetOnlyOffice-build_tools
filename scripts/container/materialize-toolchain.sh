#!/bin/sh
set -eu

test "${JETONLYOFFICE_NETWORK_POLICY:-}" = "none"
plan=${1:-/input/cache/materialization-plan.tsv}
test -s "$plan"

cache_root=/input/cache
toolchain_root=/work/toolchain-root
sources_root=/work/sources
offline_cache_root=/work/offline-cache
mkdir -p "$toolchain_root" "$sources_root" "$offline_cache_root"

export JETONLYOFFICE_TOOLCHAIN_ROOT=$toolchain_root
export JETONLYOFFICE_OFFLINE_CACHE=$offline_cache_root
export PATH="$toolchain_root/usr/local/bin:$toolchain_root/usr/bin:$toolchain_root/bin:$PATH"
export LD_LIBRARY_PATH="$toolchain_root/usr/local/lib:$toolchain_root/usr/lib/x86_64-linux-gnu:$toolchain_root/usr/lib:$toolchain_root/lib/x86_64-linux-gnu:$toolchain_root/lib"
export PKG_CONFIG_PATH="$toolchain_root/usr/local/lib/pkgconfig:$toolchain_root/usr/lib/x86_64-linux-gnu/pkgconfig:$toolchain_root/usr/lib/pkgconfig"
export CMAKE_PREFIX_PATH="$toolchain_root/usr/local:$toolchain_root/usr"
export NPM_CONFIG_CACHE="$offline_cache_root/npm"
export PIP_FIND_LINKS="$offline_cache_root/pip"

reject_alias_path() {
  alias_root=$1
  alias_relative=$2
  alias_current=$alias_root
  alias_old_ifs=$IFS
  IFS=/
  set -- $alias_relative
  IFS=$alias_old_ifs
  for alias_part do
    alias_current=$alias_current/$alias_part
    if test -L "$alias_current"; then
      echo "locked materialization path contains a symbolic link: $alias_current" >&2
      return 3
    fi
  done
}

tab=$(printf '\t')
while IFS="$tab" read -r archive_type source root destination strip_components mode; do
  test -n "$archive_type"
  case "$source" in
    toolchain/*/*) ;;
    *)
      echo "locked materialization source is invalid: $source" >&2
      return 3
      ;;
  esac
  case "$destination" in
    ""|/*|../*|*/../*|*/..|*\\*)
      echo "locked materialization destination is invalid: $destination" >&2
      return 3
      ;;
  esac
  case "$strip_components" in
    ""|*[!0-9]*)
      echo "locked materialization strip count is invalid" >&2
      return 3
      ;;
  esac

  source_path=$cache_root/$source
  test -f "$source_path"
  case "$root" in
    toolchain) destination_root=$toolchain_root ;;
    sources) destination_root=$sources_root ;;
    offline-cache) destination_root=$offline_cache_root ;;
    *)
      echo "locked materialization root is invalid: $root" >&2
      return 3
      ;;
  esac
  target=$destination_root/$destination
  reject_alias_path "$destination_root" "$destination"

  case "$archive_type" in
    file)
      test "$strip_components" = 0
      case "$mode" in
        [0-7][0-7][0-7][0-7]) ;;
        *)
          echo "locked materialization file mode is invalid" >&2
          return 3
          ;;
      esac
      mkdir -p "$(dirname "$target")"
      if test -e "$target" || test -L "$target"; then
        cmp -s "$source_path" "$target" || {
          echo "locked materialization file conflicts with an existing path" >&2
          return 3
        }
      else
        cp "$source_path" "$target"
      fi
      chmod "$mode" "$target"
      ;;
    deb)
      test "$strip_components" = 0
      test "$mode" = -
      mkdir -p "$target"
      dpkg-deb -x "$source_path" "$target"
      ;;
    tar|tar-gzip|tar-xz)
      test "$mode" = -
      mkdir -p "$target"
      case "$archive_type" in
        tar) tar_flags=-xf ;;
        tar-gzip) tar_flags=-xzf ;;
        tar-xz) tar_flags=-xJf ;;
      esac
      if test "$strip_components" = 0; then
        tar "$tar_flags" "$source_path" -C "$target"
      else
        tar "$tar_flags" "$source_path" -C "$target" \
          --strip-components="$strip_components"
      fi
      ;;
    *)
      echo "locked materialization type is invalid: $archive_type" >&2
      return 3
      ;;
  esac
done < "$plan"
