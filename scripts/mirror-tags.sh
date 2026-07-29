#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: mirror-tags.sh <source-git-dir> <target-url>" >&2
  exit 2
fi

source_git_dir="$1"
target_url="$2"
batch_size="${MIRROR_TAG_BATCH_SIZE:-100}"

if [[ ! "${batch_size}" =~ ^[1-9][0-9]*$ ]]; then
  echo "mirror tags error: MIRROR_TAG_BATCH_SIZE must be a positive integer" >&2
  exit 2
fi

if [[ "$(git -C "${source_git_dir}" rev-parse --is-bare-repository)" != "true" ]]; then
  echo "mirror tags error: source must be a bare Git repository" >&2
  exit 2
fi

declare -A source_tags=()
declare -A target_tags=()

while read -r ref object; do
  [[ -n "${ref}" ]] || continue
  source_tags["${ref}"]="${object}"
done < <(
  git -C "${source_git_dir}" for-each-ref \
    --sort=refname --format='%(refname) %(objectname)' refs/tags
)

while read -r object ref; do
  [[ -n "${ref}" ]] || continue
  target_tags["${ref}"]="${object}"
done < <(git ls-remote --refs --tags "${target_url}")

for ref in "${!target_tags[@]}"; do
  if [[ ! -v "source_tags[${ref}]" ]]; then
    echo "mirror tags error: target has unexpected tag ${ref}" >&2
    exit 3
  fi
done

pending=()
for ref in "${!source_tags[@]}"; do
  if [[ -v "target_tags[${ref}]" ]]; then
    if [[ "${target_tags[${ref}]}" != "${source_tags[${ref}]}" ]]; then
      echo "mirror tags error: target tag differs: ${ref}" >&2
      exit 3
    fi
    continue
  fi
  pending+=("${ref}:${ref}")
done

if [[ "${#pending[@]}" -gt 0 ]]; then
  mapfile -t pending < <(printf '%s\n' "${pending[@]}" | LC_ALL=C sort)
fi

batch_count=0
for ((offset = 0; offset < ${#pending[@]}; offset += batch_size)); do
  batch=("${pending[@]:offset:batch_size}")
  git -C "${source_git_dir}" push --atomic "${target_url}" "${batch[@]}"
  batch_count=$((batch_count + 1))
done

printf 'tag sync: source=%d target=%d pending=%d batches=%d\n' \
  "${#source_tags[@]}" \
  "${#target_tags[@]}" \
  "${#pending[@]}" \
  "${batch_count}"
