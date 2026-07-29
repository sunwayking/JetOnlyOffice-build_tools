# Locked offline baseline

JetOnlyOffice exposes four PowerShell entrypoints for the Ubuntu 24.04
`linux/amd64` release pipeline:

```powershell
.\scripts\bootstrap-source.ps1
.\scripts\build.ps1 -Platform linux-amd64 -Configuration Release
.\scripts\package.ps1 -Platform linux-amd64
.\scripts\verify.ps1 -Image sha256:<digest>
```

`bootstrap-source.ps1` is the only entrypoint allowed to use the network. It
validates all three lock contracts before resolving sources, downloads missing
toolchain bytes directly from their reviewed HTTPS URLs, and accepts them only
when both the declared size and SHA-256 match. Existing mismatched cache files,
redirects outside credential-free HTTPS, ancestor symlink or junction aliases,
and concurrent cache races fail closed. It pulls every image by immutable
repository digest for `linux/amd64` and independently checks the exact local
repository digest and config digest. It writes `cache/bootstrap-manifest.json`
only after all inputs are present and verified.

Toolchain files use this deterministic cache path:

```text
cache/toolchain/<tool-id>/<sha256>
```

`build.ps1` and `package.ps1` revalidate the bootstrap manifest, all three
lock digests, the locked toolchain bytes, and their complete upstream
manifests before invoking Docker. Only a copied temporary cache view containing
the current bootstrap manifest, canonical toolchain lock, consumer-specific
inventory, deterministic materialization plan, and bytes declared for that
entrypoint is mounted. Build receives only `build` inputs; package receives
only `package` and `runtime` inputs. Other shared-cache files are not visible,
and hard links cannot expose the private view to later cache mutation.
Their containers use the digest-pinned builder image with `--pull never`,
`--network none`, `--platform linux/amd64`, a read-only root filesystem, and
read-only source, cache, and driver mounts.

Every toolchain lock record declares how its exact bytes are materialized as a
regular file, DEB payload, or tar archive. The target is restricted to the
private toolchain root, copied source workspace, or offline package cache under
`/work`; normalized paths and parent symbolic links are rejected. Build and
package set npm, pip, Cargo, Yarn, and Git to fail-closed offline modes before
running upstream code. The build entrypoint invokes only the locked Python
materialized at
`sources/build_tools/tools/linux/python3/bin/python3`; the minimal Ubuntu image
cannot silently supply a host or image Python fallback.

Each container invocation receives new staging and work directories. The
expected output manifest must resolve inside the artifact root and any
previous manifest at that path is removed. The build manifest must bind one
executable package driver to an identical file record. Package execution
receives that exact path and declared mode, and rejects a missing,
non-executable, differently hashed, or differently permissioned driver. Files
are validated entirely in staging, promoted only when every JSON contract,
lock binding, size, and SHA-256 check passes. Parent symlink and junction
aliases, dangling or cyclic links, and artifact paths that conflict with the
final manifest are rejected. Regular files and relative in-root symbolic links
have distinct manifest records, so promotion moves links themselves instead of
resolving and moving their targets. The canonical manifest is written last.
Existing destination files cause a blocking failure instead of being reused or
overwritten.

## Locked image facts

The committed image lock records these public `linux/amd64` inputs:

| Role | Reference | Repository digest | Config digest |
|---|---|---|---|
| builder | `ubuntu:24.04` | `sha256:4fbb8e6a...7092d90` | `sha256:ef91e4b1...65bc4` |
| runtime | `ubuntu:24.04` | `sha256:4fbb8e6a...7092d90` | `sha256:ef91e4b1...65bc4` |
| buildkit | `moby/buildkit:v0.31.1` | `sha256:6b59b7df...99c03a` | `sha256:61b4b32f...ad249` |
| dockerfile frontend | `docker/dockerfile:1.19.0` | `sha256:b6afd424...4e39b6` | `sha256:6742480c...5c680e` |

The full values are authoritative only in `locks/images.lock.json`. The Ubuntu
builder record is a locked minimal base; it does not contain Python or the
DocumentServer compiler stack. The cache-to-workspace materialization method is
implemented and exercised in the locked Ubuntu image, but a reviewed complete
toolchain lock and all corresponding cached bytes remain required before the
baseline can run.

`verify.ps1` checks every packaged file, compares DEB, rootfs, and OCI
SHA-256 values against an independent clean build, binds the requested OCI
digest, and delegates release evidence aggregation to the fail-closed QA
contract. Missing evidence returns exit code 3. A failed or incomplete
blocking gate writes `release-evidence.json` with outcome `BLOCKED` and returns
exit code 4.

## Current blocking state

This branch does not contain or generate a formal `locks/sources.lock.json`.
The source resolver still reports `LICENSE_INCOMPLETE` for:

- `build-tools-data`
- `core-fonts`
- `dictionaries`

The locked GLEW archive and six font components now have payload-complete,
machine-verified primary evidence. The remaining blockers are Android, CEF,
Python, Qt, and sysroot payloads; six font components; and the Azerbaijani and
Russian dictionary packs enumerated in `locks/README.md`. Partial evidence does
not turn any of the three repositories into a repository-wide declaration.

The image lock and offline materializer are concrete and locally reverified.
The formal toolchain lock, its complete Python/apt/npm/pkg/Qt/native dependency
cache, and a real package driver produced by the locked source build remain
prerequisites. The current upstream build does not produce
`build-output/packaging/package.sh`, so manifest generation must stop instead
of inventing DEB/rootfs/OCI outputs. Until those inputs are reviewed and
published, the public entrypoints must stop before producing a release
candidate. Placeholder locks, `NOASSERTION`, upstream fallbacks, and online
build/package retries are not supported.

The stable exit codes are:

- `0`: success
- `2`: invocation or contract error
- `3`: locked input missing or mismatched
- `4`: build, package, reproducibility, or release gate failure
