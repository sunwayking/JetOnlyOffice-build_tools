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
The `@yao-pkg/pkg` runtime cache is likewise isolated at
`/work/offline-cache/pkg` through `PKG_CACHE_PATH`; package binaries must be
locked and downloaded during bootstrap, then materialized there before build
rather than fetched on the first `pkg` invocation.

The build entrypoint also emits a deterministic source snapshot and the
executable `build-output/packaging/package.sh` driver. The driver and its JWT
entrypoint are copied from the locked `build_tools` source tree and included in
the build manifest. Package execution invokes that exact driver after
materializing the package/runtime toolchain inputs. It receives the source,
toolchain, image, and runtime-rootfs locks as read-only inputs and emits the
DEB, normalized rootfs archive, OCI image layout, source archive, SPDX,
CycloneDX, SLSA provenance, and checksums manifest.

Repository-level and component-scoped license records are both first-class
source-lock inputs. Packaging copies a declared repository license or extracts
the exact reviewed bytes from a Git blob, OpenType name record, or locked ZIP
member for every component payload. The deterministic license bundle records
those paths and digests in its own canonical manifest. SPDX represents each
component independently and includes `hasExtractedLicensingInfos` for every
custom `LicenseRef-*`; CycloneDX preserves the same component expression,
payload paths, and immutable evidence references. `verify.ps1` reopens the
license archive, checks its repository and toolchain inventories against both
locks, rejects every undeclared file, directory, or special archive member, and
cross-checks its extracted text against both SBOMs rather than accepting
artifact presence alone. Git LFS evidence binds the pointer bytes in Git and
extracts embedded font or archive terms only from the separately digest-verified
LFS object.

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

The license bundle, SPDX, CycloneDX, and SLSA provenance enumerate only source
repositories marked both `active` and `buildInput`; reference-only repositories
cannot appear as release dependencies. Provenance verification recomputes the
source, toolchain, and image lock digests and also binds the source date epoch,
offline build type, exact repository dependency inventory, and digest-locked
builder identity.

Every `.tar.zst` license archive is verified with only the `zstd` executable
declared as a `package` consumer in the toolchain lock. The executable is
resolved from `-CacheDirectory`, checked
against the locked size and SHA-256, copied to an isolated temporary directory,
and checked again. `verify.ps1` then runs that Linux executable inside the
digest-locked builder image with `--network none`, `--pull never`, a read-only
root filesystem, and read-only mounts. It never executes the Linux verifier on
the Windows host and never falls back to a `zstd` found on the host `PATH`.
Plain tar or other compression formats are rejected before decompression. The
stable verifier inputs therefore include `-ImageLockPath`, `-CacheDirectory`,
and `-DockerExecutable` in addition to the source and toolchain locks.
Bootstrap preflight rejects the toolchain lock unless it contains exactly one
Linux `zstd` record materialized as an executable `toolchain` file whose
destination basename is `zstd`.

## Current blocking state

This branch does not contain or generate a formal `locks/sources.lock.json`.
The source resolver still reports `LICENSE_INCOMPLETE` for:

- `build-tools-data`
- `core-fonts`
- `dictionaries`

Thirty-three font components and twenty-three dictionary packs now have
payload-complete, machine-verified primary evidence. The remaining blockers
are the selected CEF, Python, and Qt payloads; six font components; and
twenty-six dictionary packs enumerated in
`locks/source-inputs.v1.json`, for thirty-five unresolved components in total.
The formal `server`/`linux_64`/`--sysroot 0` profile does not enter the Android
V8, Ubuntu 16 sysroot, Windows Mobile GLEW, or Python extraction-helper paths;
behavior tests bind those exclusions to the published entrypoint and upstream
guards. A future profile that selects any of those paths must restore it to the
audited payload inventory. Partial evidence does not turn any of the three
repositories into a repository-wide declaration.

License closure alone does not make the first full build runnable. The locked
`core` tree does not contain the source directories that `boost.py`, `icu.py`,
and `openssl.py` clone when absent. `cef.py` still performs a remote metadata
probe and download, `deploy_server.py` still downloads the three plugin runtime
files even though `plugin-catalog` is a locked source input, and
`build_server.py` executes `npm ci` plus `pkg`. The formal toolchain closure
must therefore materialize every exact native, apt, npm, pkg, Java, Qt, CEF,
and third-party source byte and remove these remaining network call sites from
the offline path. `--update 0` only disables repository updates; it is not a
general offline switch.

The image lock, offline materializer, deterministic package driver, and release
artifact verifier are concrete and locally reverified. The formal toolchain
lock and its complete Python/apt/npm/pkg/Qt/native dependency cache remain
prerequisites. Until those inputs and the formal source lock are reviewed and
published, the public entrypoints must stop before producing a release
candidate. Placeholder locks, `NOASSERTION`, upstream fallbacks, and online
build/package retries are not supported.

The current release verifier still validates the source archive through its
artifact digest and the license/SBOM/provenance cross-checks, but does not yet
reconstruct every repository tree from that archive to independently recompute
all Git blob and LFS pointer bindings. Completing that ADR-0067 requirement is
a separate release-blocking work item; a future source lock revision must add
the immutable tree evidence or an equivalent verifiable Git bundle before a
formal release can be declared.

## Shortest real build path after closure

Run the authoring gates from the clean, merged build_tools commit that the
source lock will identify. The self checkout rejects `skip-worktree` and
`assume-unchanged` flags before resolving that commit. These gates are
intentionally separate from the four stable release entrypoints:

```powershell
pwsh -NoProfile -File scripts/resolve-sources.ps1 -Command Audit
pwsh -NoProfile -File scripts/resolve-sources.ps1 -Command LicenseAudit
pwsh -NoProfile -File scripts/resolve-sources.ps1 -Command LfsAudit
pwsh -NoProfile -File scripts/resolve-sources.ps1 -Command SelectionAudit
pwsh -NoProfile -File scripts/resolve-sources.ps1 -Command Resolve
```

Publish the canonical `sources.lock.json` as the immutable build_tools release
asset, place that exact asset and the reviewed `toolchain.lock.json` beside the
committed image lock, then run:

```powershell
pwsh -NoProfile -File scripts/bootstrap-source.ps1
pwsh -NoProfile -File scripts/build.ps1
pwsh -NoProfile -File scripts/package.ps1
```

Bootstrap is restartable: a complete matching source workspace is verified and
reused, while a failed first materialization is staged outside the public
workspace and removed instead of leaving a partial checkout that blocks the
next run. Failure to clean the private staging directory is itself reported as
a blocking source error. Reuse rejects ignored files, every path outside the
locked checkout inventory, and `skip-worktree` or `assume-unchanged` index
flags, so an existing workspace cannot hide modified tracked files or add
untracked build input. Build and package remain strictly `--network none`.

Repeat bootstrap, build, and package in a second independent cache, workspace,
and artifact root. Only then invoke `verify.ps1` with both artifact manifests;
the first build cannot serve as its own reproducibility reference.

The stable exit codes are:

- `0`: success
- `2`: invocation or contract error
- `3`: locked input missing or mismatched
- `4`: build, package, reproducibility, or release gate failure
