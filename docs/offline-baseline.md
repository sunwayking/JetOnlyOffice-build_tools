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
validates all three lock contracts before resolving sources, verifies every
toolchain cache file by size and SHA-256, and pulls every image by immutable
digest for `linux/amd64`. It writes `cache/bootstrap-manifest.json` only after
all inputs are present and verified.

Toolchain files use this deterministic cache path:

```text
cache/toolchain/<tool-id>/<sha256>
```

`build.ps1` and `package.ps1` revalidate the bootstrap manifest, all three
lock digests, the locked toolchain bytes, and their complete upstream
manifests before invoking Docker. Only a temporary cache view containing the
current bootstrap manifest and its declared toolchain files is mounted; other
files retained in the shared cache are not visible to build or package.
Their containers use the digest-pinned builder image with `--pull never`,
`--network none`, `--platform linux/amd64`, a read-only root filesystem, and
read-only source, cache, and driver mounts.

Before each container invocation, the expected output manifest must resolve
inside the artifact root and any previous manifest at that path is removed.
The command succeeds only when this invocation creates a new manifest whose
JSON contract, lock bindings, file sizes, and file SHA-256 values all validate.

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

Formal toolchain and image locks, their complete caches, and the locked package
driver also remain prerequisites. Until those inputs are reviewed and
published, the public entrypoints must stop before producing a release
candidate. Placeholder locks, `NOASSERTION`, upstream fallbacks, and online
build/package retries are not supported.

The stable exit codes are:

- `0`: success
- `2`: invocation or contract error
- `3`: locked input missing or mismatched
- `4`: build, package, reproducibility, or release gate failure
