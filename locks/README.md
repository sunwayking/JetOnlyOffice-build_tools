# Source resolution inputs

`source-inputs.v1.json` is the reviewed selection policy used by
`bootstrap-source.ps1`. It contains fixed commits or the explicit `self`
selection for the build_tools commit that runs the resolver. Branch and tag
names are provenance hints only and are never checkout selectors.

The authoritative `sources.lock.json` is intentionally not committed here.
It is generated after the resolver commit is merged and published as an
immutable build_tools release asset, which avoids a lock file referring to the
commit that contains itself.

The current policy is expected to fail with `LICENSE_INCOMPLETE` for inputs
whose upstream repositories do not provide complete license evidence. That
failure is a release gate, not an invitation to replace the evidence with
`NOASSERTION`.

`images.lock.json` is the reviewed `linux/amd64` image lock. Each entry binds
both the repository manifest digest and the platform config digest. The four
records were pulled from their public repositories and inspected on the local
Docker Linux engine; bootstrap repeats those checks before writing its
manifest. The Ubuntu image is the minimal builder/runtime base, not evidence
that the compiler toolchain has been closed.

The formal `toolchain.lock.json` remains intentionally absent. Every eventual
tool record must declare its exact bytes, media type, license, sorted `build`,
`package`, or `runtime` consumers, and deterministic materialization. The
materialization target is one of the private toolchain root, copied source
workspace, or offline package cache; supported inputs are regular files, DEBs,
and tar archives. The contract requires all three consumer classes to be
covered, so a one-file placeholder cannot satisfy the release toolchain gate.
