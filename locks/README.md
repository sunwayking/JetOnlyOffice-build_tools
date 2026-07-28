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

The current resolver accepts only the reviewed source expressions used by this
closure (`AGPL-3.0-only`, `Apache-2.0`, and `MIT`). Adding another expression
requires an explicit resolver and contract update backed by real license
evidence; arbitrary or syntactically incomplete SPDX-like text fails closed.

Each generated repository record includes the complete Git LFS object list
reachable from its locked commit: immutable SHA-256 object id, byte size, and
all materialized paths. Bootstrap proves that both Git history and every LFS
object are anonymously readable from the repository's public
`sunwayking/JetOnlyOffice-*` origin. The resolver forces that origin's LFS
endpoint and never follows the informational `upstream` URL as a fallback.

`bootstrap-source.ps1 -Command Bootstrap` is the network preparation step. It
fills and verifies the Git/LFS cache before materializing source. `-Command
Verify` performs local commit, tree, license, and LFS content verification and
does not contact a remote.
