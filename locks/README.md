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

Incomplete repository records carry a sorted `unresolvedComponents` inventory.
It names the payload families, font components, or dictionary language packs
whose license coverage is not proved by the locked tree. The audit report
copies that inventory verbatim, so a generic repository-level failure cannot
hide which evidence is still missing. Candidate license files do not become a
declaration until their asset mapping and SPDX expression have been reviewed.
`payloadPatterns` defines the build payloads covered by this structural audit;
`patterns` defines candidate evidence only and does not declare a license.
`resolve-sources.ps1 -Command LicenseAudit` reads the locked Git objects from
the local cache, records every matched payload and candidate evidence blob with
its SHA-256, and rejects stale `unresolvedComponents`. It returns exit code 3
while legal mappings are incomplete, even when candidate files exist.

`resolve-sources.ps1 -Command LfsAudit` independently enumerates the LFS
pointers reachable from an explicitly selected locked commit, downloads every
object through the public mirror's anonymous batch API, verifies its size and
SHA-256, and writes a canonical report. It is available before formal source
lock generation, so license findings cannot conceal an incomplete LFS mirror.
The three audit commands keep independent canonical reports at
`artifacts/source-input-audit.json`, `artifacts/source-license-audit.json`, and
`artifacts/source-lfs-public-audit.json`; running one gate cannot overwrite the
evidence from another gate.

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
Bootstrap calls the public Git LFS batch protocol directly without a credential
helper, follows only HTTPS download actions, and recomputes each downloaded
object's locked size and SHA-256 before caching it. Standard HTTP proxy settings
may transport the anonymous requests but cannot satisfy repository
authentication or change bytes without failing the digest check. A public Git
ref whose LFS object still requires credentials is an incomplete mirror and
fails the source gate.

`bootstrap-source.ps1 -Command Bootstrap` is the network preparation step. It
fills and verifies the Git/LFS cache before materializing source. `-Command
Verify` performs local commit, tree, license, and LFS content verification and
does not contact a remote.
