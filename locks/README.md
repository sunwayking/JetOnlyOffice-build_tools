# Source resolution inputs

`source-inputs.v1.json` is the reviewed selection policy used by the internal
source resolver. It contains fixed commits or the explicit `self` selection
for the build_tools commit that runs the resolver. Every repository also has a
machine-checked `selection`: an immutable tag, the exact public
`refs/heads/develop` head of a project fork, an exact declared gitlink, the last
commit reachable from `refs/heads/upstream/` before `releaseCutoff`, or the
resolver's clean `self` checkout. These refs prove why a fixed commit was
selected; the fixed commit remains the only checkout selector. A later develop
advance makes the prior authoring policy stale and requires an explicit
re-lock; it never changes an already published immutable release lock.

Source-lock generation re-resolves every selection against the complete public
mirror before it emits repository metadata. A tag or gitlink that no longer
peels to the locked commit fails, and cutoff selection scans all official
upstream heads and rejects any earlier commit that should have been selected
instead. Human-readable `refHint` text is not accepted as selection evidence.

`resolve-sources.ps1` is an internal source-lock authoring and audit wrapper,
not one of the stable release-pipeline entrypoints. A release consumes its
immutable lock output through `bootstrap-source.ps1` after every blocking
source and license gate has passed.

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
`reviewedComponents` is narrower: every payload in such a component must be
covered by one immutable evidence record and an explicitly reviewed SPDX
expression. The resolver accepts three primary evidence forms: an exact
license member inside a locked ZIP, copyright/license text in a locked OpenType
`name` table, or an exact license file stored as a locked Git blob. For
Git-blob evidence, each payload `path` names the covered payload and `locator`
names its reviewed license file, or the exact payload whose own header contains
a complete license grant, in the same locked tree. The resolver hashes
the extracted bytes or decoded text, binds every result to the containing Git
blob and payload SHA-256, and rejects missing, extra, or changed payloads.
`resolve-sources.ps1 -Command LicenseAudit` reads the locked Git objects from
the local cache, records every matched payload plus candidate or verified
evidence with its SHA-256, and rejects stale `unresolvedComponents`. It returns
exit code 3 while legal mappings are incomplete, even when candidate files
exist.

At the current lock, this closes the GLEW archive and thirty-seven font
components. The `fonts-beng-extra`, `fonts-gujr-extra`, `kacst`, and
`kacst-one` families are mapped payload by payload to exact license records in
their locked OpenType name tables. Their reviewed `LicenseRef` expressions
preserve the upstream text without inventing a GPL version. The release gate
remains blocked for `build-tools-data` Android, CEF, Python, Qt, and sysroot
payloads. `ASC.ttf` remains unresolved because its only relevant locked record
says all rights reserved. `liberation` remains unresolved because its locked
records name and link to the Liberation Fonts license but do not contain its
redistribution terms. A product name, copyright line, package family, external
URL, or unrelated nearby license is not accepted as a substitute.

Nineteen dictionary language packs are mapped payload by payload to exact
license blobs in the locked tree: `ar`, `bg_BG`, `cs_CZ`, `en_ZA`, `es_ES`,
`eu_ES`, `fr_FR`, `hu_HU`, `lb_LU`, `lv_LV`, `nb_NO`, `nl_NL`, `nn_NO`,
`oc_FR`, `ro_RO`, `sk_SK`, `sv_SE`, `tr_TR`, and `vi_VN`. The remaining thirty
language packs stay incomplete; twenty-eight have
candidate text that still requires a precise mapping and `az_Latn_AZ` plus
`ru_RU` have no in-tree license candidate.

`resolve-sources.ps1 -Command LfsAudit` independently enumerates the LFS
pointers reachable from an explicitly selected locked commit, downloads every
object through the public mirror's anonymous batch API, verifies its size and
SHA-256, and writes a canonical report. It is available before formal source
lock generation, so license findings cannot conceal an incomplete LFS mirror.
The four audit commands keep independent canonical reports at
`artifacts/source-input-audit.json`, `artifacts/source-license-audit.json`, and
`artifacts/source-lfs-public-audit.json`. `SelectionAudit` writes the independent
`artifacts/source-selection-audit.json` report; running one gate cannot
overwrite the evidence from another gate.

The resolver accepts only the source and component expressions explicitly
listed in its reviewed set. Adding another expression requires a resolver and
contract update backed by real license evidence; arbitrary or syntactically
incomplete SPDX-like text fails closed.

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
