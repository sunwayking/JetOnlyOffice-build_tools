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

The formal lock preserves two mutually exclusive license shapes. Repositories
with one reviewed declaration retain the existing `path`, Git blob, SHA-256,
and SPDX record. Component-scoped repositories retain `scope: component`, the
reviewed `payloadPatterns`, and a complete sorted component inventory. Each
component binds its concrete payload paths and SPDX expression to expanded
evidence containing the payload Git blob and SHA-256 plus the evidence locator
and SHA-256. Audit-only candidate paths, diagnostic reasons, and unresolved
states never enter a formal lock. Bootstrap and local verification re-enumerate
the locked tree from `payloadPatterns`, so deleting a component from the lock
cannot hide a matching payload.
For an LFS payload, the evidence `blob` and payload SHA-256 bind the Git pointer,
while the matching `lfsObjects` record binds the materialized bytes. Embedded
font and archive evidence is extracted only after that LFS object has passed
its locked size and SHA-256 checks.

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
`payloadPatterns` defines the build payloads covered by this structural audit.
For build-tools-data it is an exact release-profile inventory, not a
repository-wide extension match: the published build entrypoint fixes
`server`, `linux_64`, and `--sysroot 0`, and behavior tests bind those options
to the upstream platform guards. Android V8, Ubuntu 16 sysroot, the Windows
Mobile GLEW archive, and the Python extraction helper are therefore outside
this release payload; expanding the release profile must add them back and
close their licenses before release. In all other cases,
`patterns` defines candidate evidence only and does not declare a license.
`reviewedComponents` is narrower: every payload in such a component must be
covered by one immutable evidence record and an explicitly reviewed SPDX
expression. The resolver accepts four primary evidence forms: an exact
license member inside a locked ZIP, copyright/license text in a locked OpenType
`name` table, or an exact license file stored as a locked Git blob. For
Git-blob evidence, each payload `path` names the covered payload and `locator`
names its reviewed license file, or the exact payload whose own header contains
a complete license grant, in the same locked tree. The resolver hashes
the extracted bytes or decoded text, binds every result to the containing Git
blob and payload SHA-256, and rejects missing, extra, or changed payloads.
`repository-git-blob` is the fourth form. It compares the consuming payload
byte-for-byte with a reviewed payload in another active, immutable-tag-selected
build-input
repository, then consumes that repository's own component-scoped Git-blob
license mapping. The formal lock records both repositories' commits and trees,
the consuming and reference payload blobs and SHA-256 values, and the evidence
blob and SHA-256. Package, SBOM, and provenance verification resolve only the
materialized locked checkout; they never fetch evidence during an offline step.
When a component expression contains multiple `LicenseRef-*` identifiers, every
evidence record carries a sorted `licenseRefs` binding, including an empty list
for evidence that belongs only to a standard SPDX license. The resolver,
packager, and verifier reject missing, unknown, or uncovered custom-license
bindings instead of copying every evidence text into every LicenseRef.
`resolve-sources.ps1 -Command LicenseAudit` reads the locked Git objects from
the local cache, records every matched payload plus candidate or verified
evidence with its SHA-256, and rejects stale `unresolvedComponents`. It returns
exit code 3 while legal mappings are incomplete, even when candidate files
exist.

At the current lock, this closes thirty-seven font
components. In addition to the previously reviewed families, the lock now
maps `ancient-scripts`, `arphic-ukai`, `dejavu`, `nanum`, `openoffice`,
`takao-gothic`, and `wqy-zenhei` to exact Git blobs or embedded font license
records. `fonts-beng-extra`, `fonts-gujr-extra`, `kacst`, and `kacst-one` use
byte-identical payload and license mappings from the immutable-tag-selected
`license-evidence` repository. The release gate remains blocked for the
selected `build-tools-data` CEF, Python, and Qt payloads. `ASC.ttf` remains
blocked on missing redistribution terms and `liberation` remains blocked on
conflicting custom terms. A product name, copyright line, package family,
external URL, or unrelated nearby license is not accepted as a substitute.

Primary archive inspection at build-tools-data commit
`743e8e55f0431523248d16b7521e01aa11744ffc` found no license, notice, or
copyright member in either the selected CEF 5414 Linux archive (SHA-256
`dff9aa53c147fd0c6a03f57e17aef10b0cee3fe7c4dc18b3b1a8a7a20bf0a145`)
or the selected Qt 5.9.9 Linux archive (LFS/SHA-256
`84181f983a5e76c2f8a63f8bf06d5ce27675f543c45febe014514633a1289f0e`).
The Python archive (SHA-256
`c251fd88959ad83a64711d37d7897d0bf7a3ed272f23b6ef6216e0eed0bf9360`)
contains the Python, pip, setuptools, and wheel license texts, but those files
do not yet prove a complete payload-to-license expression for the bundled
runtime. All three components therefore remain unresolved; no SPDX expression
is inferred from product identity or adjacent upstream sources.

Twenty-eight dictionary language packs are mapped payload by payload to exact
license blobs in the locked tree: `ar`, `bg_BG`, `ca_ES`, `ca_ES_valencia`,
`cs_CZ`, `en_CA`, `en_GB`, `en_US`, `en_ZA`, `es_ES`, `eu_ES`, `fr_FR`, `gl_ES`,
`hu_HU`, `ko_KR`, `lb_LU`, `lv_LV`, `nb_NO`, `nl_NL`, `nn_NO`, `oc_FR`,
`ro_RO`, `sk_SK`, `sr_Cyrl_RS`, `sr_Latn_RS`, `sv_SE`, `tr_TR`, and `vi_VN`.
Embedded grants are accepted only when the
payload identifies itself or explicitly identifies its paired word list.
`en_CA` uses `LicenseRef-SCOWL-2020-12-07` because its locked README contains
the complete compound SCOWL, Ispell, WordNet, VarCon, UKACD, and public-domain
terms for both the dictionary and affix payloads; no external license text is
substituted for that blob. `en_US` records its independently licensed spelling,
hyphenation, and WordNet thesaurus payloads as a compound expression. `en_GB`
binds byte-identical spelling and hyphenation payloads to the immutable
`license-evidence` snapshot, with separate LGPL 3.0 and versioned hyphenation
terms. `gl_ES` and both Serbian variants bind their payloads to exact in-tree
GPL 3.0 and LGPL 3.0 evidence respectively.
Mixed-origin payloads stay unresolved when a grant covers only an adaptation
but not the version-specific license of the underlying material. Conflicting
terms and license lists that do not establish whether choices are alternatives
also remain fail-closed. Machine-verified `blockingReviews` bind these findings
to the exact locked evidence bytes and prevent a blocked component from entering
`reviewedComponents`. `mn_MN` is blocked because its README both prohibits
modified redistribution and later offers redistribution or modification under
LPPL 1.3 or later. The locked blockers also cover `da_DK`, `el_GR`, `hr_HR`,
`it_IT`, `pt_BR`, and `sl_SI`, whose notices omit a license version; `kk_KZ`,
whose grant does not establish an alternative choice; `pl_PL` and `uk_UA`,
whose multi-license notices are not version-specific; `pt_PT`, whose notices
conflict; `en_AU`, `id_ID`, and `lt_LT`, whose locked evidence does not cover
every payload; and both Uzbek variants, whose READMEs identify an upstream
origin without granting a license. The remaining
twenty-one language packs stay incomplete; nineteen have candidate text
that does not yet provide a complete, version-specific payload mapping, while
`az_Latn_AZ` and `ru_RU` have no in-tree license candidate.

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

Every audit rerun removes its own previous report before locating Python,
reading inputs, or contacting a mirror. `Resolve` applies the same rule to its
requested source lock output. A startup, contract, or network failure that
prevents a new canonical result therefore leaves that run's output absent
instead of exposing an older passed report or stale lock as current evidence.
`Audit` and `LicenseAudit` can intentionally write a new canonical `failed`
report and return exit code 3; that report is current blocking evidence.
Formal authoring must retain the exit status together with the newly generated
report. A missing report after a failed rerun is also blocking evidence, not
permission to reuse the previous file.

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
