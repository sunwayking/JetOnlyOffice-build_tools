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
covered by one or more immutable evidence records and an explicitly reviewed
SPDX expression. Distinct `path` plus `locator` mappings may bind cumulative
terms to one payload; duplicate mappings are rejected. The resolver accepts an
exact license member inside a locked ZIP, copyright/license text in a locked
OpenType `name` table, or an exact license file stored as a locked Git blob. For
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
`repository-cef-pak-resource` covers the CEF distribution case without copying
the 92 MB archive into the evidence repository. It binds the original LFS
payload, exact 7z member, Chromium DataPack v5 resource id, and optional
`chromium-grit-brotli` transform, then compares the derived bytes with a regular
Git blob in the immutable evidence snapshot. The transform requires Chromium's
two-byte `1e 9b` magic and six-byte little-endian uncompressed length before the
raw Brotli stream. DataPack encoding, zero padding, the terminal entry, ordered
unique resource and alias ids, alias indexes, and all offsets are validated.
7z output is read through a hard-bounded stream and terminated as soon as the
limit is exceeded. Resolver, package, and verify share this implementation;
verify re-extracts both the payload and evidence bytes from the source archive.
Malformed resources, unsupported transforms, LFS evidence blobs, trailing
Brotli input, and digest drift fail closed.
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

At the current lock, this closes thirty-eight font
components. In addition to the previously reviewed families, the lock now
maps `ancient-scripts`, `arphic-ukai`, `dejavu`, `liberation`, `nanum`,
`openoffice`, `takao-gothic`, and `wqy-zenhei` to exact Git blobs or embedded
font license records. `fonts-beng-extra`, `fonts-gujr-extra`, `kacst`, and
`kacst-one` use byte-identical payload and license mappings from the
immutable-tag-selected `license-evidence` repository, locked at
`v9.4.0-evidence.26`. The selected `build-tools-data` CEF, Python, and Qt
payloads are now closed from their embedded license resources. `ASC.ttf` is
the only unresolved font component and remains blocked on missing
redistribution terms.
A product name, copyright line, package family, external URL, or unrelated
nearby license is not accepted as a substitute.

At build-tools-data commit
`743e8e55f0431523248d16b7521e01aa11744ffc`, the selected Python bundle
(`python/python3.tar.gz`, SHA-256
`c251fd88959ad83a64711d37d7897d0bf7a3ed272f23b6ef6216e0eed0bf9360`)
is now closed with a complete versioned package-to-license inventory:
CPython 3.10.8 (PSF-2.0), pip/setuptools/wheel and the ensurepip wheels
(MIT) with every vendored package, plus the statically linked OpenSSL
1.1.1j, expat 2.4.9, libmpdec 1.70, zlib 1.2.12, bzip2 1.0.6, XZ 5.2.4,
SQLite 3.19.3, libffi, libedit, ncurses 6.0, and libuuid libraries, each
with a version-pinned upstream license text mirrored in the evidence
snapshot. The selected CEF 5414 Linux
archive (SHA-256
`dff9aa53c147fd0c6a03f57e17aef10b0cee3fe7c4dc18b3b1a8a7a20bf0a145`)
contains CEF license resource 63001 in
`cef_binary/Resources/chrome_100_percent.pak` and Chromium generated credits
resource 31061 in `cef_binary/Resources/resources.pak`. After the locked Brotli
transform, their SHA-256 values are respectively
`058c3827ffb827ff3edda471ae7e1bb1d1aa5931985f0126043ccd33409e792f` and
`4323092783bb888b8cacdd0f4e6173a69eedc29b747015376f17d337bbe304ef`.
The credits resource declares 6,692,103 output bytes in its GRIT header, exactly
matching the reviewed evidence blob. CEF locks Chromium `109.0.5414.120`; its
GRIT writer and resource loader define this 2-byte magic plus 6-byte length
framing rather than an opaque eight-byte prefix.
The selected Qt 5.9.9 Linux archive (LFS/SHA-256
`84181f983a5e76c2f8a63f8bf06d5ce27675f543c45febe014514633a1289f0e`)
now has a complete reviewed binary-to-source inventory. The bundle contains
GPLv3-only modules (Charts, Data Visualization, NetworkAuth, VirtualKeyboard),
so the conservative reviewed expression treats the whole Qt payload as
GPL-3.0-only and ANDs the compatible third-party licenses of the statically
integrated components: zlib 1.2.11 (Zlib), libpng 1.6.37 (Libpng AND
libpng-2.0), libjpeg 8c (IJG), libtiff 4.1.0 (libtiff), libwebp 1.0.3
(BSD-3-Clause), PCRE2 10.32, double-conversion 2.0.1, old HarfBuzz (MIT),
easing, forkfd, FreeBSD strtoll/strtoull, RFC6234, MD4/MD5/SHA-1 (public
domain), and SHA-3 brg_endian/Keccak (CC0-1.0). External runtime libraries
(ICU, OpenSSL via dlopen, FreeType, fontconfig, xcb, GLib, GStreamer, ALSA,
PulseAudio, CUPS, GTK, D-Bus, Wayland) are not packaged in the 7z and are
audited with the runtime image.

Forty-nine dictionary language packs are mapped payload by payload to exact
license blobs in the locked tree or immutable `license-evidence` snapshot:
`ar`, `az_Latn_AZ`, `bg_BG`, `ca_ES`, `ca_ES_valencia`, `cs_CZ`, `da_DK`, `de_AT`,
`de_CH`, `de_DE`, `el_GR`, `en_AU`, `en_CA`, `en_GB`, `en_US`, `en_ZA`, `es_ES`,
`eu_ES`, `fr_FR`, `gl_ES`, `hr_HR`,
`hu_HU`, `id_ID`, `it_IT`, `kk_KZ`, `ko_KR`, `lb_LU`, `lt_LT`, `lv_LV`,
`mn_MN`, `nb_NO`, `nl_NL`, `nn_NO`, `oc_FR`, `pl_PL`, `pt_BR`, `pt_PT`,
`ro_RO`, `ru_RU`, `sk_SK`, `sl_SI`, `sr_Cyrl_RS`, `sr_Latn_RS`, `sv_SE`,
`tr_TR`, `uk_UA`, `uz_Cyrl_UZ`, `uz_Latn_UZ`, and `vi_VN`.
Embedded grants are accepted only when the
payload identifies itself or explicitly identifies its paired word list.
`en_CA` uses `LicenseRef-SCOWL-2020-12-07` because its locked README contains
the complete compound SCOWL, Ispell, WordNet, VarCon, UKACD, and public-domain
terms for both the dictionary and affix payloads; no external license text is
substituted for that blob. `en_US` records its independently licensed spelling,
hyphenation, and WordNet thesaurus payloads as a compound expression. `en_GB`
binds byte-identical spelling and hyphenation payloads to the immutable
`license-evidence` snapshot, with separate LGPL 3.0 and versioned hyphenation
terms. The three German variants bind their byte-identical payloads to GPL 2
or 3 spelling terms and the cumulative LGPL 2 or later plus LPPL 1.0
hyphenation terms. Each hyphenation payload maps independently to the adaptation
README, the original `dehyphn.tex` grant, and the canonical `LPPL-1.0` text.
`az_Latn_AZ` binds both locked spelling payloads to an immutable Hunspell/Aspell
source snapshot. The digest-bound Fedora package spec and RPM provide the
payload provenance and select GPL 2 or later, while the upstream copyright
notice and complete GPL 2 text preserve the grant and attribution evidence.
`en_AU` keeps the SCOWL compound terms embedded in its locked spelling README
and binds the generated hyphenation payload to an immutable OpenOffice source
blob. The extension metadata and build manifest identify the source-derived
payload and declare LGPL 3.0 for the hyphenation package.
`kk_KZ` binds byte-identical locked payloads to an immutable Debian copyright
record that establishes GPL 2 or later, LGPL 2.1 or later, and MPL 1.1 as
alternative choices. The independent package payloads reproduce the locked
bytes after UTF-8 BOM removal and CRLF-to-LF normalization.
`lt_LT` binds byte-identical payloads to the immutable BSD 3-Clause text from
the `ispell-lt` 1.3 source imported by LibreOffice; the locked bytes are
reproduced by a deterministic ISO-8859-13-to-BOM-UTF-8 conversion. `sl_SI`
binds its spelling and hyphenation payloads to the versioned LGPL 2.1 notices,
the original LPPL 1.0 source, and the canonical LPPL text. The locked Slovenian
bytes are reproduced by a deterministic ISO-8859-2-to-UTF-8 conversion.
`id_ID` binds all three payloads to the immutable LibreOffice extension source.
Its extension metadata covers spelling, hyphenation, and thesaurus content, and
the dictionary license is the complete LGPL 3.0 text. Deterministic
ISO-8859-1-to-UTF-8 conversion reproduces the locked spelling, affix, and
hyphenation bytes.
`it_IT` binds byte-identical locked payloads to the immutable LibreOffice
extension source, whose complete GPL 3 grant expressly covers spelling and
hyphenation. The original hyphenation notice independently grants LGPL 2.1 or
later, so the reviewed expression retains both cumulative terms.
`el_GR` selects LGPL 2.1 or later for its spelling payloads and binds the
hyphenation payload to the matching Fedora 11 source RPM, whose spec declares
`LGPLv2+`. Deterministic ISO-8859-7-to-UTF-8 conversion reproduces the locked
hyphenation bytes.
`hr_HR` retains its in-tree LGPL 3.0 spelling grant and binds the hyphenation
payload to the versioned Croatian LibreOffice extension. Its registration
license supplies LGPL 3.0, the original pattern source supplies LPPL 1.0, and
deterministic ISO-8859-2-to-UTF-8 conversion reproduces the locked bytes.
`pt_PT` binds all three payloads to Debian `libreoffice-dictionaries 1:7.2.0-1`.
The source record offers GPL 2 for the spelling payloads and assigns GPL 2 to
hyphenation, so the reviewed mapping consistently selects `GPL-2.0-only`.
`pt_BR` binds byte-identical spelling payloads to an immutable LibreOffice
commit and the locked LGPL 2.1 notice. Its hyphenation payload is reproduced
from Fedora's digest-bound `hyphptBR-213.zip`; the Azure Linux package spec
assigns LGPL 3.0 to the Brazilian subpackage, and a deterministic
ISO-8859-1-to-UTF-8 conversion reproduces the locked bytes.
`uk_UA` retains the in-tree GPL 2-or-later spelling and hyphenation notices,
while the thesaurus data and deterministically generated index bind to an
immutable `spell-uk` source commit under the same selected branch.
`da_DK` binds byte-identical spelling payloads to the explicit GPL 2, LGPL 2.1,
and MPL 1.1 alternatives. Its hyphenation payload is reproduced from the Fedora
source and retains both the versioned LGPL 2.1-or-later adaptation grant and the
original LPPL 1.3-or-later patterns, selecting the canonical LPPL 1.3c branch.
`ru_RU` binds all five locked payloads to the custom Lebedev terms. Current
payloads are byte-identical to a locked LibreOffice commit and independently
mapped by Debian; the historical OpenOffice payloads are reproduced from the
original OXT with their required modification notice.
`gl_ES` and both Serbian variants bind their payloads to
exact in-tree GPL 3.0 and LGPL 3.0 evidence respectively.
`mn_MN` binds its spelling and hyphenation payloads to the complete LPPL 1.3c
text in the immutable evidence snapshot.
Both Uzbek variants bind their byte-identical spelling payloads to the MIT
text their sole author published in `u2b3k/uz-hunspell` at commit `6de6532`,
where the exact locked bytes coexist with the MIT `LICENSE`. The ONLYOFFICE
import (2022-01-20) falls inside that grant window; the author's later GPL v3
switch accompanies replacement payloads, not the locked ones.
Mixed-origin payloads stay unresolved when a grant covers only an adaptation
but not the version-specific license of the underlying material. Conflicting
terms and license lists that do not establish whether choices are alternatives
also remain fail-closed. Machine-verified `blockingReviews` bind these findings
to the exact locked evidence bytes and prevent a blocked component from entering
`reviewedComponents`. The `pl_PL` spelling and hyphenation payloads bind to the
pl.openoffice.org 2008.12.06 release: the locked notice pins the Creative
Commons branch to CC-SA-1.0 via its `/sa/1.0` URL and grants the hyphenation
adaptation under LGPL 2.1, while the GPL/LGPL/MPL versions are pinned by the
era-matched Debian `ipolish 20090225-1` copyright, the maintainer's own sjp.pl
page, and the LibreOffice 2026-05-11 README. Complete GPL v2, LGPL 2.1,
MPL 1.1, and CC-SA 1.0 texts are mirrored in the immutable evidence snapshot.
Together with `ASC.ttf`, they account for the one unresolved component in
the current lock.

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
