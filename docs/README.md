# JetOnlyOffice authoritative design record

This directory is the authoritative home for JetOnlyOffice architecture,
Mobile Web product decisions, Android reference evidence, and release design.
The outer local workspace is a convenience checkout only and is not a fifth
coordination repository.

## Start here

- [`../CONTEXT.md`](../CONTEXT.md): canonical product language and scope.
- [`source-build-architecture.md`](source-build-architecture.md): source,
  build, package, and verification architecture.
- [`mobile-design-reference.md`](mobile-design-reference.md): Android device
  screenshots and interaction hierarchy, the highest-priority Mobile design
  reference.
- [`desktop-web-reuse.md`](desktop-web-reuse.md): Desktop command and state
  reuse boundaries.
- [`adr/`](adr/): accepted architecture decisions.
- [`reference/mobile/`](reference/mobile/): original PNG and UI hierarchy XML
  evidence captured from the Android device.
- [`design-source-manifest.json`](design-source-manifest.json): migration
  provenance for every file copied from the pre-implementation workspace
  snapshot.
- [`../manifests/authoritative-design-docs.v1.json`](../manifests/authoritative-design-docs.v1.json):
  deterministic SHA-256 and size of the current authoritative `CONTEXT.md` and
  every regular file under `docs/`.

## Integrity verification

The current-authority manifest lives outside `docs/` to avoid self-reference.
It contains no timestamp or local path, rejects symbolic links, and is sorted
by repository-relative path. Generate it only when authoritative content is
intentionally changed, and verify it before review:

```powershell
.\scripts\design-docs.ps1 -Command Generate
.\scripts\design-docs.ps1 -Command Verify
```

The commands do not read or modify product source, toolchain, or image locks.

New decisions and evidence must be committed here on a branch based on
`develop`. Do not update the outer workspace copy and treat it as canonical.
