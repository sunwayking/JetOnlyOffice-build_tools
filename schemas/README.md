# JetOnlyOffice build contracts

These schemas are the versioned boundary between source resolution, build,
packaging, and release verification:

- `source-lock.schema.json` pins every Git repository and gitlink.
- `toolchain-lock.schema.json` pins every non-container tool input.
- `image-lock.schema.json` pins builder, runtime, BuildKit, and frontend images.
- `build-manifest.schema.json` inventories the offline build output.
- `artifact-manifest.schema.json` inventories packages and supply-chain files.
- `command-catalog.schema.json` proves every Desktop command is Mobile-mapped or ADR-excluded.
- `corpus-manifest.schema.json` pins the release and performance corpora.
- `gate-catalog.schema.json` freezes the source-independent release gate matrix.
- `gate-result.schema.json` records immutable first-attempt evidence and status.
- `release-policy.schema.json` binds the gate matrix to a source lock.
- `release-evidence.schema.json` aggregates all blocking and non-blocking results.
- `entrypoints.v1.json` freezes the four public PowerShell entrypoints and their
  network policy.

Contract JSON is canonicalized before hashing. JetOnlyOffice uses the RFC 8785
subset in which object keys are ASCII and numbers are integers in the
interoperable IEEE-754 range. Floating-point values, duplicate keys, unsorted
identity arrays, non-normalized paths, and unknown properties fail closed.

Use the stable wrapper from the repository root:

```powershell
.\scripts\contracts.ps1 -Command Validate -Contract source-lock -Path .\locks\sources.lock.json
.\scripts\contracts.ps1 -Command Canonicalize -Path .\locks\sources.lock.json -Output .\out\sources.lock.canonical.json
.\scripts\contracts.ps1 -Command Digest -Path .\locks\sources.lock.json -Sidecar .\out\sources.lock.sha256
.\scripts\contracts.ps1 -Command ValidateEntrypoints -Path .\schemas\entrypoints.v1.json
```

The lock file never contains its own digest. The digest is stored in a sidecar
or immutable release metadata to avoid self-reference.
