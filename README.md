# JetOnlyOffice Build Tools

This fork is the authoritative coordination repository for JetOnlyOffice.
It owns the source and toolchain locks, reproducible build pipeline, product
design decisions, QA corpora, and release evidence.

Development targets the protected `develop` branch. A coordinated release
promotes DocumentServer, web-apps, SDKJS, and build_tools together. Release
builds must not consume a floating upstream branch.

## Authoritative records

- [Product language and scope](CONTEXT.md)
- [Architecture and Mobile design index](docs/README.md)
- [Upstream build-tools documentation](docs/upstream-build-tools.md)

## Stable entrypoints

The release pipeline exposes only these maintainer entrypoints:

```powershell
.\scripts\bootstrap-source.ps1
.\scripts\build.ps1
.\scripts\package.ps1
.\scripts\verify.ps1
```

These entrypoints remain fail-closed until their source, license, toolchain,
image, package, and QA evidence is complete. A successful build is not a
release unless every blocking gate passes.

Other scripts are internal authoring or verification tools. They are not
stable release-pipeline entrypoints and carry no compatibility guarantee.
