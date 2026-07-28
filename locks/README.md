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
