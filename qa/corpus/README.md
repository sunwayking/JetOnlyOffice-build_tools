# JetOnlyOffice QA corpus

The corpus contains only dedicated non-user test data.

- `upstream/sample.*` is copied byte-for-byte from
  `sunwayking/JetOnlyOffice-document-templates` commit
  `71430c9f183489e8912f54f9dc859e369cf0dfb4`, path `sample/`, under
  Apache-2.0.
- `generated/basic.odt`, `generated/basic.ods`, and `generated/basic.odp` are
  deterministic JetOnlyOffice fixtures produced by
  `scripts/qa/build_odf_corpus.py` and covered by this repository's license.

`qa/corpus-manifest.json` is authoritative for paths, byte sizes, SHA-256,
purposes, and provenance. Do not replace a file without updating the manifest
and reviewing the resulting release-policy change.
