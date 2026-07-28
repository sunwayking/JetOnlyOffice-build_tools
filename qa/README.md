# JetOnlyOffice release QA

The QA layer is fail-closed. It validates command coverage and corpus bytes, runs browser and device harnesses, records immutable first-attempt results, and aggregates them into one deterministic release decision. `INFRA_INCOMPLETE` is distinct from a product failure but blocks a coordinated release exactly like any other non-pass on a blocking gate.

## Contracts

- `gate-catalog.v1.json` is the source-independent gate matrix.
- A release policy binds that catalog to a release ID and source-lock SHA-256.
- Command catalogs list every Desktop built-in command as Mobile-mapped or ADR-excluded.
- The corpus manifest covers DOCX/ODT, XLSX/ODS, PPTX/ODP and PDF, pins every file by size and SHA-256, and reports whether all four performance profiles are actually ready.
- Each gate result represents attempt 1 only and references content-addressed raw evidence.
- `release-evidence.json` is recomputed from the bound policy and gate results. Missing blocking results, failures and incomplete infrastructure produce `BLOCKED`.

## Commands

```powershell
.\scripts\contracts.ps1 -Command Validate -Contract gate-catalog -Path .\qa\gate-catalog.v1.json
.\scripts\qa.ps1 verify-corpus --manifest .\qa\corpus-manifest.json --root .
.\scripts\qa.ps1 check-commands --required-editor word --required-editor spreadsheet --required-editor presentation --required-editor pdf --catalog .\qa\commands\word.json --catalog .\qa\commands\spreadsheet.json --catalog .\qa\commands\presentation.json --catalog .\qa\commands\pdf.json
.\scripts\qa.ps1 evaluate-performance --samples .\evidence\raw\release-run-001\performance.xiaomi.open-time\samples.json --output .\evidence\results\release-run-001\performance.xiaomi.open-time\result.json
.\scripts\qa.ps1 aggregate --policy .\evidence\release-policy.json --gate-result .\evidence\results\browser.desktop.chromium.json --run-id release-run-001 --artifact-manifest-sha256 <sha256> --output .\evidence\release-evidence.json
```

`evaluate-performance` accepts one immutable sample file for one of the three
Xiaomi performance gates. It validates the complete four-format measurement
shape, verifies the exact Android-target, device-fact and raw-trace bytes,
recomputes the threshold result, and emits a canonical `gate-result`. The
output is created exclusively at
`evidence/results/<run-id>/<gate-id>/result.json`; another path or a second
evaluation is rejected before recomputation. A write-once
`first-attempt.json` receipt remains under the raw gate path even if the result
is removed. Release aggregation rereads every raw performance record, reruns
the evaluator, compares the result digest and validates that receipt, so a
replaced sample, trace or result blocks release. An incomplete collector emits
no measurements and must carry an infrastructure error code.

The Playwright harness uses three locked projects with `retries: 0`. `JETONLYOFFICE_QA_BASE_URL` and `JETONLYOFFICE_QA_EVIDENCE_DIR` are mandatory; absence is infrastructure incomplete, never a skipped pass. Editor owners add functional specifications under `qa/playwright/tests` as their command providers freeze.

`qa/playwright/package-lock.json` pins the runner. Its npm tarballs and browser binaries must be fetched and hashed during `bootstrap-source.ps1`; `build.ps1` and `verify.ps1` consume only that cache with network disabled. A local harness smoke check is:

```powershell
Set-Location .\qa\playwright
npm ci --ignore-scripts
$env:JETONLYOFFICE_QA_BASE_URL = "https://documentserver.test"
$env:JETONLYOFFICE_QA_EVIDENCE_DIR = "evidence/raw/release-run-001/browser.desktop.chromium"
npm test
```

Android facts are captured with `qa/android/collect-device-facts.ps1`. The target file deliberately leaves the tablet model unlocked; that state blocks tablet release gates until a real device is selected.

The Xiaomi runtime lock records official Chrome Stable `150.0.7871.186` and
System WebView `143.0.7499.192`, including both verified APK signing
certificates. A runtime update changes the attested facts and blocks performance
evaluation until this lock is deliberately reviewed and updated.

The committed corpus is currently `INFRA_INCOMPLETE`: its small files are smoke fixtures, not the ADR-0018/0053 performance corpus. Corpus byte verification can pass while readiness remains incomplete; that result must not be promoted to a performance gate pass.
