# Mobile performance protocol

This protocol is blocking only on the Xiaomi `2409BRN2CC` (`pond`) performance-floor device. The run must use a release build over a local network after all static assets have been cached. Official Chrome Stable and System WebView versions, package names, signing certificate SHA-256 values, Android build fingerprint, memory and CPU ABI are captured before measurement.

## Run rules

1. Restart the browser or WebView host and clear unrelated background workloads without clearing the warmed editor cache.
2. Open each standard DOCX, XLSX, PPTX and PDF corpus once as warmup. Warmup samples are retained but excluded from the measured set.
3. Perform ten consecutive measured opens for each format. Every sample, measured from the real connection phase through first rendered interactive frame and collaboration initialization, must be at most `8000 ms`.
4. Execute each representative command at least 30 times. Compute P95 with the nearest-rank method (`ceil(0.95 * n)` in ascending order). P95 must be at most `250 ms`.
5. Perform three complete scroll and pinch-zoom rounds per format. The median frame rate of every round must be at least `45 FPS`, represented as an integer in milli-FPS. No main-thread or rendered-frame freeze may exceed `1000 ms`.
6. Preserve raw performance traces, per-sample integer measurements and the calculation output under the immutable evidence path. A failed first attempt remains failed; reruns use a new run ID and never replace prior evidence.

Missing Chrome, an unlocked browser version or signature, an unavailable device, an unlocked performance corpus, or a trace collection failure produces `INFRA_INCOMPLETE`. It is not classified as a product failure, but it blocks release.
