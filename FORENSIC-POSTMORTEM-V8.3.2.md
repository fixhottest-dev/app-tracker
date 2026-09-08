# Forensic Postmortem — V8.3.2

## Incident
A real signed APK entered the V8.3.1 automatic release worker. The job transitioned to `processing` and approximately 12 seconds later logged `RELEASE_JOB_OWNERSHIP_LOST`.

The service was already running under the Docker runtime with `aapt2`, `aapt`, `apksigner`, `bsdiff`, and `bspatch` available, and MongoDB transaction capability had passed startup verification. Therefore the incident was not consistent with the earlier native-toolchain failure.

## Root-cause class
The worker's fenced updates used `modifiedCount !== 1` as the ownership-loss condition. MongoDB distinguishes:

- `matchedCount`: documents matching the fenced ownership filter.
- `modifiedCount`: documents whose stored values actually changed.

For a first release of a package, the patch-state persistence update can legitimately set fields to their existing defaults (`patchGenerated=false`, empty patch URLs/hashes, null previous-release fields, etc.). That update can match the correct owned job while reporting `modifiedCount=0`.

Treating that as lease loss is therefore a false-fencing condition.

## V8.3.2 remediation
- Ownership/CAS decisions use `matchedCount === 1`.
- Heartbeats use `matchedCount` for lease ownership; a zero `modifiedCount` is not treated as lease loss.
- Ownership-loss logs include stage, job ID, worker ID, lease version, matched count and modified count, but never the secret lease token.
- Release jobs persist `stage`, `stageUpdatedAt`, `lastErrorCode` and `lastError` for admin diagnostics.
- Manual publication now uses the same per-package publication lock as automatic publication.
- `manualPatchTempPath` is function-scoped so final cleanup cannot hit a lexical-scope `ReferenceError` when multiple temporary files exist.
- Docker build runs static regression checks before the image is produced.

## What is still intentionally not claimed
No source-only package can honestly guarantee a literal 100/100 runtime result. The remaining proof step is a live end-to-end release using the user's real signed APK, transaction-capable MongoDB, and selected artifact storage provider. V8.3.2 is designed to make that test deterministic and observable rather than hiding failures behind a generic ownership message.
