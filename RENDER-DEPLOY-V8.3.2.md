# RD APK Store V8.3.2 — Production Render Deployment

## Why V8.3.2 exists
V8.3.1 exposed a live worker-lease failure during a real signed-APK release attempt. The release job was reported as `RELEASE_JOB_OWNERSHIP_LOST` even though there was no evidence of an actual competing worker taking the lease.

The immediate code weakness was using MongoDB `modifiedCount === 1` as an ownership signal. A valid fenced update can match exactly one owned job while changing zero fields when the requested values already equal the stored values. That is not ownership loss.

V8.3.2 changes ownership/CAS decisions to `matchedCount === 1`, adds stage-aware diagnostics, fixes a manual-patch temporary-path scope bug, and applies the same per-package publication lock to manual publication.

## Render settings
Use **Docker runtime**. Do not use the Native Node runtime because the release engine requires OS-level Android and BSDIFF tools.

- Runtime: Docker
- Dockerfile: `./Dockerfile`
- Docker Command: leave blank
- Health Check Path: `/healthz`
- Build Command: leave blank
- Start Command: leave blank

The Dockerfile supplies the CMD and installs the required native release toolchain.

## Required environment variables
- `NODE_ENV=production`
- `MONGO_URI`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD_HASH` — bcrypt hash, never plain text
- `SESSION_SECRET` — at least 32 characters
- `TRUST_PROXY=1` for the normal single Render proxy hop
- `ARTIFACT_STORAGE_MODE` — `manual` is the default/safe starting mode

See `.env.production.example` for optional storage configuration.

## Expected startup logs
The deployment should show all of these before the service becomes live:

- `Release toolchain OK: aapt2`
- `Release toolchain OK: aapt`
- `Release toolchain OK: apksigner`
- `Release toolchain OK: bsdiff`
- `Release toolchain OK: bspatch`
- `MongoDB transaction capability verified.`
- `... running on port ...`

## Release test order
1. Confirm `/healthz` is HTTP 200.
2. Log into the admin console.
3. Upload one real signed APK.
4. Watch `/api/releases` or the Release Pipeline Status table.
5. Confirm the job advances beyond `metadata_persist` and `patch_state_persist` without an ownership-loss error.
6. In manual mode, download the server-generated APK/patch, host them externally, and use **Verify URLs & Publish**. The server re-downloads and verifies exact SHA-256 plus APK metadata/signing certificate before atomic publication.

## Important operational notes
- Do not upload the ZIP itself to Render. Put these files in the Git repository and deploy the repository with Docker runtime.
- Do not store secrets in GitHub or this ZIP.
- Render's filesystem is ephemeral. `manual` mode is intentionally a staging workflow, not durable artifact storage.
- For durable automatic artifact hosting, configure `github`, `custom_http`, or `firebase` and test the selected provider end-to-end.
- MongoDB transactions require a transaction-capable deployment (replica set / compatible managed cluster).
- A package-lock file is intentionally not fabricated here because this build environment cannot reach npm to generate a trustworthy lockfile. The dependency versions are pinned in `package.json`; Render resolves them during image build.

## Security posture
The release path remains fail-closed for cryptographic/integrity failures: APK hash, signature, package/version metadata, patch reconstruction, remote artifact hash, and publication invariants are verified before publication. Operational patch-generation failure may fall back to a full APK; integrity/security failures never silently fall back.
