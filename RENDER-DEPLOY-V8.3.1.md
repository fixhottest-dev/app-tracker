# RD APK Store V8.3.1 — Render Deployment

## What changed
- V8.3.1 Render production toolchain.
- Docker runtime with Node.js 24.
- Android SDK Build Tools 36.0.0: `aapt`, `aapt2`, `apksigner`.
- Debian `bsdiff` package provides `bsdiff` and `bspatch`.
- Startup performs a native release-toolchain preflight and fails closed if a required tool is missing.
- Added `/healthz` for Render health checks.
- Per-package MongoDB publication lock closes the concurrent monotonic-version publication race.
- Final publication transaction re-checks the latest published version while holding the package lock.
- Firebase Admin SDK is explicitly included for the optional Firebase artifact mode.
- Dependency versions refreshed to maintained/current compatible releases without moving Express or Mongoose across major versions.

## Render configuration
Use the **Docker** runtime for this service. Render supports Docker runtimes specifically when OS-level packages/tools are required.

- Runtime: `Docker`
- Dockerfile: `./Dockerfile`
- Docker Command: leave blank (uses the Dockerfile CMD)
- Health Check Path: `/healthz`

Environment variables remain in Render; do NOT put secrets in the repository.

Required production variables:
- `NODE_ENV=production`
- `MONGO_URI=...`
- `ADMIN_USERNAME=...`
- `ADMIN_PASSWORD_HASH=...` (bcrypt; do not use plain password here)
- `SESSION_SECRET=...` (minimum 32 characters)
- `TRUST_PROXY=1`

Storage mode:
- `ARTIFACT_STORAGE_MODE=manual` is the safe default.
- For GitHub/custom HTTP/Firebase, configure the corresponding credentials and endpoints.

## Important
Do not set `AAPT_PATH=apt`. The Docker image supplies absolute paths to Android Build Tools.

The release engine will verify:
- aapt2
- aapt
- apksigner
- bsdiff
- bspatch

before the web server starts.

## First deployment test
1. Deploy successfully.
2. Confirm startup logs show all five `Release toolchain OK` messages.
3. Confirm `/healthz` returns HTTP 200.
4. Log in to the admin console.
5. Upload a real signed APK.
6. Confirm metadata extraction succeeds before testing Smart Patch.

A real signed APK + MongoDB transaction-capable cluster + selected artifact storage provider still requires an end-to-end production test; static/source verification cannot substitute for that test.
