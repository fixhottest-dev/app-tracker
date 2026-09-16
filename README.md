# RD Store Tracker — Fixed Server + Preserved Smali Set

This package is based on the supplied `index (3).js` and the supplied current Smali files. The existing release pipeline, dashboard, device/session models, `/track`, `/index.php`, and control response contract are preserved.

## Server changes

1. `/wake` (configurable by `TRACKING_WAKE_PATH`) is a lightweight 200 endpoint intended for Render/UptimeRobot-style external wake checks. It does not require MongoDB.
2. `/healthz` remains the real health endpoint and now reports HTTP 200 only when MongoDB is connected; it includes `service`, `database`, and `timestamp`.
3. Tracking automatically registers a valid Android package name in `AppRegistry` when `TRACKING_AUTO_REGISTER_APPS=true`. This removes the first-device `APP_NOT_REGISTERED` chicken-and-egg problem.
4. Device approval is NOT bypassed. A newly seen device is still `pending` and therefore receives `BLOCKED` until an administrator approves it.
5. Existing client-compatible routes remain `/track` and `/index.php`.
6. Tracking JSON responses now echo `appId` for diagnostics/contract visibility.
7. Startup can optionally pre-register package IDs from `TRACKING_APP_IDS`.

## Client Smali

All seven supplied Smali files are copied unchanged into `smali/`:

- BootGate.smali
- BootGate$1.smali
- TrackerConfig.smali
- SessionTracker.smali
- SessionTracker$1.smali
- SessionTracker$1$1.smali
- SessionTracker$PingRunnable.smali

No client Smali was silently rewritten in this package.

## Important current client contract

`TrackerConfig` reads `com.helper.updater.TRACK_BASE_URL` from application metadata and requires HTTPS. `SessionTracker$1` then calls:

`<TRACK_BASE_URL>/index.php?id=<encoded-device-id>&appId=<encoded-package>&action=<start|ping|stop>`

The supplied client uses a 5-second connect/read timeout. The server-side wake endpoint helps keep Render warm, but it cannot change that client timeout. If cold-start latency remains a problem, the client timeout/retry logic should be changed as a separate Smali revision.

## Uptime monitor

Configure the external monitor to call:

`https://app-tracker-xyp7.onrender.com/wake`

about every 5–10 minutes. Use `/healthz` when you want the monitor to alert when MongoDB is unavailable as well.

## Verification

`node --check "index (3).js"` was run successfully on the generated server file. Runtime verification against your actual MongoDB/Render environment was not possible here.
