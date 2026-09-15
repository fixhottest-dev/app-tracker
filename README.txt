RD FINAL SERVER — FCM + APK REMOTE CONTROL

Base:
- Original index (2)(2).js preserved as the authoritative base.

Preserved:
- Existing FCM initialization and package-topic update notifications.
- Existing release/update pipeline.
- Existing Smart Patch pipeline.
- Existing Device records and approval system.
- Existing session timeout/cleanup.
- Existing security middleware and API behavior.

Added:
- AppControl per uploaded APK package.
- Admin page: /controls
- Admin action: /action/app-control
- API: /api/app-control/:appId
- Controls: ACTIVE, MAINTENANCE, REDIRECT, DISABLED, FORCE_EXIT
- Non-ACTIVE controls close the corresponding online session.
- Existing RD Store user/device records are not migrated, reset, or deleted.

Important:
- This ZIP contains ONE production server file only: server/index.js
- Deploy this as your Render index.js.
- Keep your existing Render environment variables unchanged, including FCM variables.
- FCM service-account JSON must remain only in Render environment variables; never commit it.

Validation performed:
- node --check: PASS
- FCM helper/call count compared with original: preserved
- AppControl additions compared with the remote-control version: preserved
- Diff against original contains only the intended AppControl additions/changes.
