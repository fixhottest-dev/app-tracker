RD Store — Minimal FCM Update Notification Server Patch

BASE
----
This patch is based directly on the untouched original index (1)(1).js supplied for the RD Store server.
The existing release/download/security/artifact architecture is preserved.

WHAT WAS ADDED
--------------
1. FCM configuration:
   FCM_NOTIFICATION_ENABLED=true
   FCM_SERVICE_ACCOUNT_JSON=<Firebase service-account JSON or base64-JSON>
   FCM_PROJECT_ID=<optional; service account project_id is used when omitted>

2. Independent Firebase Admin Messaging initialization.
   This does NOT require ARTIFACT_STORAGE_MODE=firebase.
   Existing Firebase Storage behavior is unchanged.

3. Package-specific FCM topic notifications.
   Topic format:
   rdstore_app_<packageName>

4. Notification is sent only after a release publication transaction succeeds:
   - automatic release publication
   - manual artifact publication

5. FCM failure can never convert an already-successful APK publication into a failed release.

ANDROID REQUIREMENT
-------------------
The RD Store Android app must subscribe to the matching topic after the user has used/downloaded an app from RD Store.
Example topic for package com.example.app:
rdstore_app_com.example.app

The Android app should also create the notification channel id:
rd_store_updates

Notification data contains:
- type=app_update
- packageName
- appName
- versionName
- versionCode
- shareUrl

IMPORTANT
---------
Do not commit FCM_SERVICE_ACCOUNT_JSON to GitHub.
Keep the service-account JSON only in Render Environment Variables.

Render variables:
FCM_NOTIFICATION_ENABLED=true
FCM_SERVICE_ACCOUNT_JSON=<private JSON value>
FCM_PROJECT_ID=<optional>

VALIDATION
----------
index.js passes `node --check`.
