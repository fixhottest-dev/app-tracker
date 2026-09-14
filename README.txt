RD Store FCM Update Notification Server Patch

Based on the supplied V8.3.2 server.

Added, without changing existing APK/release logic:
- NotificationSubscription Mongo model
- POST /api/notifications/register
- POST /api/notifications/unregister
- Firebase Admin FCM sender
- Automatic-release post-commit notification
- Manual-artifact-release post-commit notification
- stale/invalid FCM token cleanup
- Mongo index sync for notification subscriptions

Required Render environment variable:
FCM_NOTIFICATION_ENABLED=true
FCM_SERVICE_ACCOUNT_JSON=<Firebase service account JSON or base64 JSON>

Optional:
FCM_PROJECT_ID=<Firebase project id>

Android must POST its FCM registration token with packageName to:
/api/notifications/register

Notification data includes packageName, so Android can open the existing AppdetailsActivity for that package.
