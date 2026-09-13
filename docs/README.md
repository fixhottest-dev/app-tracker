# RD Store Server — 10/10 Share + Production Edition

This build is based on the current uploaded V8.3.x production backend and adds the missing public RD Store share/App-Link layer without removing the existing device tracking, dashboard, MongoDB, Cloudinary, release-worker, artifact-storage, Smart Patch, or `/api/updates` architecture.

## Public routes

- `GET /app/:packageName` — canonical share landing page.
- `GET /download/app/:packageName` — resolves the latest valid published APK and redirects to its HTTPS artifact URL (or Firebase signed URL when configured).
- `GET /download/rdstore` — RD Store APK download route.
- `GET /.well-known/assetlinks.json` — Android App Links verification document.

## Required Render environment

```text
PUBLIC_SHARE_BASE_URL=https://app-tracker-xyp7.onrender.com
RDSTORE_SHARE_PACKAGE=com.ApkStoreManager
RDSTORE_SHA256_CERT_FINGERPRINT=YOUR_RELEASE_CERT_SHA256
```

`RDSTORE_SHA256_CERT_FINGERPRINT` must be the SHA-256 fingerprint of the **release signing certificate**, colon-separated (32 byte pairs). Multiple fingerprints can be comma-separated.

## Important

The server can only expose a public download when MongoDB contains a `published` release with:
- valid package name/version;
- valid 64-character APK SHA-256;
- valid 64-character signing-certificate SHA-256;
- an HTTPS public artifact URL, or a Firebase artifact storage path when Firebase mode is active.

Legacy published records missing cryptographic metadata remain in MongoDB but are intentionally excluded from public sharing until re-released with the current release pipeline.

## Android side

The Android manifest should contain the verified HTTPS App Link on `MainActivity`:

```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data
        android:scheme="https"
        android:host="app-tracker-xyp7.onrender.com"
        android:pathPrefix="/app/" />
</intent-filter>
```

The backend and Android package must use the same host, and `assetlinks.json` must contain the exact release signing fingerprint.
