# RD Tracker / RD Store Complete Fixed Build

This package uses the current uploaded server as the source of truth and fixes the Render startup crash caused by initialization order.

## Critical fix
`TRACKING_AUTO_REGISTER_NAME` is initialized only after `MAX_APP_NAME_LENGTH` is initialized. This fixes:

`ReferenceError: Cannot access 'MAX_APP_NAME_LENGTH' before initialization`

## Preserved systems
- Existing admin dashboard and authentication
- Manual device control: approve / pending / block / delete / nickname / history
- Automatic AppRegistry registration for valid Android package IDs
- `/wake` endpoint
- `/healthz` endpoint
- Existing APK/release pipeline and artifact storage modes
- Existing share/public routes and app controls
- Existing tracking start / ping / stop flow
- Current Android Smali tracking files

## Validation
`node --check index.js` passes.

## Deployment
Replace the Render project's root `index.js` with this `index.js`, commit and push, then redeploy. Do not paste secrets from `.env` into chat.
