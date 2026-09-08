"use strict";

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const { MongoStore } = require("connect-mongo");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const streamifier = require("streamifier");
const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const os = require("os");
const { execFile } = require("child_process");
const { Readable } = require("stream");
const dns = require("dns").promises;
const net = require("net");

const app = express();

/* =========================================================
   V8.3.2 ULTIMATE RENDER PRODUCTION EDITION
   (OG Device/App/Dashboard Server + Automatic APK Release Engine)
========================================================= */

const PORT = Number(process.env.PORT || 3000);
const MONGO_URI = String(process.env.MONGO_URI || "").trim();
const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || "admin");
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";
const NODE_ENV = String(process.env.NODE_ENV || "development");
const IS_PRODUCTION = NODE_ENV === "production";
const SESSION_SECRET = process.env.SESSION_SECRET || (!IS_PRODUCTION ? crypto.randomBytes(48).toString("hex") : "");
const REDIRECT_URL = process.env.REDIRECT_URL || "https://wa.me/918099188409?text=Hello%20Developer,%20please%20activate%20my%20app";

const ONLINE_TIMEOUT_MS = Math.max(10000, Number(process.env.ONLINE_TIMEOUT_MS || 45000));
const CLEANUP_INTERVAL_MS = Math.max(5000, Number(process.env.CLEANUP_INTERVAL_MS || 15000));
const DASHBOARD_REFRESH_SECONDS = 15;
const DEVICES_PER_PAGE = 20;

const MAX_DEVICE_ID_LENGTH = 200;
const MAX_NICKNAME_LENGTH = 50;
const MAX_SEARCH_LENGTH = 100;
const MAX_APP_ID_LENGTH = 200;
const MAX_APP_NAME_LENGTH = 100;
const MAX_DESCRIPTION_LENGTH = 500;
const MAX_VERSION_NAME_LENGTH = 50;
const MAX_PACKAGE_LENGTH = 200;
const MAX_URL_LENGTH = 500;
const MAX_HASH_LENGTH = 64;
const ADMIN_SESSION_MAX_AGE = 24 * 60 * 60 * 1000;

/* ---- APK release pipeline configuration ---- */
const APK_MAX_SIZE_BYTES = Math.max(1024 * 1024, Number(process.env.APK_MAX_SIZE_BYTES || 400 * 1024 * 1024));
const TEMP_UPLOAD_DIR = String(process.env.TEMP_UPLOAD_DIR || path.join(os.tmpdir(), "apk_store_releases"));
const AAPT_PATH = String(process.env.AAPT_PATH || (fs.existsSync("/opt/android-sdk/build-tools/36.0.0/aapt2") ? "/opt/android-sdk/build-tools/36.0.0/aapt2" : "aapt2"));
const AAPT_FALLBACK_PATH = String(process.env.AAPT_FALLBACK_PATH || (fs.existsSync("/opt/android-sdk/build-tools/36.0.0/aapt") ? "/opt/android-sdk/build-tools/36.0.0/aapt" : "aapt"));
const APKSIGNER_PATH = String(process.env.APKSIGNER_PATH || (fs.existsSync("/opt/android-sdk/build-tools/36.0.0/apksigner") ? "/opt/android-sdk/build-tools/36.0.0/apksigner" : "apksigner"));
const BSDIFF_CLI_PATH = String(process.env.BSDIFF_CLI_PATH || "bsdiff");
const BSPATCH_CLI_PATH = String(process.env.BSPATCH_CLI_PATH || "bspatch");
const RELEASE_WORKER_INTERVAL_MS = Math.max(1000, Number(process.env.RELEASE_WORKER_INTERVAL_MS || 4000));
const STALE_JOB_TIMEOUT_MS = Math.max(60000, Number(process.env.STALE_JOB_TIMEOUT_MS || 15 * 60 * 1000));
const WORKER_HEARTBEAT_INTERVAL_MS = Math.max(5000, Number(process.env.WORKER_HEARTBEAT_INTERVAL_MS || Math.floor(STALE_JOB_TIMEOUT_MS / 3)));
const MAX_JOB_ATTEMPTS = Math.max(1, Number(process.env.MAX_JOB_ATTEMPTS || 3));
const PATCH_USELESS_RATIO = Math.min(1, Math.max(0.1, Number(process.env.PATCH_USELESS_RATIO || 0.9)));
const WORKER_ID = `${os.hostname()}-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;

/* ---- Artifact storage modes ----
   manual      = generate + verify locally; admin hosts artifacts externally
   github      = GitHub Release assets through the GitHub API
   custom_http = user-controlled HTTP PUT/GET storage endpoint
   firebase    = Firebase Storage (EXPLICIT OPT-IN; never enabled by credentials alone)
*/
const ARTIFACT_STORAGE_MODE = String(process.env.ARTIFACT_STORAGE_MODE || "manual").trim().toLowerCase();
const ALLOWED_ARTIFACT_STORAGE_MODES = new Set(["manual", "github", "custom_http", "firebase"]);

const FIREBASE_STORAGE_BUCKET = String(process.env.FIREBASE_STORAGE_BUCKET || "").trim();
const FIREBASE_SERVICE_ACCOUNT_JSON = String(process.env.FIREBASE_SERVICE_ACCOUNT_JSON || "").trim();
const FIREBASE_SIGNED_URL_EXPIRY_MS = Math.min(1000 * 60 * 60 * 24 * 6, Math.max(60000, Number(process.env.FIREBASE_SIGNED_URL_EXPIRY_MS || 1000 * 60 * 60 * 24 * 6)));

const GITHUB_TOKEN = String(process.env.GITHUB_TOKEN || "").trim();
const GITHUB_OWNER = String(process.env.GITHUB_OWNER || "").trim();
const GITHUB_REPO = String(process.env.GITHUB_REPO || "").trim();
const GITHUB_API_BASE = String(process.env.GITHUB_API_BASE || "https://api.github.com").replace(/\/$/, "");
const GITHUB_RELEASE_PREFIX = String(process.env.GITHUB_RELEASE_PREFIX || "apk").trim().substring(0, 40);
const TRUST_PROXY = String(process.env.TRUST_PROXY || "false").trim();
const MAX_ARTIFACT_DOWNLOAD_BYTES = (() => { const n = Number(process.env.MAX_ARTIFACT_DOWNLOAD_BYTES || APK_MAX_SIZE_BYTES); return Number.isFinite(n) ? Math.max(APK_MAX_SIZE_BYTES, n) : APK_MAX_SIZE_BYTES; })();

const CUSTOM_STORAGE_UPLOAD_URL_TEMPLATE = String(process.env.CUSTOM_STORAGE_UPLOAD_URL_TEMPLATE || "").trim();
const CUSTOM_STORAGE_DOWNLOAD_URL_TEMPLATE = String(process.env.CUSTOM_STORAGE_DOWNLOAD_URL_TEMPLATE || "").trim();
const CUSTOM_STORAGE_DELETE_URL_TEMPLATE = String(process.env.CUSTOM_STORAGE_DELETE_URL_TEMPLATE || "").trim();
const CUSTOM_STORAGE_API_KEY = String(process.env.CUSTOM_STORAGE_API_KEY || "").trim();

if (!ALLOWED_ARTIFACT_STORAGE_MODES.has(ARTIFACT_STORAGE_MODE)) {
  console.error("FATAL: Invalid ARTIFACT_STORAGE_MODE. Use manual, github, custom_http, or firebase.");
  process.exit(1);
}

if (!MONGO_URI) { console.error("FATAL: MONGO_URI is missing."); process.exit(1); }
if (!ADMIN_PASSWORD && !ADMIN_PASSWORD_HASH) { console.error("FATAL: ADMIN_PASSWORD or ADMIN_PASSWORD_HASH is required."); process.exit(1); }
if (IS_PRODUCTION && !ADMIN_PASSWORD_HASH) { console.error("FATAL: ADMIN_PASSWORD_HASH is required in production."); process.exit(1); }
if (IS_PRODUCTION && !/^\$2[aby]\$\d{2}\$/.test(ADMIN_PASSWORD_HASH)) { console.error("FATAL: ADMIN_PASSWORD_HASH must be a valid bcrypt hash."); process.exit(1); }
if (IS_PRODUCTION && (!SESSION_SECRET || SESSION_SECRET.length < 32)) { console.error("FATAL: SESSION_SECRET must be at least 32 characters in production."); process.exit(1); }

try {
  cloudinary.config({
    cloud_name: String(process.env.CLOUDINARY_CLOUD_NAME || "").trim(),
    api_key: String(process.env.CLOUDINARY_API_KEY || "").trim(),
    api_secret: String(process.env.CLOUDINARY_API_SECRET || "").trim()
  });
} catch (err) {
  console.error("Cloudinary config error:", err);
}

/* ---- Firebase Admin initialization ---- */
let firebaseBucket = null;
let firebaseEnabled = false;
try {
  if (ARTIFACT_STORAGE_MODE === "firebase" && FIREBASE_SERVICE_ACCOUNT_JSON && FIREBASE_STORAGE_BUCKET) {
    const admin = require("firebase-admin");
    let serviceAccount;
    try {
      const raw = FIREBASE_SERVICE_ACCOUNT_JSON.trim().startsWith("{")
        ? FIREBASE_SERVICE_ACCOUNT_JSON
        : Buffer.from(FIREBASE_SERVICE_ACCOUNT_JSON, "base64").toString("utf8");
      serviceAccount = JSON.parse(raw);
    } catch (parseErr) {
      throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON or base64-JSON: " + parseErr.message);
    }
    if (!admin.apps.length) {
      admin.initializeApp({ credential: admin.credential.cert(serviceAccount), storageBucket: FIREBASE_STORAGE_BUCKET });
    }
    firebaseBucket = admin.storage().bucket();
    firebaseEnabled = true;
    console.log("Firebase Storage artifact store initialized: bucket=" + FIREBASE_STORAGE_BUCKET);
  } else if (ARTIFACT_STORAGE_MODE === "firebase") {
    console.warn("Firebase mode selected but credentials/bucket are missing. Artifact pipeline is disabled.");
  } else {
    console.log("Firebase Storage is OFF. Active artifact storage mode: " + ARTIFACT_STORAGE_MODE);
  }
} catch (err) {
  console.error("Firebase initialization error (release pipeline disabled):", err.message);
  firebaseBucket = null;
  firebaseEnabled = false;
}

if (TRUST_PROXY === "false" || TRUST_PROXY === "0") app.set("trust proxy", false);
else if (/^\d+$/.test(TRUST_PROXY)) {
  const proxyHops = Number(TRUST_PROXY);
  if (!Number.isSafeInteger(proxyHops) || proxyHops < 0 || proxyHops > 10) { console.error("FATAL: TRUST_PROXY hop count must be an integer from 0 to 10."); process.exit(1); }
  app.set("trust proxy", proxyHops);
}
else if (TRUST_PROXY === "true") {
  if (IS_PRODUCTION) { console.error("FATAL: TRUST_PROXY=true is forbidden in production. Set TRUST_PROXY to a controlled hop count."); process.exit(1); }
  app.set("trust proxy", true);
} else {
  console.error("FATAL: Invalid TRUST_PROXY. Use false, 0, or a numeric proxy hop count.");
  process.exit(1);
}
app.disable("x-powered-by");
app.get("/healthz", (req, res) => {
  const dbReady = mongoose.connection.readyState === 1;
  res.status(dbReady ? 200 : 503).json({ status: dbReady ? "ok" : "degraded" });
});
app.use(express.urlencoded({ extended: true, limit: "100kb" }));
app.use(express.json({ limit: "100kb" }));
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(24).toString("base64");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  res.setHeader("Content-Security-Policy", `default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' https: data:; style-src 'self' 'nonce-${res.locals.cspNonce}'; style-src-attr 'unsafe-inline'; script-src 'self' 'nonce-${res.locals.cspNonce}' https://cdn.jsdelivr.net; connect-src 'self'; form-action 'self';`);
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  if (IS_PRODUCTION) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  const originalSend = res.send.bind(res);
  res.send = (body) => { if (typeof body === "string") body = body.replace(/__CSP_NONCE__/g, res.locals.cspNonce); return originalSend(body); };
  next();
});

app.use(session({
  name: "admin.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: MONGO_URI, collectionName: "admin_sessions", ttl: ADMIN_SESSION_MAX_AGE / 1000, autoRemove: "native" }),
  cookie: { httpOnly: true, secure: IS_PRODUCTION, sameSite: "lax", maxAge: ADMIN_SESSION_MAX_AGE }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: "Too many login attempts." });
const trackingLimiter = rateLimit({ windowMs: 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false, message: { status: "ERROR", message: "RATE_LIMITED" } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
const adminActionLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false, message: "Too many admin actions. Please try again shortly." });
const releaseUploadLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: "Too many APK uploads. Please try again shortly." });

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 11, fields: 30, parts: 45 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === "iconFile" || file.fieldname === "screenshotFiles") {
      if (!String(file.mimetype || "").toLowerCase().startsWith("image/")) { return cb(new Error("Only image files are allowed for icon/screenshots.")); }
      return cb(null, true);
    }
    return cb(new Error("Unexpected upload field."));
  }
});

function isSupportedImageBuffer(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return false;
  const png = buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]));
  const jpeg = buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  const gif = buffer.subarray(0, 6).toString("ascii") === "GIF87a" || buffer.subarray(0, 6).toString("ascii") === "GIF89a";
  const webp = buffer.subarray(0, 4).toString("ascii") === "RIFF" && buffer.subarray(8, 12).toString("ascii") === "WEBP";
  return png || jpeg || gif || webp;
}

function uploadToCloudinary(buffer, folderName) {
  return new Promise((resolve, reject) => {
    if (!buffer || !buffer.length) return reject(new Error("Empty upload."));
    if (!isSupportedImageBuffer(buffer)) return reject(new Error("Image content signature is invalid."));
    const uploadStream = cloudinary.uploader.upload_stream({ folder: folderName, resource_type: "image" }, (error, result) => {
      if (error) return reject(error);
      if (!result || !result.secure_url) return reject(new Error("Cloudinary did not return a secure URL."));
      resolve(result.secure_url);
    });
    streamifier.createReadStream(buffer).pipe(uploadStream);
  });
}

function extractCloudinaryPublicId(url) {
  if (!url || typeof url !== "string") return null;
  const match = url.match(/\/upload\/(?:v\d+\/)?(.+)\.[a-zA-Z0-9]+$/);
  return match ? match[1] : null;
}

async function ensureTempDir() { await fsp.mkdir(TEMP_UPLOAD_DIR, { recursive: true }); }
const releaseStorage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try { await ensureTempDir(); cb(null, TEMP_UPLOAD_DIR); } catch (err) { cb(err); }
  },
  filename: (req, file, cb) => {
    const safeName = crypto.randomBytes(16).toString("hex") + "-" + Date.now() + path.extname(file.originalname || "").toLowerCase();
    cb(null, safeName);
  }
});
const releaseUpload = multer({
  storage: releaseStorage,
  limits: { fileSize: APK_MAX_SIZE_BYTES, files: 12, fields: 20, parts: 40 },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === "apkFile") {
      const nameOk = String(file.originalname || "").toLowerCase().endsWith(".apk");
      const mimeOk = ["application/vnd.android.package-archive", "application/octet-stream", "application/zip"].includes(String(file.mimetype || "").toLowerCase());
      if (!nameOk) return cb(new Error("Only .apk files are allowed for signed APK upload."));
      if (!mimeOk) return cb(new Error("Unexpected content-type for APK upload."));
      return cb(null, true);
    }
    if (file.fieldname === "iconFile" || file.fieldname === "screenshotFiles") {
      if (!String(file.mimetype || "").toLowerCase().startsWith("image/")) return cb(new Error("Only image files are allowed for icon/screenshots."));
      return cb(null, true);
    }
    return cb(new Error("Unexpected upload field."));
  }
});

class ReleaseSecurityError extends Error {
  constructor(message, code = "RELEASE_SECURITY_ERROR") {
    super(message);
    this.name = "ReleaseSecurityError";
    this.code = code;
  }
}

/* =========================================================
   SCHEMAS
========================================================= */
const AppRegistrySchema = new mongoose.Schema({
  appId: { type: String, required: true, unique: true, index: true, trim: true, maxlength: MAX_APP_ID_LENGTH },
  appName: { type: String, required: true, trim: true, maxlength: MAX_APP_NAME_LENGTH },
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

const DeviceSchema = new mongoose.Schema({
  deviceId: { type: String, required: true, index: true, trim: true, maxlength: MAX_DEVICE_ID_LENGTH },
  appId: { type: String, required: true, default: "default_app", index: true, trim: true, maxlength: MAX_APP_ID_LENGTH },
  nickname: { type: String, default: "", trim: true, maxlength: MAX_NICKNAME_LENGTH },
  status: { type: String, enum: ["pending", "approved", "blocked"], default: "pending", index: true },
  registeredAt: { type: Date, default: Date.now, index: true }
}, { versionKey: false });
DeviceSchema.index({ deviceId: 1, appId: 1 }, { unique: true });

const SessionSchema = new mongoose.Schema({
  deviceId: { type: String, required: true, index: true, maxlength: MAX_DEVICE_ID_LENGTH },
  appId: { type: String, required: true, default: "default_app", index: true, maxlength: MAX_APP_ID_LENGTH },
  startTime: { type: Date, required: true, index: true },
  lastSeenTime: { type: Date, required: true, index: true },
  endTime: { type: Date, default: null },
  startTimestamp: { type: Number, required: true, index: true },
  lastSeenTimestamp: { type: Number, required: true, index: true },
  endTimestamp: { type: Number, default: null, index: true },
  durationMs: { type: Number, default: 0 },
  status: { type: String, enum: ["online", "offline"], default: "online", index: true },
  endReason: { type: String, enum: ["stop", "timeout", "blocked", "pending", null], default: null }
}, { versionKey: false });
SessionSchema.index({ deviceId: 1, appId: 1, startTimestamp: -1 });
SessionSchema.index({ status: 1, lastSeenTimestamp: 1 });
SessionSchema.index({ deviceId: 1, appId: 1 }, { unique: true, partialFilterExpression: { status: "online" }, name: "unique_online_session_per_device_app" });

const ApkSchema = new mongoose.Schema({
  appName: { type: String, required: true, trim: true, maxlength: MAX_APP_NAME_LENGTH },
  description: { type: String, default: "", trim: true, maxlength: MAX_DESCRIPTION_LENGTH },
  versionName: { type: String, required: true, trim: true, maxlength: MAX_VERSION_NAME_LENGTH },
  versionCode: { type: Number, required: true, min: 1, index: true },
  packageName: { type: String, required: true, trim: true, maxlength: MAX_PACKAGE_LENGTH, index: true },
  apkUrl: { type: String, required: true, trim: true, maxlength: MAX_URL_LENGTH },
  patchUrl: { type: String, default: "", trim: true, maxlength: MAX_URL_LENGTH },
  iconUrl: { type: String, default: "", trim: true, maxlength: MAX_URL_LENGTH },
  screenshots: { type: [String], default: [] },
  apkSha256: { type: String, default: "", trim: true, lowercase: true, maxlength: MAX_HASH_LENGTH },
  signatureSha256: { type: String, default: "", trim: true, lowercase: true, maxlength: MAX_HASH_LENGTH },
  createdAt: { type: Date, default: Date.now, index: true },
  status: { type: String, enum: ["published", "queued", "processing", "failed", "retired"], default: "published", index: true },
  origin: { type: String, enum: ["automatic", "manual"], default: "manual" },
  apkSizeBytes: { type: Number, default: 0 },
  apkSize: { type: Number, default: 0 }, 
  patchSha256: { type: String, default: "", trim: true, lowercase: true, maxlength: MAX_HASH_LENGTH },
  patchSizeBytes: { type: Number, default: 0 },
  patchSize: { type: Number, default: 0 }, 
  patchFromVersionCode: { type: Number, default: null },
  patchToVersionCode: { type: Number, default: null },
  previousVersionCode: { type: Number, default: null },
  baseApkSha256: { type: String, default: "", trim: true, lowercase: true, maxlength: MAX_HASH_LENGTH },
  targetApkSha256: { type: String, default: "", trim: true, lowercase: true, maxlength: MAX_HASH_LENGTH },
  apkStoragePath: { type: String, default: "" },
  patchStoragePath: { type: String, default: "" },
  artifactStorageMode: { type: String, default: "manual" },
  githubReleaseId: { type: Number, default: null },
  githubReleaseTag: { type: String, default: "", trim: true, maxlength: 200 },
  githubApkAssetId: { type: Number, default: null },
  githubPatchAssetId: { type: Number, default: null },
  releaseJobId: { type: mongoose.Schema.Types.ObjectId, default: null, index: true },
  publishedAt: { type: Date, default: null, index: true }
}, { versionKey: false });

ApkSchema.index({ packageName: 1, versionCode: -1, createdAt: -1 }, { name: "apk_package_version_history" });
ApkSchema.index({ packageName: 1, versionCode: 1 }, { unique: true, partialFilterExpression: { status: "published" }, name: "unique_published_release_pkg_vc" });

const ReleaseJobSchema = new mongoose.Schema({
  status: { type: String, enum: ["queued", "processing", "awaiting_upload", "published", "failed"], default: "queued", index: true },
  originalFilename: { type: String, default: "" },
  apkTempPath: { type: String, default: "" },
  submittedDescription: { type: String, default: "", maxlength: MAX_DESCRIPTION_LENGTH },
  submittedIconUrl: { type: String, default: "" },
  submittedScreenshots: { type: [String], default: [] },

  extractedAppName: { type: String, default: "" },
  extractedPackageName: { type: String, default: "", index: true },
  extractedVersionName: { type: String, default: "" },
  extractedVersionCode: { type: Number, default: null },
  extractedSignatureSha256: { type: String, default: "" },
  targetApkSha256: { type: String, default: "" },
  targetApkSizeBytes: { type: Number, default: 0 },

  previousReleaseId: { type: mongoose.Schema.Types.ObjectId, default: null },
  previousVersionCode: { type: Number, default: null },
  previousApkStoragePath: { type: String, default: "" },
  previousApkSha256: { type: String, default: "" },

  patchGenerated: { type: Boolean, default: false },
  patchSha256: { type: String, default: "" },
  patchSizeBytes: { type: Number, default: 0 },
  patchStoragePath: { type: String, default: "" },
  
  stagingApkStoragePath: { type: String, default: "" },
  stagingPatchStoragePath: { type: String, default: "" },
  manualApkTempPath: { type: String, default: "" },
  manualPatchTempPath: { type: String, default: "" },
  artifactStorageMode: { type: String, default: "manual" },
  githubReleaseId: { type: Number, default: null },
  githubReleaseTag: { type: String, default: "", trim: true, maxlength: 200 },
  githubApkAssetId: { type: Number, default: null },
  githubPatchAssetId: { type: Number, default: null },
  manualVerified: { type: Boolean, default: false },

  apkStoragePath: { type: String, default: "" },
  apkPublicUrl: { type: String, default: "" },
  patchPublicUrl: { type: String, default: "" },

  releaseId: { type: mongoose.Schema.Types.ObjectId, default: null },

  attempts: { type: Number, default: 0 },
  lastError: { type: String, default: "" },
  lastErrorCode: { type: String, default: "", maxlength: 120 },
  stage: { type: String, default: "queued", maxlength: 120, index: true },
  stageUpdatedAt: { type: Date, default: null },
  
  workerId: { type: String, default: "" },
  leaseToken: { type: String, default: "", index: true },
  leaseVersion: { type: Number, default: 0 },
  heartbeatAt: { type: Date, default: null, index: true },
  
  claimedAt: { type: Date, default: null },
  startedAt: { type: Date, default: null },
  completedAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now, index: true }
}, { versionKey: false });

ReleaseJobSchema.index({ status: 1, createdAt: 1 });
ReleaseJobSchema.index({ status: 1, heartbeatAt: 1 });
ReleaseJobSchema.index({ extractedPackageName: 1, extractedVersionCode: 1 });
ReleaseJobSchema.index({ status: 1, stage: 1, stageUpdatedAt: 1 });

const AppRegistry = mongoose.model("AppRegistry", AppRegistrySchema);
const Device = mongoose.model("Device", DeviceSchema);
const UsageSession = mongoose.model("UsageSession", SessionSchema);
const Apk = mongoose.model("Apk", ApkSchema);
const ReleaseJob = mongoose.model("ReleaseJob", ReleaseJobSchema);

/* Per-package publication lock. A transaction updates this single document before
   reading the latest published version, serializing concurrent publications for
   the same package and closing the v2/v3 -> v3/v2 monotonic race. */
const ReleasePackageLockSchema = new mongoose.Schema({
  packageName: { type: String, required: true, unique: true, index: true, maxlength: MAX_PACKAGE_LENGTH },
  lastTouchedAt: { type: Date, default: Date.now, index: true }
}, { versionKey: false });
const ReleasePackageLock = mongoose.model("ReleasePackageLock", ReleasePackageLockSchema);

/* =========================================================
   HELPERS
========================================================= */
function escapeHtml(value) { return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;"); }
function safeString(value, maxLength) { return String(value ?? "").trim().substring(0, maxLength); }
function isValidPackageName(value) { return /^[A-Za-z][A-Za-z0-9_\.]*$/.test(String(value || "")); }
function isValidAppId(value) { const s = String(value || "").trim(); return s.length > 0 && s.length <= MAX_APP_ID_LENGTH && !/[\r\n<>"']/.test(s); }
function isValidVersionName(value) { const s = String(value || "").trim(); return s.length > 0 && s.length <= MAX_VERSION_NAME_LENGTH && !/[\r\n<>]/.test(s); }
function parsePositiveVersionCode(value) { const s = String(value ?? "").trim(); if (!/^\d+$/.test(s)) return null; const n = Number(s); if (!Number.isSafeInteger(n) || n < 1) return null; return n; }
function normalizeSha256(value) { const s = String(value ?? "").trim().toLowerCase(); if (!s) return ""; return /^[a-f0-9]{64}$/.test(s) ? s : null; }
function isValidHttpUrl(value) { try { const u = new URL(String(value || "").trim()); return (u.protocol === "https:" || u.protocol === "http:") && !!u.hostname; } catch (err) { return false; } }

function safeDate(value) {
  if (!value) return "N/A"; const date = new Date(value); if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("en-IN", { timeZone: "Asia/Kolkata", dateStyle: "medium", timeStyle: "medium", hour12: true });
}
function formatDuration(ms) {
  const safeMs = Number(ms); if (!Number.isFinite(safeMs) || safeMs <= 0) return "0s";
  const totalSeconds = Math.floor(safeMs / 1000); const days = Math.floor(totalSeconds / 86400); const hours = Math.floor((totalSeconds % 86400) / 3600); const minutes = Math.floor((totalSeconds % 3600) / 60); const seconds = totalSeconds % 60;
  const parts = []; if (days > 0) parts.push(days + "d"); if (hours > 0) parts.push(hours + "h"); if (minutes > 0) parts.push(minutes + "m"); if (seconds > 0 || parts.length === 0) parts.push(seconds + "s"); return parts.join(" ");
}
function getISTStartOfDay() {
  const now = new Date(); const formatter = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Kolkata", year: "numeric", month: "2-digit", day: "2-digit" });
  const parts = formatter.formatToParts(now); const values = {}; parts.forEach((part) => { if (part.type !== "literal") values[part.type] = part.value; });
  return Date.UTC(Number(values.year), Number(values.month) - 1, Number(values.day), 0, 0, 0) - (5.5 * 60 * 60 * 1000);
}
function getRange(filter, customFrom, customTo) {
  const now = Date.now(); let from = null; let to = now;
  if (filter === "today") from = getISTStartOfDay();
  if (filter === "7d") from = now - (7 * 24 * 60 * 60 * 1000);
  if (filter === "30d") from = now - (30 * 24 * 60 * 60 * 1000);
  if (filter === "custom") {
    if (customFrom) { const parsed = new Date(customFrom + "T00:00:00+05:30"); if (!Number.isNaN(parsed.getTime())) from = parsed.getTime(); }
    if (customTo) { const parsed = new Date(customTo + "T23:59:59.999+05:30"); if (!Number.isNaN(parsed.getTime())) to = parsed.getTime(); }
  }
  if (from !== null && from > to) { const temp = from; from = to; to = temp; }
  return { from, to };
}
function getObjectId(value) { const s = safeString(value, 100); return mongoose.Types.ObjectId.isValid(s) ? s : null; }
function parseExistingScreenshots(value) {
  if (!value) return []; try {
    const parsed = JSON.parse(value); if (!Array.isArray(parsed)) return [];
    return parsed.filter((x) => typeof x === "string" && isValidHttpUrl(x)).slice(0, 10).map((x) => x.substring(0, MAX_URL_LENGTH));
  } catch (err) { return []; }
}
function normalizeScreenshotUrls(list) {
  return Array.from(new Set((Array.isArray(list) ? list : []).filter((x) => typeof x === "string" && isValidHttpUrl(x)).map((x) => x.trim().substring(0, MAX_URL_LENGTH)))).slice(0, 10);
}

function csrfProtection(req, res, next) {
  if (!req.session) return res.status(500).send("Session unavailable.");
  const method = req.method.toUpperCase(); const protectedMethod = ["POST", "PUT", "PATCH", "DELETE"].includes(method);
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  res.locals.csrfToken = req.session.csrfToken;
  if (protectedMethod) { const token = req.body?._csrf || req.get("x-csrf-token"); if (!token || token !== req.session.csrfToken) return res.status(403).send("CSRF validation failed."); }
  next();
}
function requireMultipartCsrfHeader(req, res, next) {
  if (!req.session) return res.status(500).send("Session unavailable.");
  const token = req.get("x-csrf-token");
  if (!token || token !== req.session.csrfToken) return res.status(403).send("CSRF validation failed.");
  next();
}

function requireLogin(req, res, next) { if (req.session && req.session.adminAuthenticated === true) return next(); return res.redirect("/login"); }
function requireApiLogin(req, res, next) { if (req.session && req.session.adminAuthenticated === true) return next(); return res.status(401).json({ success: false, error: "UNAUTHORIZED" }); }
async function verifyPassword(password) {
  if (ADMIN_PASSWORD_HASH) return bcrypt.compare(String(password || ""), ADMIN_PASSWORD_HASH);
  if (!ADMIN_PASSWORD) return false;
  const input = Buffer.from(String(password || "")); const stored = Buffer.from(ADMIN_PASSWORD);
  if (input.length !== stored.length) return false; return crypto.timingSafeEqual(input, stored);
}

async function closeOnlineSession(deviceId, appId, reason, timestamp) {
  const now = Number(timestamp) || Date.now(); const nowDate = new Date(now);
  return UsageSession.findOneAndUpdate(
    { deviceId, appId, status: "online" },
    [
      { $set: {
        status: "offline", endReason: reason, endTime: nowDate, endTimestamp: now,
        lastSeenTime: nowDate, lastSeenTimestamp: now,
        durationMs: { $max: [0, { $subtract: [now, "$startTimestamp"] }] }
      }}
    ],
    { new: true, sort: { startTimestamp: -1 } }
  );
}

let cleanupRunning = false;
async function markStaleSessionsOffline() {
  if (cleanupRunning) return; cleanupRunning = true;
  try {
    const now = Date.now(); const cutoff = now - ONLINE_TIMEOUT_MS;
    const staleSessions = await UsageSession.find({ status: "online", lastSeenTimestamp: { $lt: cutoff } }).select({ _id: 1, startTimestamp: 1, lastSeenTimestamp: 1 }).lean();
    if (!staleSessions.length) return;
    const operations = staleSessions.map((item) => {
      const endTimestamp = Number(item.lastSeenTimestamp); const duration = Math.max(0, endTimestamp - Number(item.startTimestamp));
      return { updateOne: { filter: { _id: item._id, status: "online" }, update: { $set: { status: "offline", endReason: "timeout", endTime: new Date(endTimestamp), endTimestamp, durationMs: duration } } } };
    });
    if (operations.length) await UsageSession.bulkWrite(operations, { ordered: false });
  } catch (err) { console.error("Session cleanup error:", err.message); } finally { cleanupRunning = false; }
}
const cleanupInterval = setInterval(markStaleSessionsOffline, CLEANUP_INTERVAL_MS);
cleanupInterval.unref();

async function assertRegisteredApp(appId) {
  const registry = await AppRegistry.findOne({ appId }).select({ _id: 1 }).lean();
  if (!registry) {
    const err = new Error("APP_NOT_REGISTERED");
    err.code = "APP_NOT_REGISTERED";
    throw err;
  }
  return true;
}

async function handleTracking(req, res) {
  const deviceId = safeString(req.query.id || req.body?.id, MAX_DEVICE_ID_LENGTH);
  const appId = safeString(req.query.appId || req.body?.appId, MAX_APP_ID_LENGTH) || "default_app";
  let rawAction = String(req.query.action || req.body?.action || req.query.status || req.body?.status || "start").trim().toLowerCase();
  if (rawAction === "offline") rawAction = "stop"; const action = ["start", "ping", "stop"].includes(rawAction) ? rawAction : "start";

  if (!deviceId) return res.status(400).json({ status: "ERROR", message: "DEVICE_ID_MISSING" });
  if (!isValidAppId(appId)) return res.status(400).json({ status: "ERROR", message: "APP_ID_INVALID" });
  if (mongoose.connection.readyState !== 1) return res.status(503).json({ status: "ERROR", message: "DATABASE_OFFLINE" });

  try {
    await assertRegisteredApp(appId);

    let device = await Device.findOne({ deviceId, appId });
    if (!device) {
      try { device = await Device.create({ deviceId, appId, status: "pending", registeredAt: new Date() }); }
      catch (err) { if (err && err.code === 11000) device = await Device.findOne({ deviceId, appId }); else throw err; }
    }

    if (!device || device.status !== "approved") {
      await closeOnlineSession(deviceId, appId, device && device.status === "blocked" ? "blocked" : "pending", Date.now());
      return res.json({ status: "BLOCKED", redirectUrl: REDIRECT_URL });
    }

    const now = Date.now(); const nowDate = new Date(now);
    if (action === "stop") {
      const stopped = await closeOnlineSession(deviceId, appId, "stop", now);
      return res.json({ status: "ALLOWED", action: stopped ? "STOPPED" : "NO_ACTIVE_SESSION" });
    }

    let activeSession = await UsageSession.findOne({ deviceId, appId, status: "online" });
    if (activeSession) {
      activeSession.lastSeenTime = nowDate; activeSession.lastSeenTimestamp = now; await activeSession.save();
      return res.json({ status: "ALLOWED", action: "HEARTBEAT" });
    }

    try { activeSession = await UsageSession.create({ deviceId, appId, startTime: nowDate, lastSeenTime: nowDate, startTimestamp: now, lastSeenTimestamp: now, status: "online" }); }
    catch (err) {
      if (err && err.code === 11000) { activeSession = await UsageSession.findOneAndUpdate({ deviceId, appId, status: "online" }, { $set: { lastSeenTime: nowDate, lastSeenTimestamp: now } }, { new: true }); } else { throw err; }
    }

    return res.json({ status: "ALLOWED", action: "STARTED", sessionId: activeSession ? String(activeSession._id) : null });
  } catch (err) {
    if (err && err.code === "APP_NOT_REGISTERED") return res.status(404).json({ status: "ERROR", message: "APP_NOT_REGISTERED" });
    console.error("Tracking error:", err.message);
    return res.status(500).json({ status: "ERROR", message: "TRACKING_FAILED" });
  }
}

app.get(["/track", "/index.php"], trackingLimiter, handleTracking);
app.post(["/track", "/index.php"], trackingLimiter, handleTracking);

/* =========================================================
   RELEASE-PIPELINE HELPERS
========================================================= */

function runCli(cmd, args, options) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { maxBuffer: 1024 * 1024 * 32, ...(options || {}) }, (error, stdout, stderr) => {
      if (error) { error.stdout = stdout; error.stderr = stderr; return reject(error); }
      resolve({ stdout: String(stdout || ""), stderr: String(stderr || "") });
    });
  });
}

async function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

async function fileSize(filePath) { const stat = await fsp.stat(filePath); return stat.size; }

async function safeUnlink(filePath) {
  if (!filePath) return;
  try { await fsp.unlink(filePath); } catch (err) { if (err && err.code !== "ENOENT") console.error("Temp cleanup error:", filePath, err.message); }
}

async function cleanTempDir() {
  try {
    const protectedPaths = new Set();
    const manualJobs = await ReleaseJob.find({ status: "awaiting_upload" })
      .select("apkTempPath manualApkTempPath manualPatchTempPath").lean().catch(() => []);
    for (const job of manualJobs) {
      for (const p of [job.apkTempPath, job.manualApkTempPath, job.manualPatchTempPath]) {
        if (p) protectedPaths.add(path.resolve(p));
      }
    }

    const files = await fsp.readdir(TEMP_UPLOAD_DIR);
    const now = Date.now();
    for (const file of files) {
      const filePath = path.join(TEMP_UPLOAD_DIR, file);
      try {
        const stat = await fsp.stat(filePath);
        if (protectedPaths.has(path.resolve(filePath))) continue;
        if (now - stat.mtimeMs > STALE_JOB_TIMEOUT_MS) await safeUnlink(filePath);
      } catch(e) {}
    }
  } catch (err) {}
}

async function assertZipLikeApk(apkPath) {
  const fh = await fsp.open(apkPath, "r");
  const header = Buffer.alloc(4);
  try { await fh.read(header, 0, 4, 0); } finally { await fh.close(); }
  const sig = header.readUInt32LE(0);
  if (![0x04034b50, 0x06054b50, 0x08074b50].includes(sig)) throw new ReleaseSecurityError("Uploaded file is not a valid ZIP/APK container.", "APK_CONTAINER_INVALID");
}

async function extractApkManifestMetadata(apkPath) {
  let output = "";
  try {
    const result = await runCli(AAPT_PATH, ["dump", "badging", apkPath]);
    output = result.stdout;
  } catch (err) {
    try {
      const result = await runCli(AAPT_FALLBACK_PATH, ["dump", "badging", apkPath]);
      output = result.stdout;
    } catch (err2) {
      throw new Error("APK metadata extraction failed (aapt/aapt2 unavailable or APK unparsable): " + err2.message);
    }
  }

  const packageMatch = output.match(/package: name='([^']+)' versionCode='(\d+)' versionName='([^']*)'/);
  if (!packageMatch) throw new Error("Could not parse packageName/versionCode/versionName from APK manifest.");
  const packageName = packageMatch[1];
  const versionCode = Number(packageMatch[2]);
  const versionName = packageMatch[3];

  let appName = packageName;
  const labelMatch = output.match(/application-label:'([^']*)'/) || output.match(/application: label='([^']*)'/);
  if (labelMatch && labelMatch[1]) appName = labelMatch[1];

  if (!isValidPackageName(packageName)) throw new Error("Extracted packageName is invalid: " + packageName);
  if (!Number.isSafeInteger(versionCode) || versionCode < 1) throw new Error("Extracted versionCode is invalid.");
  if (!isValidVersionName(versionName)) throw new Error("Extracted versionName is invalid.");

  return { appName: safeString(appName, MAX_APP_NAME_LENGTH), packageName, versionName, versionCode };
}

async function extractApkSignatureSha256(apkPath) {
  let output = "";
  try {
    const result = await runCli(APKSIGNER_PATH, ["verify", "--print-certs", apkPath]);
    output = result.stdout + "\n" + result.stderr;
  } catch (err) {
    output = String((err && err.stdout) || "") + "\n" + String((err && err.stderr) || "");
    if (!output.trim()) throw new Error("Signature verification failed (apksigner unavailable or APK not validly signed): " + err.message);
  }
  const digestMatch = output.match(/(?:Signer\s+#\d+\s+certificate\s+SHA-256\s+digest|SHA-256\s+digest):\s*([a-fA-F0-9:]+)/i);
  if (!digestMatch) throw new Error("Could not extract signing certificate SHA-256 from apksigner output. Is the APK validly signed?");
  const sha = digestMatch[1].replace(/:/g, "").toLowerCase();
  const normalized = normalizeSha256(sha);
  if (!normalized) throw new Error("Extracted signature digest is not a valid SHA-256 hash.");
  return normalized;
}

let bsdiffModule = null;
try { bsdiffModule = require("@bsdiff-rust/node"); } catch (err) { bsdiffModule = null; }

async function generateBsdiffPatch(oldPath, newPath, patchPath) {
  if (bsdiffModule && typeof bsdiffModule.diff === "function") {
    await bsdiffModule.diff(oldPath, newPath, patchPath);
  } else {
    await runCli(BSDIFF_CLI_PATH, [oldPath, newPath, patchPath]);
  }
  const magic = Buffer.alloc(8);
  const fh = await fsp.open(patchPath, "r");
  try { await fh.read(magic, 0, 8, 0); } finally { await fh.close(); }
  if (magic.toString("ascii", 0, 8) !== "BSDIFF40") throw new Error("Generated patch is not a valid BSDIFF40 artifact.");
}

async function applyBsdiffPatch(oldPath, patchPath, outPath) {
  if (bsdiffModule && typeof bsdiffModule.patch === "function") {
    await bsdiffModule.patch(oldPath, patchPath, outPath);
  } else {
    await runCli(BSPATCH_CLI_PATH, [oldPath, patchPath, outPath]);
  }
}

async function firebaseGetSignedUrl(storagePath) {
  if (!firebaseEnabled || !storagePath) throw new Error("Firebase Storage is not configured or artifact path is missing.");
  const file = firebaseBucket.file(storagePath);
  const [url] = await file.getSignedUrl({
    version: "v4",
    action: "read",
    expires: Date.now() + FIREBASE_SIGNED_URL_EXPIRY_MS
  });
  if (!url) throw new Error("Firebase did not return a signed artifact URL.");
  return url;
}

async function firebaseUploadFile(localPath, storagePath, contentType) {
  if (!firebaseEnabled) throw new Error("Firebase Storage is not configured on this server.");
  const uploadOptions = {
    destination: storagePath,
    metadata: { contentType: contentType || "application/octet-stream" },
    preconditionOpts: { ifGenerationMatch: 0 }
  };
  await firebaseBucket.upload(localPath, uploadOptions);
  return firebaseGetSignedUrl(storagePath);
}

async function firebaseDeleteFile(storagePath) {
  if (!firebaseEnabled || !storagePath) return;
  try { await firebaseBucket.file(storagePath).delete({ ignoreNotFound: true }); } catch (err) { console.error("Firebase cleanup error:", storagePath, err.message); }
}

async function findAndValidatePreviousRelease(packageName, targetVersionCode, targetSignatureSha256) {
  const previous = await Apk.findOne({ packageName, status: "published", versionCode: { $lt: targetVersionCode } })
    .sort({ versionCode: -1 }).lean();
  if (!previous) return null;

  if (!previous.apkUrl && !previous.apkStoragePath) {
    throw new ReleaseSecurityError("Previous published release has no downloadable APK artifact.", "PREVIOUS_ARTIFACT_MISSING");
  }
  if (!previous.signatureSha256) {
    throw new ReleaseSecurityError("Previous published release has no signing certificate SHA-256. Patch generation is forbidden.", "PREVIOUS_SIGNATURE_MISSING");
  }
  if (!targetSignatureSha256) {
    throw new ReleaseSecurityError("Target APK signing certificate SHA-256 is missing.", "TARGET_SIGNATURE_MISSING");
  }
  if (previous.signatureSha256 !== targetSignatureSha256) {
    throw new ReleaseSecurityError("Signing certificate mismatch. Patch generation forbidden.", "SIGNATURE_MISMATCH");
  }
  return previous;
}

function storageModeLabel() {
  if (ARTIFACT_STORAGE_MODE === "firebase") return firebaseEnabled ? "firebase" : "firebase-unavailable";
  return ARTIFACT_STORAGE_MODE;
}

function assertArtifactStorageReady() {
  if (ARTIFACT_STORAGE_MODE === "manual") return true;
  if (ARTIFACT_STORAGE_MODE === "firebase") {
    if (!firebaseEnabled) throw new Error("Firebase mode is selected but Firebase Storage is not configured/authorized.");
    return true;
  }
  if (ARTIFACT_STORAGE_MODE === "github") {
    if (!GITHUB_TOKEN || !GITHUB_OWNER || !GITHUB_REPO) {
      throw new Error("GitHub mode requires GITHUB_TOKEN, GITHUB_OWNER and GITHUB_REPO.");
    }
    return true;
  }
  if (ARTIFACT_STORAGE_MODE === "custom_http") {
    if (!CUSTOM_STORAGE_UPLOAD_URL_TEMPLATE || !CUSTOM_STORAGE_DOWNLOAD_URL_TEMPLATE) {
      throw new Error("custom_http mode requires CUSTOM_STORAGE_UPLOAD_URL_TEMPLATE and CUSTOM_STORAGE_DOWNLOAD_URL_TEMPLATE.");
    }
    return true;
  }
  throw new Error("Unsupported artifact storage mode.");
}

function fillStorageTemplate(template, storagePath) {
  return String(template || "").replace(/\{path\}/g, encodeURIComponent(String(storagePath || "")));
}

function getArtifactHttpTimeout() {
  return Math.max(5000, Number(process.env.ARTIFACT_HTTP_TIMEOUT_MS || 120000));
}

async function githubApi(pathname, options = {}) {
  if (!GITHUB_TOKEN) throw new Error("GITHUB_TOKEN is missing.");
  const response = await fetch(GITHUB_API_BASE + pathname, {
    method: options.method || "GET",
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${GITHUB_TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "RD-ApkStore-ReleaseEngine/8.3.2"
    },
    body: options.body,
    signal: AbortSignal.timeout(getArtifactHttpTimeout())
  });
  const textBody = await response.text();
  let parsed = null;
  try { parsed = textBody ? JSON.parse(textBody) : null; } catch (_) {}
  if (!response.ok) {
    const message = parsed && parsed.message ? parsed.message : textBody.substring(0, 500);
    throw new Error(`GitHub API ${response.status}: ${message}`);
  }
  return parsed;
}

function githubSafeReleaseTag(packageName, versionCode, jobId) {
  const raw = `${GITHUB_RELEASE_PREFIX}-${packageName}-${versionCode}-${String(jobId || "").trim()}`;
  return raw.replace(/[^A-Za-z0-9._-]+/g, "-").substring(0, 180);
}

function githubReleaseMarker(packageName, versionCode, jobId) {
  return `RD_APK_STORE_JOB=${String(jobId || "").trim()};PACKAGE=${String(packageName || "").trim()};VERSION=${String(versionCode || "").trim()}`;
}

async function githubEnsureRelease(packageName, versionCode, jobId) {
  const tag = githubSafeReleaseTag(packageName, versionCode, jobId);
  const marker = githubReleaseMarker(packageName, versionCode, jobId);
  try {
    const existing = await githubApi(`/repos/${encodeURIComponent(GITHUB_OWNER)}/${encodeURIComponent(GITHUB_REPO)}/releases/tags/${encodeURIComponent(tag)}`);
    const body = String(existing && existing.body || "");
    if (!body.includes(marker)) {
      throw new ReleaseSecurityError(
        "GitHub deterministic release tag exists but does not belong to this ReleaseJob.",
        "GITHUB_RELEASE_PROVENANCE_MISMATCH"
      );
    }
    existing._createdByJob = true;
    existing._ownedByJob = true;
    existing._tagName = tag;
    return existing;
  } catch (err) {
    if (err && err.code === "GITHUB_RELEASE_PROVENANCE_MISMATCH") throw err;
    if (!String(err.message || "").startsWith("GitHub API 404")) throw err;
  }

  try {
    const created = await githubApi(`/repos/${encodeURIComponent(GITHUB_OWNER)}/${encodeURIComponent(GITHUB_REPO)}/releases`, {
      method: "POST",
      body: JSON.stringify({
        tag_name: tag,
        name: `${packageName} v${versionCode} [job ${String(jobId)}]`,
        body: `Automated APK Store release.\n${marker}\nArtifacts are published only after local reconstruction and remote hash verification.`,
        draft: false,
        prerelease: false
      })
    });
    created._createdByJob = true;
    created._ownedByJob = true;
    created._tagName = tag;
    return created;
  } catch (err) {
    if (!String(err.message || "").startsWith("GitHub API 422")) throw err;
    const existing = await githubApi(`/repos/${encodeURIComponent(GITHUB_OWNER)}/${encodeURIComponent(GITHUB_REPO)}/releases/tags/${encodeURIComponent(tag)}`);
    const body = String(existing && existing.body || "");
    if (!body.includes(marker)) {
      throw new ReleaseSecurityError(
        "GitHub release create raced with an unrelated release using the same tag.",
        "GITHUB_RELEASE_PROVENANCE_MISMATCH"
      );
    }
    existing._createdByJob = true;
    existing._ownedByJob = true;
    existing._tagName = tag;
    return existing;
  }
}

async function githubListReleaseAssets(releaseId) {
  const data = await githubApi(`/repos/${encodeURIComponent(GITHUB_OWNER)}/${encodeURIComponent(GITHUB_REPO)}/releases/${encodeURIComponent(releaseId)}/assets?per_page=100`);
  return Array.isArray(data) ? data : [];
}

async function githubDeleteRelease(releaseId) {
  if (!releaseId || !GITHUB_TOKEN) return;
  try { await githubApi(`/repos/${encodeURIComponent(GITHUB_OWNER)}/${encodeURIComponent(GITHUB_REPO)}/releases/${encodeURIComponent(releaseId)}`, { method: "DELETE" }); }
  catch (err) { console.error("GitHub release cleanup error:", err.message); }
}

async function githubUploadAsset(release, localPath, assetName, contentType) {
  const uploadUrl = String(release && release.upload_url || "").replace(/\{\?name,label\}$/, "");
  if (!uploadUrl) throw new Error("GitHub release upload URL is missing.");

  const existingAssets = await githubListReleaseAssets(release.id);
  for (const existing of existingAssets) {
    if (String(existing && existing.name || "") === String(assetName)) {
      await githubDeleteAsset(existing.id);
    }
  }

  const stat = await fsp.stat(localPath);
  const response = await fetch(uploadUrl + `?name=${encodeURIComponent(assetName)}`, {
    method: "POST",
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${GITHUB_TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "RD-ApkStore-ReleaseEngine/8.3.2",
      "Content-Type": contentType || "application/octet-stream",
      "Content-Length": String(stat.size)
    },
    body: Readable.toWeb(fs.createReadStream(localPath)),
    duplex: "half",
    signal: AbortSignal.timeout(getArtifactHttpTimeout())
  });
  const bodyText = await response.text();
  let parsed = null;
  try { parsed = bodyText ? JSON.parse(bodyText) : null; } catch (_) {}
  if (!response.ok) throw new Error(`GitHub asset upload ${response.status}: ${parsed && parsed.message ? parsed.message : bodyText.substring(0, 500)}`);
  if (!parsed || !parsed.id || !parsed.browser_download_url) throw new Error("GitHub did not return a usable release asset.");
  return parsed;
}

async function githubDeleteAsset(assetId) {
  if (!assetId || !GITHUB_TOKEN) return;
  try {
    await githubApi(`/repos/${encodeURIComponent(GITHUB_OWNER)}/${encodeURIComponent(GITHUB_REPO)}/releases/assets/${encodeURIComponent(assetId)}`, { method: "DELETE" });
  } catch (err) {
    console.error("GitHub artifact cleanup error:", err.message);
  }
}

async function customUploadFile(localPath, storagePath, contentType) {
  const url = fillStorageTemplate(CUSTOM_STORAGE_UPLOAD_URL_TEMPLATE, storagePath);
  const stat = await fsp.stat(localPath);
  const headers = {
    "Content-Type": contentType || "application/octet-stream",
    "Content-Length": String(stat.size),
    "User-Agent": "RD-ApkStore-ReleaseEngine/8.3.2"
  };
  if (CUSTOM_STORAGE_API_KEY) headers.Authorization = `Bearer ${CUSTOM_STORAGE_API_KEY}`;

  const response = await fetch(url, {
    method: "PUT",
    headers,
    body: Readable.toWeb(fs.createReadStream(localPath)),
    duplex: "half",
    signal: AbortSignal.timeout(getArtifactHttpTimeout())
  });
  const body = await response.text();
  if (!response.ok) throw new Error(`Custom storage upload ${response.status}: ${body.substring(0, 500)}`);
  return { storagePath, publicUrl: fillStorageTemplate(CUSTOM_STORAGE_DOWNLOAD_URL_TEMPLATE, storagePath) };
}

async function customDeleteFile(storagePath) {
  if (!CUSTOM_STORAGE_DELETE_URL_TEMPLATE || !storagePath) return;
  try {
    const url = fillStorageTemplate(CUSTOM_STORAGE_DELETE_URL_TEMPLATE, storagePath);
    const headers = { "User-Agent": "RD-ApkStore-ReleaseEngine/8.3.2" };
    if (CUSTOM_STORAGE_API_KEY) headers.Authorization = `Bearer ${CUSTOM_STORAGE_API_KEY}`;
    const response = await fetch(url, { method: "DELETE", headers, signal: AbortSignal.timeout(getArtifactHttpTimeout()) });
    if (!response.ok && response.status !== 404) console.error("Custom storage cleanup HTTP " + response.status);
  } catch (err) {
    console.error("Custom storage cleanup error:", err.message);
  }
}

function isUnsafeIpAddress(address) {
  const normalized = String(address || "").toLowerCase();
  const type = net.isIP(normalized);
  if (type === 4) {
    const o = normalized.split(".").map(Number); const a=o[0], b=o[1], c=o[2];
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 0) || (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) || a >= 224;
  }
  if (type === 6) {
    const hex = normalized.replace(/^\[|\]$/g, "");
    if (hex === "::1" || hex === "::" || hex.startsWith("fc") || hex.startsWith("fd") || hex.startsWith("fe8") || hex.startsWith("fe9") || hex.startsWith("fea") || hex.startsWith("feb") || hex.startsWith("ff")) return true;
    const mapped = hex.match(/^::ffff:(?:([0-9.]+)|([0-9a-f:]+))$/i);
    if (mapped) { const candidate = mapped[1] || mapped[2]; if (net.isIP(candidate) === 4) return isUnsafeIpAddress(candidate); }
  }
  return false;
}

async function resolvePublicAddress(hostname) {
  const clean = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
  const addresses = net.isIP(clean) ? [clean] : (await dns.lookup(clean, { all: true, verbatim: true })).map((item) => item.address);
  if (!addresses.length) throw new Error("Artifact host did not resolve.");
  for (const address of addresses) if (isUnsafeIpAddress(address)) throw new Error("Private/reserved artifact host is not allowed.");
  return addresses[0];
}

async function assertSafeArtifactUrl(rawUrl) {
  const parsed = new URL(String(rawUrl || ""));
  if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Artifact URL must use HTTP or HTTPS.");
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const blockedHostnames = new Set(["localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "broadcasthost"]);
  if (blockedHostnames.has(hostname) || hostname.endsWith(".localhost") || hostname.endsWith(".local") || hostname.endsWith(".internal")) throw new Error("Private/local artifact hosts are not allowed.");
  return { parsed, address: await resolvePublicAddress(hostname) };
}

async function downloadHttpFile(url, destination) {
  let currentUrl = String(url || "");
  for (let redirects = 0; redirects <= 5; redirects++) {
    const { parsed, address } = await assertSafeArtifactUrl(currentUrl);
    const transport = parsed.protocol === "https:" ? require("https") : require("http");
    const downloaded = await new Promise((resolve, reject) => {
      let settled = false; let bytes = 0; let req = null; let output = null;
      const fail = (err) => {
        if (settled) return;
        settled = true;
        if (output) output.destroy();
        if (req) req.destroy();
        safeUnlink(destination).catch(() => {});
        reject(err instanceof Error ? err : new Error(String(err || "Artifact download failed.")));
      };
      req = transport.get(parsed, {
        hostname: parsed.hostname, port: parsed.port || undefined, path: `${parsed.pathname}${parsed.search}`, method: "GET",
        headers: { "User-Agent": "RD-ApkStore-ReleaseEngine/8.3.2", "Accept": "*/*" },
        lookup: (_hostname, _options, cb) => cb(null, address, net.isIP(address)), servername: parsed.hostname
      }, (response) => {
        if ([301,302,303,307,308].includes(response.statusCode || 0)) {
          response.resume();
          const location = response.headers.location;
          if (!location) return fail(new Error("Artifact server returned a redirect without Location."));
          if (redirects === 5) return fail(new Error("Too many artifact download redirects."));
          currentUrl = new URL(location, parsed).toString();
          settled = true;
          return resolve({ redirect: true });
        }
        if ((response.statusCode || 500) < 200 || (response.statusCode || 500) >= 300 || !response.readable) { response.resume(); return fail(new Error(`Artifact download failed with HTTP ${response.statusCode || 0}.`)); }
        const contentLength = Number(response.headers["content-length"] || 0);
        if (Number.isFinite(contentLength) && contentLength > MAX_ARTIFACT_DOWNLOAD_BYTES) { response.resume(); return fail(new Error("Artifact download exceeds configured maximum size.")); }
        output = fs.createWriteStream(destination, { flags: "wx" });
        output.on("error", fail); response.on("error", fail);
        response.on("data", (chunk) => {
          if (settled) return;
          bytes += chunk.length;
          if (bytes > MAX_ARTIFACT_DOWNLOAD_BYTES) return response.destroy(new Error("Artifact download exceeds configured maximum size."));
          if (!output.write(chunk)) response.pause();
        });
        output.on("drain", () => response.resume());
        response.on("end", () => {
          if (settled) return;
          settled = true;
          output.end(() => resolve({ redirect: false, bytes }));
        });
      });
      req.setTimeout(getArtifactHttpTimeout(), () => fail(new Error("Artifact download timed out.")));
      req.on("error", fail);
    });
    if (downloaded.redirect) continue;
    return downloaded.bytes;
  }
  throw new Error("Artifact download failed after redirect processing.");
}

function assertArtifactStorageReadyForDownload(storagePath, publicUrl) {
  if (ARTIFACT_STORAGE_MODE === "firebase" && firebaseEnabled && storagePath) return;
  if (publicUrl) return;
  throw new Error("No downloadable artifact URL/path is available.");
}

async function artifactDownload(storagePath, publicUrl, destination, providerHint = "") {
  assertArtifactStorageReadyForDownload(storagePath, publicUrl);
  const provider = String(providerHint || "").trim().toLowerCase();
  if (provider === "firebase" && firebaseEnabled && storagePath) {
    await firebaseBucket.file(storagePath).download({ destination });
    return fileSize(destination);
  }
  if (provider === "firebase" && !publicUrl) {
    throw new Error("Firebase artifact requires Firebase access or a valid public/signed URL.");
  }
  return downloadHttpFile(publicUrl, destination);
}

async function artifactUpload(localPath, storagePath, contentType, context = {}) {
  assertArtifactStorageReady();

  if (ARTIFACT_STORAGE_MODE === "manual") {
    return { provider: "manual", storagePath: "", publicUrl: "", localPath };
  }
  if (ARTIFACT_STORAGE_MODE === "firebase") {
    return { provider: "firebase", storagePath, publicUrl: await firebaseUploadFile(localPath, storagePath, contentType) };
  }
  if (ARTIFACT_STORAGE_MODE === "custom_http") {
    return { provider: "custom_http", ...(await customUploadFile(localPath, storagePath, contentType)) };
  }
  if (ARTIFACT_STORAGE_MODE === "github") {
    if (!context.githubRelease) throw new Error("GitHub release context is missing.");
    const asset = await githubUploadAsset(context.githubRelease, localPath, context.assetName, contentType);
    return {
      provider: "github",
      storagePath: `github:${context.githubRelease.id}:${asset.id}`,
      publicUrl: asset.browser_download_url,
      assetId: asset.id
    };
  }
  throw new Error("Unsupported artifact storage mode.");
}

async function artifactDelete(storagePath) {
  if (!storagePath) return;
  if (storagePath.startsWith("github:")) {
    const parts = storagePath.split(":");
    return githubDeleteAsset(parts[2]);
  }
  if (ARTIFACT_STORAGE_MODE === "firebase") return firebaseDeleteFile(storagePath);
  if (ARTIFACT_STORAGE_MODE === "custom_http") return customDeleteFile(storagePath);
}

/* =========================================================
   WORKER LEASE & FENCING HELPERS
========================================================= */
function ownershipSnapshot(job) {
  return {
    jobId: String(job && job._id || ""),
    workerId: WORKER_ID,
    leaseVersion: Number(job && job.leaseVersion || 0)
  };
}

function makeOwnershipLostError(stage = "unknown", result = null) {
  const err = new Error(`RELEASE_JOB_OWNERSHIP_LOST${stage ? ` at ${stage}` : ""}`);
  err.code = "RELEASE_JOB_OWNERSHIP_LOST";
  err.stage = stage || "unknown";
  if (result) {
    err.matchedCount = Number(result.matchedCount || 0);
    err.modifiedCount = Number(result.modifiedCount || 0);
  }
  return err;
}

async function assertJobOwnership(job, stage = "ownership_assert") {
  try {
    const current = await ReleaseJob.findOne({
      _id: job._id,
      status: "processing",
      workerId: WORKER_ID,
      leaseToken: job.leaseToken,
      leaseVersion: job.leaseVersion
    }).select("_id").lean();

    if (!current) {
      console.error("Release job ownership check failed:", JSON.stringify(ownershipSnapshot(job)), "stage=" + stage);
      throw makeOwnershipLostError(stage);
    }
    return true;
  } catch (err) {
    if (err && err.code === "RELEASE_JOB_OWNERSHIP_LOST") throw err;
    throw err;
  }
}

async function assertActiveJobOwnership(job, state, stage = "ownership_assert") {
  if (state && state.ownershipLost) throw makeOwnershipLostError(stage);
  await assertJobOwnership(job, stage);
  if (state && state.ownershipLost) throw makeOwnershipLostError(stage);
}

async function fencedReleaseJobUpdate(job, update, options = {}, stage = "fenced_update") {
  const result = await ReleaseJob.updateOne(
    {
      _id: job._id,
      status: "processing",
      workerId: WORKER_ID,
      leaseToken: job.leaseToken,
      leaseVersion: job.leaseVersion
    },
    update,
    options
  );

  // IMPORTANT: matchedCount is the ownership/CAS signal. modifiedCount may be 0
  // when the requested values already equal the stored values, which is still a
  // valid owned job and must never be treated as lease loss.
  if (Number(result.matchedCount || 0) !== 1) {
    console.error(
      "Release job fenced update lost ownership:",
      JSON.stringify(ownershipSnapshot(job)),
      `stage=${stage} matchedCount=${Number(result.matchedCount || 0)} modifiedCount=${Number(result.modifiedCount || 0)}`
    );
    throw makeOwnershipLostError(stage, result);
  }
  return result;
}

async function heartbeatReleaseJob(job) {
  const result = await ReleaseJob.updateOne(
    { _id: job._id, status: "processing", workerId: WORKER_ID, leaseToken: job.leaseToken, leaseVersion: job.leaseVersion },
    { $set: { heartbeatAt: new Date(), stageUpdatedAt: new Date() } }
  );
  if (Number(result.matchedCount || 0) !== 1) {
    console.error(
      "Release job heartbeat lost ownership:",
      JSON.stringify(ownershipSnapshot(job)),
      `matchedCount=${Number(result.matchedCount || 0)} modifiedCount=${Number(result.modifiedCount || 0)}`
    );
    throw makeOwnershipLostError("heartbeat", result);
  }
}

async function setReleaseStage(job, stage) {
  const cleanStage = safeString(stage, 120) || "unknown";
  try {
    const result = await ReleaseJob.updateOne(
      { _id: job._id, status: "processing", workerId: WORKER_ID, leaseToken: job.leaseToken, leaseVersion: job.leaseVersion },
      { $set: { stage: cleanStage, stageUpdatedAt: new Date() } }
    );
    if (Number(result.matchedCount || 0) !== 1) {
      console.error("Release job stage update lost ownership:", JSON.stringify(ownershipSnapshot(job)), "stage=" + cleanStage);
      throw makeOwnershipLostError(cleanStage, result);
    }
  } catch (err) {
    if (err && err.code === "RELEASE_JOB_OWNERSHIP_LOST") throw err;
    console.warn(`Release job stage update failed at ${cleanStage}:`, err.message);
  }
}

async function failJobOwned(job, error, options = {}) {
  const errorMessage = error instanceof Error ? error.message : String(error || "");
  const errorCode = error && error.code ? String(error.code) : "RELEASE_JOB_FAILED";
  const result = await ReleaseJob.updateOne(
    { _id: job._id, status: "processing", workerId: WORKER_ID, leaseToken: job.leaseToken, leaseVersion: job.leaseVersion },
    {
      $set: {
        status: "failed",
        lastError: errorMessage.substring(0, 1000),
        lastErrorCode: errorCode.substring(0, 120),
        completedAt: new Date(),
        stage: "failed",
        stageUpdatedAt: new Date()
      },
      $unset: { workerId: 1, leaseToken: 1, claimedAt: 1, heartbeatAt: 1 }
    }
  );

  if (Number(result.matchedCount || 0) !== 1) {
    console.warn(`Job ${job._id} failure update skipped because ownership was lost (matched=${Number(result.matchedCount || 0)} modified=${Number(result.modifiedCount || 0)}).`);
    return;
  }

  if (options.cleanupTemp) await safeUnlink(job.apkTempPath);
  if (options.cleanupArtifacts) {
    if (job.stagingApkStoragePath) await artifactDelete(job.stagingApkStoragePath);
    if (job.stagingPatchStoragePath) await artifactDelete(job.stagingPatchStoragePath);

    if (job.submittedIconUrl) {
      const pubId = extractCloudinaryPublicId(job.submittedIconUrl);
      if (pubId) cloudinary.uploader.destroy(pubId).catch(()=>{});
    }
    for (const url of (job.submittedScreenshots || [])) {
      const pubId = extractCloudinaryPublicId(url);
      if (pubId) cloudinary.uploader.destroy(pubId).catch(()=>{});
    }
  }
}

async function ensureReleasePackageLock(packageName) {
  try {
    await ReleasePackageLock.updateOne(
      { packageName },
      { $setOnInsert: { packageName, lastTouchedAt: new Date() } },
      { upsert: true }
    );
  } catch (err) {
    if (!err || err.code !== 11000) throw err;
    const existing = await ReleasePackageLock.findOne({ packageName }).select("_id").lean();
    if (!existing) throw new Error("PACKAGE_RELEASE_LOCK_INITIALIZATION_RACE");
  }
}

async function reconcileOrphanedPublications() {
  try {
    const orphanApks = await Apk.find({
      releaseJobId: { $ne: null },
      status: "published",
      origin: "automatic",
      apkStoragePath: { $ne: "" },
      apkSha256: { $regex: /^[a-f0-9]{64}$/i }
    }).select("_id releaseJobId packageName versionCode versionName apkUrl apkSha256 signatureSha256 apkStoragePath patchUrl patchSha256 patchStoragePath patchFromVersionCode patchToVersionCode baseApkSha256 targetApkSha256 artifactStorageMode githubReleaseId githubReleaseTag githubApkAssetId githubPatchAssetId origin status publishedAt").lean();

    for (const apk of orphanApks) {
      const job = await ReleaseJob.findOne({ _id: apk.releaseJobId }).lean();
      if (!job || job.status === "published" || job.status === "failed") continue;

      // Reconcile only a release that unmistakably belongs to this automatic
      // pipeline and whose published artifact metadata matches the job's
      // extracted target. Do not turn an arbitrary published row into a
      // successful job.
      const metadataMatches =
        job.extractedPackageName === apk.packageName &&
        Number(job.extractedVersionCode) === Number(apk.versionCode) &&
        job.targetApkSha256 &&
        job.targetApkSha256.toLowerCase() === String(apk.apkSha256 || "").toLowerCase() &&
        job.extractedSignatureSha256 &&
        job.extractedSignatureSha256.toLowerCase() === String(apk.signatureSha256 || "").toLowerCase() &&
        job.apkStoragePath === apk.apkStoragePath &&
        job.apkPublicUrl === apk.apkUrl &&
        String(job.artifactStorageMode || "") === String(apk.artifactStorageMode || "");

      if (!metadataMatches) {
        console.error(`Refusing unsafe publication reconciliation for job ${job._id}: release metadata mismatch.`);
        continue;
      }

      if (apk.artifactStorageMode === "github") {
        if (!apk.githubReleaseId || !apk.githubReleaseTag || !apk.githubApkAssetId) {
          console.error(`Refusing unsafe publication reconciliation for job ${job._id}: incomplete GitHub release metadata.`);
          continue;
        }
        if (job.githubReleaseId !== apk.githubReleaseId || job.githubReleaseTag !== apk.githubReleaseTag ||
            job.githubApkAssetId !== apk.githubApkAssetId || (apk.patchUrl && job.githubPatchAssetId !== apk.githubPatchAssetId)) {
          console.error(`Refusing unsafe publication reconciliation for job ${job._id}: GitHub provenance metadata mismatch.`);
          continue;
        }
      }

      if (apk.patchUrl) {
        if (!apk.patchStoragePath || !apk.patchSha256 || !apk.patchFromVersionCode || !apk.patchToVersionCode || !apk.baseApkSha256) {
          console.error(`Refusing unsafe publication reconciliation for job ${job._id}: incomplete patch metadata.`);
          continue;
        }
        if (!job.patchGenerated || job.patchStoragePath !== apk.patchStoragePath || job.patchPublicUrl !== apk.patchUrl ||
            job.patchSha256.toLowerCase() !== apk.patchSha256.toLowerCase()) {
          console.error(`Refusing unsafe publication reconciliation for job ${job._id}: patch metadata mismatch.`);
          continue;
        }
      } else if (job.patchGenerated) {
        console.error(`Refusing unsafe publication reconciliation for job ${job._id}: job expects a patch but release has none.`);
        continue;
      }

      const result = await ReleaseJob.updateOne(
        {
          _id: job._id,
          status: { $in: ["queued", "processing"] },
          extractedPackageName: apk.packageName,
          extractedVersionCode: apk.versionCode,
          extractedSignatureSha256: apk.signatureSha256,
          targetApkSha256: apk.apkSha256,
          apkStoragePath: apk.apkStoragePath,
          apkPublicUrl: apk.apkUrl
        },
        { $set: { status: "published", releaseId: apk._id, completedAt: job.completedAt || apk.publishedAt || new Date() }, $unset: { workerId: 1, leaseToken: 1, claimedAt: 1, heartbeatAt: 1 } }
      );

      if (result.modifiedCount === 1) {
        console.warn(`Reconciled verified orphan publication for job ${job._id}.`);
      }
    }
  } catch (err) { console.error("Publication reconciliation error:", err.message); }
}

async function recoverStaleJobs() {
  try {
    const staleCutoff = new Date(Date.now() - STALE_JOB_TIMEOUT_MS);
    const staleJobs = await ReleaseJob.find({ 
      status: "processing", 
      $or: [
        { heartbeatAt: { $lt: staleCutoff } },
        { heartbeatAt: null, claimedAt: { $lt: staleCutoff } }
      ]
    }).lean();
    
    for (const job of staleJobs) {
      if ((job.attempts || 0) >= MAX_JOB_ATTEMPTS) {
        const failResult = await ReleaseJob.updateOne(
          {
            _id: job._id,
            status: "processing",
            workerId: job.workerId,
            leaseToken: job.leaseToken,
            leaseVersion: job.leaseVersion,
            $or: [
              { heartbeatAt: { $lt: staleCutoff } },
              { heartbeatAt: null, claimedAt: { $lt: staleCutoff } }
            ]
          },
          {
            $set: { status: "failed", lastError: "Job exceeded max attempts after stale recovery.", lastErrorCode: "STALE_JOB_MAX_ATTEMPTS", completedAt: new Date(), stage: "failed", stageUpdatedAt: new Date() },
            $unset: { workerId: 1, leaseToken: 1, claimedAt: 1, heartbeatAt: 1 }
          }
        );
        // Cleanup is performed only after the fenced compare-and-set wins.
        if (failResult.modifiedCount === 1) {
          if (job.apkTempPath) await safeUnlink(job.apkTempPath);
          if (job.stagingApkStoragePath) await artifactDelete(job.stagingApkStoragePath);
          if (job.stagingPatchStoragePath) await artifactDelete(job.stagingPatchStoragePath);
        }
      } else {
        const reclaimResult = await ReleaseJob.updateOne(
          { 
            _id: job._id, status: "processing", workerId: job.workerId, leaseToken: job.leaseToken, leaseVersion: job.leaseVersion,
            $or: [ { heartbeatAt: { $lt: staleCutoff } }, { heartbeatAt: null, claimedAt: { $lt: staleCutoff } } ]
          },
          { $set: { status: "queued", stage: "queued", stageUpdatedAt: new Date(), lastErrorCode: "STALE_JOB_REQUEUED" }, $unset: { workerId: 1, leaseToken: 1, claimedAt: 1, heartbeatAt: 1 } }
        );
        if (reclaimResult.modifiedCount === 1) {
          console.warn("Requeued stale release job:", String(job._id));
        }
      }
    }
    await cleanTempDir();
  } catch (err) { console.error("Stale job recovery error:", err.message); }
}

/* =========================================================
   AUTOMATIC RELEASE PIPELINE
========================================================= */
async function processReleaseJob(job) {
  const tempFilesToClean = [];
  const uploadedArtifactPaths = new Set();
  let heartbeatTimer = null;
  let publicationCommitted = false;
  let retainManualArtifacts = false;
  let manualPatchTempPath = "";
  const ownershipState = { ownershipLost: false };
  let githubRelease = null;

  try {
    assertArtifactStorageReady();
    await setReleaseStage(job, "starting");
    await assertActiveJobOwnership(job, ownershipState, "starting");

    heartbeatTimer = setInterval(() => {
      heartbeatReleaseJob(job).catch((err) => {
        ownershipState.ownershipLost = true;
        console.error(`Release job heartbeat failed ${job._id}:`, err.message);
      });
    }, WORKER_HEARTBEAT_INTERVAL_MS);
    heartbeatTimer.unref();

    await assertActiveJobOwnership(job, ownershipState, "preflight");

    await setReleaseStage(job, "apk_validation");
    await assertZipLikeApk(job.apkTempPath);
    const metadata = await extractApkManifestMetadata(job.apkTempPath);
    const signatureSha256 = await extractApkSignatureSha256(job.apkTempPath);
    const targetApkSha256 = await sha256File(job.apkTempPath);
    const targetApkSizeBytes = await fileSize(job.apkTempPath);
    await assertActiveJobOwnership(job, ownershipState, "metadata_complete");

    const metadataUpdate = await ReleaseJob.updateOne(
      { _id: job._id, status: "processing", workerId: WORKER_ID, leaseToken: job.leaseToken, leaseVersion: job.leaseVersion },
      { $set: {
        extractedAppName: metadata.appName,
        extractedPackageName: metadata.packageName,
        extractedVersionName: metadata.versionName,
        extractedVersionCode: metadata.versionCode,
        extractedSignatureSha256: signatureSha256,
        targetApkSha256,
        targetApkSizeBytes,
        artifactStorageMode: ARTIFACT_STORAGE_MODE
      }}
    );
    if (Number(metadataUpdate.matchedCount || 0) !== 1) throw makeOwnershipLostError("metadata_persist", metadataUpdate);

    const activeJob = await ReleaseJob.findOne({
      extractedPackageName: metadata.packageName,
      extractedVersionCode: metadata.versionCode,
      status: { $in: ["queued", "processing"] },
      _id: { $ne: job._id }
    }).select("_id").lean();
    if (activeJob) throw new Error(`Another release job is already processing versionCode ${metadata.versionCode}.`);

    const duplicate = await Apk.findOne({
      packageName: metadata.packageName,
      versionCode: metadata.versionCode,
      status: "published"
    }).select("_id").lean();
    if (duplicate) throw new Error(`A published release already exists for ${metadata.packageName} versionCode ${metadata.versionCode}.`);

    const maxPublished = await Apk.findOne({ packageName: metadata.packageName, status: "published" }).sort({ versionCode: -1 }).lean();
    if (maxPublished && metadata.versionCode <= maxPublished.versionCode) {
      throw new Error(`Monotonic version policy violation: target versionCode (${metadata.versionCode}) must be strictly greater than current published versionCode (${maxPublished.versionCode}).`);
    }

    const previous = await findAndValidatePreviousRelease(metadata.packageName, metadata.versionCode, signatureSha256);

    if (ARTIFACT_STORAGE_MODE === "github") {
      githubRelease = await githubEnsureRelease(metadata.packageName, metadata.versionCode, String(job._id));
      const githubReleaseUpdate = await ReleaseJob.updateOne(
        { _id: job._id, status: "processing", workerId: WORKER_ID, leaseToken: job.leaseToken, leaseVersion: job.leaseVersion },
        { $set: { githubReleaseId: Number(githubRelease.id || 0) || null, githubReleaseTag: String(githubRelease._tagName || "") } }
      );
      if (Number(githubReleaseUpdate.matchedCount || 0) !== 1) throw makeOwnershipLostError("github_release_persist", githubReleaseUpdate);
    }

    let patchStoragePath = "";
    let patchSha256 = "";
    let patchSizeBytes = 0;
    let patchPublicUrl = "";
    let previousTempPath = null;
    let patchGeneratedSuccessfully = false;
    let stagingPatchStoragePath = "";
    let githubPatchAssetId = null;
    let githubApkAssetId = null;

    if (previous) {
      try {
        await setReleaseStage(job, "previous_artifact_validation");
        await assertActiveJobOwnership(job, ownershipState, "previous_artifact_validation");

        previousTempPath = path.join(TEMP_UPLOAD_DIR, `prev-${crypto.randomBytes(8).toString("hex")}.apk`);
        tempFilesToClean.push(previousTempPath);

        await artifactDownload(previous.apkStoragePath || "", previous.apkUrl || "", previousTempPath, previous.artifactStorageMode || "");

        const previousActualSha = await sha256File(previousTempPath);
        if (previousActualSha.toLowerCase() !== previous.apkSha256.toLowerCase()) {
          throw new ReleaseSecurityError("Previous APK artifact SHA-256 mismatch.", "PREVIOUS_APK_HASH_MISMATCH");
        }

        const reconstructedMetaDB = await extractApkManifestMetadata(previousTempPath);
        if (reconstructedMetaDB.packageName !== metadata.packageName) throw new ReleaseSecurityError("Previous APK package mismatch.", "PREVIOUS_APK_PACKAGE_MISMATCH");
        if (reconstructedMetaDB.versionCode !== previous.versionCode) throw new ReleaseSecurityError("Previous APK versionCode mismatch.", "PREVIOUS_APK_VERSION_MISMATCH");

        const previousSignature = await extractApkSignatureSha256(previousTempPath);
        if (previousSignature !== previous.signatureSha256) throw new ReleaseSecurityError("Previous APK signing certificate mismatch.", "PREVIOUS_APK_SIGNATURE_MISMATCH");

        await setReleaseStage(job, "smart_patch_generation");
        const patchTempPath = path.join(TEMP_UPLOAD_DIR, `patch-${crypto.randomBytes(8).toString("hex")}.patch`);
        tempFilesToClean.push(patchTempPath);

        await generateBsdiffPatch(previousTempPath, job.apkTempPath, patchTempPath);
        const patchSize = await fileSize(patchTempPath);

        if (patchSize > 0 && patchSize < targetApkSizeBytes * PATCH_USELESS_RATIO) {
          const reconstructedPath = path.join(TEMP_UPLOAD_DIR, `recon-${crypto.randomBytes(8).toString("hex")}.apk`);
          tempFilesToClean.push(reconstructedPath);
          await applyBsdiffPatch(previousTempPath, patchTempPath, reconstructedPath);

          const reconstructedSha = await sha256File(reconstructedPath);
          if (reconstructedSha !== targetApkSha256) throw new ReleaseSecurityError("Reconstructed APK SHA-256 mismatch.", "PATCH_RECONSTRUCTION_HASH_MISMATCH");

          const reconstructedMeta = await extractApkManifestMetadata(reconstructedPath);
          if (reconstructedMeta.packageName !== metadata.packageName) throw new ReleaseSecurityError("Reconstructed APK package mismatch.", "PATCH_PACKAGE_MISMATCH");
          if (reconstructedMeta.versionCode !== metadata.versionCode) throw new ReleaseSecurityError("Reconstructed APK versionCode mismatch.", "PATCH_VERSION_MISMATCH");
          if (reconstructedMeta.versionName !== metadata.versionName) throw new ReleaseSecurityError("Reconstructed APK versionName mismatch.", "PATCH_VERSION_NAME_MISMATCH");

          const reconstructedSignature = await extractApkSignatureSha256(reconstructedPath);
          if (reconstructedSignature !== signatureSha256) throw new ReleaseSecurityError("Reconstructed APK signing certificate mismatch.", "PATCH_SIGNATURE_MISMATCH");

          patchSha256 = await sha256File(patchTempPath);
          patchSizeBytes = patchSize;
          patchGeneratedSuccessfully = true;

          stagingPatchStoragePath = `releases/${metadata.packageName}/${metadata.versionCode}/${job._id}/smart-patch-${previous.versionCode}-to-${metadata.versionCode}.patch`;

          if (ARTIFACT_STORAGE_MODE === "manual") {
            manualPatchTempPath = patchTempPath;
            retainManualArtifacts = true;
          } else {
            const uploadResult = await artifactUpload(
              patchTempPath,
              stagingPatchStoragePath,
              "application/octet-stream",
              { githubRelease, assetName: `smart-patch-${previous.versionCode}-to-${metadata.versionCode}-${job._id}.patch` }
            );
            patchStoragePath = uploadResult.storagePath;
            patchPublicUrl = uploadResult.publicUrl;
            githubPatchAssetId = uploadResult.assetId || null;
            if (patchStoragePath) uploadedArtifactPaths.add(patchStoragePath);

            await assertActiveJobOwnership(job, ownershipState, "patch_remote_verification");
            const verifyPatchTempPath = path.join(TEMP_UPLOAD_DIR, `verify-patch-${crypto.randomBytes(8).toString("hex")}.patch`);
            tempFilesToClean.push(verifyPatchTempPath);
            await artifactDownload(patchStoragePath, patchPublicUrl, verifyPatchTempPath);
            const verifiedPatchSha = await sha256File(verifyPatchTempPath);
            if (verifiedPatchSha !== patchSha256) {
              throw new ReleaseSecurityError(`${ARTIFACT_STORAGE_MODE} patch artifact SHA-256 verification failed.`, "PATCH_ARTIFACT_HASH_MISMATCH");
            }
          }
        } else {
          console.log(`Patch for ${metadata.packageName} v${metadata.versionCode} is not size-effective. Publishing full APK only.`);
        }
      } catch (patchErr) {
        if (patchErr && patchErr.code === "RELEASE_JOB_OWNERSHIP_LOST") throw patchErr;
        if (patchErr instanceof ReleaseSecurityError) throw patchErr;
        console.warn(`Patch generation failed operationally; using full APK fallback: ${patchErr.message}`);
        if (stagingPatchStoragePath) {
          await artifactDelete(stagingPatchStoragePath);
          uploadedArtifactPaths.delete(stagingPatchStoragePath);
        }
        patchGeneratedSuccessfully = false;
        patchSha256 = "";
        patchSizeBytes = 0;
        patchStoragePath = "";
        patchPublicUrl = "";
        stagingPatchStoragePath = "";
        manualPatchTempPath = "";
      }
    }

    await setReleaseStage(job, "patch_state_persist");
    await assertActiveJobOwnership(job, ownershipState, "patch_state_persist");

    const patchUpdateRes = await ReleaseJob.updateOne(
      { _id: job._id, status: "processing", workerId: WORKER_ID, leaseToken: job.leaseToken, leaseVersion: job.leaseVersion },
      { $set: {
        patchGenerated: patchGeneratedSuccessfully,
        patchSha256,
        patchSizeBytes,
        patchStoragePath,
        patchPublicUrl,
        previousReleaseId: previous ? previous._id : null,
        previousVersionCode: previous ? previous.versionCode : null,
        previousApkStoragePath: previous ? (previous.apkStoragePath || "") : "",
        previousApkSha256: previous ? previous.apkSha256 : "",
        stagingPatchStoragePath,
        manualPatchTempPath,
        githubPatchAssetId
      }}
    );
    if (Number(patchUpdateRes.matchedCount || 0) !== 1) throw makeOwnershipLostError("patch_state_persist", patchUpdateRes);

    await setReleaseStage(job, "apk_artifact_upload");
    let apkStoragePath = "";
    let apkPublicUrl = "";
    let stagingApkStoragePath = `releases/${metadata.packageName}/${metadata.versionCode}/${job._id}/app.apk`;
    let manualApkTempPath = "";

    if (ARTIFACT_STORAGE_MODE === "manual") {
      manualApkTempPath = job.apkTempPath;
      retainManualArtifacts = true;
    } else {
      const uploadResult = await artifactUpload(
        job.apkTempPath,
        stagingApkStoragePath,
        "application/vnd.android.package-archive",
        { githubRelease, assetName: `app-${job._id}.apk` }
      );
      apkStoragePath = uploadResult.storagePath;
      apkPublicUrl = uploadResult.publicUrl;
      githubApkAssetId = uploadResult.assetId || null;
      if (apkStoragePath) uploadedArtifactPaths.add(apkStoragePath);

      await assertActiveJobOwnership(job, ownershipState, "apk_remote_verification");

      const verifyTempPath = path.join(TEMP_UPLOAD_DIR, `verify-${crypto.randomBytes(8).toString("hex")}.apk`);
      tempFilesToClean.push(verifyTempPath);
      await artifactDownload(apkStoragePath, apkPublicUrl, verifyTempPath);

      const verifiedSha = await sha256File(verifyTempPath);
      if (verifiedSha !== targetApkSha256) {
        throw new ReleaseSecurityError(`${ARTIFACT_STORAGE_MODE} APK artifact SHA-256 verification failed.`, "APK_ARTIFACT_HASH_MISMATCH");
      }

      const verifiedMeta = await extractApkManifestMetadata(verifyTempPath);
      if (verifiedMeta.packageName !== metadata.packageName || verifiedMeta.versionCode !== metadata.versionCode || verifiedMeta.versionName !== metadata.versionName) {
        throw new ReleaseSecurityError("Uploaded APK metadata verification failed.", "APK_ARTIFACT_METADATA_MISMATCH");
      }
      const verifiedSignature = await extractApkSignatureSha256(verifyTempPath);
      if (verifiedSignature !== signatureSha256) {
        throw new ReleaseSecurityError("Uploaded APK signing certificate verification failed.", "APK_ARTIFACT_SIGNATURE_MISMATCH");
      }
    }

    const apkUpdateRes = await ReleaseJob.updateOne(
      { _id: job._id, status: "processing", workerId: WORKER_ID, leaseToken: job.leaseToken, leaseVersion: job.leaseVersion },
      { $set: {
        apkStoragePath,
        stagingApkStoragePath,
        apkPublicUrl,
        manualApkTempPath,
        githubApkAssetId,
        artifactStorageMode: ARTIFACT_STORAGE_MODE
      }}
    );
    if (Number(apkUpdateRes.matchedCount || 0) !== 1) throw makeOwnershipLostError("apk_state_persist", apkUpdateRes);

    if (ARTIFACT_STORAGE_MODE === "manual") {
      const manualReadyResult = await ReleaseJob.updateOne(
        { _id: job._id, status: "processing", workerId: WORKER_ID, leaseToken: job.leaseToken, leaseVersion: job.leaseVersion },
        { $set: { status: "awaiting_upload", lastError: "", lastErrorCode: "", stage: "awaiting_upload", stageUpdatedAt: new Date() }, $unset: { workerId: 1, leaseToken: 1, claimedAt: 1, heartbeatAt: 1 } }
      );
      if (Number(manualReadyResult.matchedCount || 0) !== 1) throw makeOwnershipLostError("manual_ready", manualReadyResult);
      console.log(`Release job ${job._id} is ready for manual artifact upload/verification.`);
      return;
    }

    await setReleaseStage(job, "publication_preflight");
    await assertActiveJobOwnership(job, ownershipState, "publication_preflight");

    await setReleaseStage(job, "publication_transaction");
    const releaseFields = {
      appName: metadata.appName,
      description: job.submittedDescription || "",
      versionName: metadata.versionName,
      versionCode: metadata.versionCode,
      packageName: metadata.packageName,
      apkUrl: apkPublicUrl,
      patchUrl: patchPublicUrl || "",
      iconUrl: job.submittedIconUrl || "",
      screenshots: job.submittedScreenshots || [],
      apkSha256: targetApkSha256,
      signatureSha256,
      status: "published",
      origin: "automatic",
      apkSizeBytes: targetApkSizeBytes,
      apkSize: targetApkSizeBytes,
      patchSha256,
      patchSizeBytes,
      patchSize: patchSizeBytes,
      patchFromVersionCode: patchGeneratedSuccessfully ? previous.versionCode : null,
      patchToVersionCode: patchGeneratedSuccessfully ? metadata.versionCode : null,
      previousVersionCode: patchGeneratedSuccessfully ? previous.versionCode : null,
      baseApkSha256: patchGeneratedSuccessfully ? previous.apkSha256 : "",
      targetApkSha256,
      apkStoragePath,
      patchStoragePath,
      artifactStorageMode: ARTIFACT_STORAGE_MODE,
      githubReleaseId: githubRelease ? Number(githubRelease.id || 0) || null : null,
      githubReleaseTag: githubRelease ? String(githubRelease._tagName || "") : "",
      githubApkAssetId,
      githubPatchAssetId,
      releaseJobId: job._id,
      publishedAt: new Date()
    };

    if (!releaseFields.packageName || !releaseFields.versionName || !Number.isSafeInteger(releaseFields.versionCode) ||
        !releaseFields.apkUrl || !releaseFields.apkSha256 || !releaseFields.signatureSha256 || !releaseFields.apkStoragePath) {
      throw new Error("Verified artifact publication fields are incomplete.");
    }
    if (releaseFields.patchUrl && (!releaseFields.patchSha256 || !releaseFields.patchStoragePath || !releaseFields.patchFromVersionCode || !releaseFields.patchToVersionCode || !releaseFields.baseApkSha256)) {
      throw new Error("Verified patch publication fields are incomplete.");
    }

    // Ensure the per-package lock document exists outside the transaction. This
    // avoids collection-creation/upsert races on the first release of a package.
    await ensureReleasePackageLock(releaseFields.packageName);

    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        const currentJob = await ReleaseJob.findOne({
          _id: job._id, status: "processing", workerId: WORKER_ID, leaseToken: job.leaseToken, leaseVersion: job.leaseVersion
        }).session(session);
        if (!currentJob) throw makeOwnershipLostError();

        // Serialize publication for this package inside the MongoDB transaction.
        // Concurrent v2/v3 publishers therefore cannot both read the same stale
        // latest version and commit in reverse order.
        const packageLock = await ReleasePackageLock.findOneAndUpdate(
          { packageName: releaseFields.packageName },
          { $set: { lastTouchedAt: new Date() } },
          { new: true, session }
        );
        if (!packageLock) throw new Error("PACKAGE_RELEASE_LOCK_MISSING");

        const existing = await Apk.findOne({ packageName: releaseFields.packageName, versionCode: releaseFields.versionCode, status: "published" }).session(session);
        if (existing) throw new Error("PUBLISHED_RELEASE_ALREADY_EXISTS");

        const latestPublished = await Apk.findOne({ packageName: releaseFields.packageName, status: "published" })
          .sort({ versionCode: -1 }).session(session).lean();
        if (latestPublished && releaseFields.versionCode <= latestPublished.versionCode) {
          throw new Error(`MONOTONIC_PUBLICATION_VIOLATION: target versionCode ${releaseFields.versionCode} must be greater than current published versionCode ${latestPublished.versionCode}.`);
        }

        const [createdApk] = await Apk.create([releaseFields], { session });

        const updateResult = await ReleaseJob.updateOne(
          { _id: job._id, status: "processing", workerId: WORKER_ID, leaseToken: job.leaseToken, leaseVersion: job.leaseVersion },
          { $set: { status: "published", releaseId: createdApk._id, completedAt: new Date() } },
          { session }
        );
        if (Number(updateResult.matchedCount || 0) !== 1) throw makeOwnershipLostError("publication_job_finalize", updateResult);
      });
    } finally {
      await session.endSession();
    }

    publicationCommitted = true;
    console.log(`Published release ${metadata.packageName} v${metadata.versionCode} (job ${job._id}) using ${ARTIFACT_STORAGE_MODE} storage.`);
  } catch (err) {
    if (err && err.code === "RELEASE_JOB_OWNERSHIP_LOST") {
      ownershipState.ownershipLost = true;
      throw err;
    }
    await failJobOwned(job, err.message, { cleanupTemp: true, cleanupArtifacts: true });
    throw err;
  } finally {
    if (heartbeatTimer) clearInterval(heartbeatTimer);

    for (const tempFile of tempFilesToClean) {
      if (retainManualArtifacts && (tempFile === job.apkTempPath || tempFile === manualPatchTempPath)) continue;
      await safeUnlink(tempFile);
    }

    if (!retainManualArtifacts && job.apkTempPath) await safeUnlink(job.apkTempPath);

    if (!publicationCommitted && !ownershipState.ownershipLost && !retainManualArtifacts) {
      for (const storagePath of uploadedArtifactPaths) await artifactDelete(storagePath);
      if (ARTIFACT_STORAGE_MODE === "github" && githubRelease && githubRelease._ownedByJob) await githubDeleteRelease(githubRelease.id);
    }
  }
}

let releaseWorkerBusy = false;
async function runReleaseWorkerTick() {
  if (releaseWorkerBusy) return;
  if (ARTIFACT_STORAGE_MODE === "firebase" && !firebaseEnabled) return;
  try { assertArtifactStorageReady(); } catch (err) {
    console.error("Artifact storage is not ready; release worker paused:", err.message);
    return;
  }
  releaseWorkerBusy = true;
  try {
    const leaseToken = crypto.randomBytes(32).toString("hex");
    const now = new Date();
    const job = await ReleaseJob.findOneAndUpdate(
      { status: "queued" },
      { $set: { status: "processing", workerId: WORKER_ID, leaseToken, claimedAt: now, heartbeatAt: now, startedAt: now, stage: "claimed", stageUpdatedAt: now, lastError: "", lastErrorCode: "" }, $inc: { attempts: 1, leaseVersion: 1 } },
      { sort: { createdAt: 1 }, new: true }
    );
    if (!job) return;
    try {
      await processReleaseJob(job);
    } catch (err) {
      console.error(`Release job ${job._id} failed or ownership lost:`, err.message);
    }
  } catch (err) {
    console.error("Release worker tick error:", err.message);
  } finally {
    releaseWorkerBusy = false;
  }
}
const releaseWorkerInterval = setInterval(runReleaseWorkerTick, RELEASE_WORKER_INTERVAL_MS);
releaseWorkerInterval.unref();
const staleRecoveryInterval = setInterval(recoverStaleJobs, Math.max(60000, Math.floor(STALE_JOB_TIMEOUT_MS / 2)));
staleRecoveryInterval.unref();

/* =========================================================
   PUBLIC APK CATALOG API
========================================================= */
app.get("/api/updates", apiLimiter, async (req, res) => {
  try {
    const apks = await Apk.aggregate([
      { $match: { status: "published" } },
      { $sort: { packageName: 1, versionCode: -1, publishedAt: -1, createdAt: -1 } },
      { $group: { _id: "$packageName", doc: { $first: "$$ROOT" } } },
      { $replaceRoot: { newRoot: "$doc" } },
      { $sort: { packageName: 1 } }
    ]);

    const normalized = await Promise.all(apks.map(async (apk) => {
      const apkUrl = (ARTIFACT_STORAGE_MODE === "firebase" && firebaseEnabled && apk.apkStoragePath)
        ? await firebaseGetSignedUrl(apk.apkStoragePath)
        : apk.apkUrl;
      const patchUrl = (ARTIFACT_STORAGE_MODE === "firebase" && firebaseEnabled && apk.patchStoragePath)
        ? await firebaseGetSignedUrl(apk.patchStoragePath)
        : (apk.patchUrl || "");

      return {
        appName: apk.appName,
        description: apk.description || "",
        packageName: apk.packageName,
        versionName: apk.versionName,
        versionCode: apk.versionCode,
        apkUrl,
        apkSha256: apk.apkSha256 || "",
        apkSize: Number(apk.apkSizeBytes || apk.apkSize || 0),
        apkSizeBytes: Number(apk.apkSizeBytes || apk.apkSize || 0),
        patchUrl,
        patchSha256: apk.patchSha256 || "",
        patchSize: Number(apk.patchSizeBytes || apk.patchSize || 0),
        patchSizeBytes: Number(apk.patchSizeBytes || apk.patchSize || 0),
        patchFromVersionCode: apk.patchFromVersionCode ?? null,
        patchToVersionCode: apk.patchToVersionCode ?? null,
        signatureSha256: apk.signatureSha256 || "",
        iconUrl: apk.iconUrl || "",
        screenshots: apk.screenshots || [],
        publishedAt: apk.publishedAt || apk.createdAt || null,
        previousVersionCode: apk.previousVersionCode ?? null,
        patchFromSha256: apk.baseApkSha256 || "",
        patchToSha256: apk.targetApkSha256 || apk.apkSha256 || "",
        baseApkSha256: apk.baseApkSha256 || "",
        targetApkSha256: apk.targetApkSha256 || apk.apkSha256 || "",
        apkStoragePath: apk.apkStoragePath || "",
        patchStoragePath: apk.patchStoragePath || "",
        releaseId: String(apk._id)
      };
    }));

    return res.status(200).json(normalized);
  } catch (err) { console.error("Updates API error:", err.message); return res.status(500).json({ error: "Failed to fetch updates" }); }
});

app.get("/api/releases", requireApiLogin, async (req, res) => {
  try {
    const jobs = await ReleaseJob.find().sort({ createdAt: -1 }).limit(50).lean();
    const formatted = jobs.map((job) => ({
      id: String(job._id),
      status: job.status,
      originalFilename: job.originalFilename,
      packageName: job.extractedPackageName || "",
      versionName: job.extractedVersionName || "",
      versionCode: job.extractedVersionCode,
      patchGenerated: job.patchGenerated,
      attempts: job.attempts,
      lastError: job.lastError || "",
      lastErrorCode: job.lastErrorCode || "",
      stage: job.stage || job.status,
      stageUpdatedAt: job.stageUpdatedAt ? safeDate(job.stageUpdatedAt) : null,
      artifactStorageMode: job.artifactStorageMode || ARTIFACT_STORAGE_MODE,
      manualReady: job.status === "awaiting_upload",
      manualApkDownloadUrl: job.status === "awaiting_upload" ? `/admin/release/${encodeURIComponent(String(job._id))}/artifact/apk` : "",
      manualPatchDownloadUrl: job.status === "awaiting_upload" && job.patchGenerated ? `/admin/release/${encodeURIComponent(String(job._id))}/artifact/patch` : "",
      manualAttachUrl: job.status === "awaiting_upload" ? "/action/apk/manual-attach" : "",
      createdAt: safeDate(job.createdAt),
      completedAt: job.completedAt ? safeDate(job.completedAt) : null
    }));
    return res.json({
      success: true,
      jobs: formatted,
      pipelineEnabled: ARTIFACT_STORAGE_MODE !== "firebase" || firebaseEnabled,
      storageMode: ARTIFACT_STORAGE_MODE,
      storageLabel: storageModeLabel()
    });
  } catch (err) { console.error("Releases API error:", err.message); return res.status(500).json({ success: false }); }
});

/* =========================================================
   UI
========================================================= */
const UI_STYLES = `
<style nonce="__CSP_NONCE__">
:root{--bg:#f5f6f8;--border:#e5e7eb;--text:#111827;--blue:#2563eb}*{box-sizing:border-box;font-family:Inter,system-ui,sans-serif}body{margin:0;background:var(--bg);color:var(--text)}.topbar{min-height:64px;background:#111827;color:white;display:flex;align-items:center;justify-content:space-between;padding:10px 24px;gap:15px}.brand{font-size:17px;font-weight:700}.brand span{color:#9ca3af;font-weight:400;margin-left:8px;font-size:13px}.container{max-width:1500px;margin:auto;padding:24px}.page-title{margin-bottom:20px}.page-title h1{font-size:24px;margin:0 0 4px}.status-line{font-size:12px;color:#6b7280}.card{background:white;border:1px solid var(--border);border-radius:10px;margin-bottom:18px}.card-header{padding:16px 18px;border-bottom:1px solid var(--border);font-weight:650;font-size:14px}.card-body{padding:18px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:18px}.stat{background:white;border:1px solid var(--border);border-radius:10px;padding:18px}.stat-label{font-size:12px;color:#6b7280;margin-bottom:8px}.stat-value{font-size:25px;font-weight:700}.filters{display:flex;flex-wrap:wrap;gap:10px;align-items:center}input,select,textarea{padding:9px 11px;border:1px solid #d1d5db;border-radius:7px;font-size:13px;background:white}.search{min-width:260px}.btn{border:0;border-radius:7px;padding:9px 12px;font-size:12px;font-weight:600;cursor:pointer;color:white;display:inline-flex;align-items:center;justify-content:center;gap:5px;text-decoration:none}.btn-dark{background:#111827}.btn-blue{background:#2563eb}.btn-green{background:#15803d}.btn-orange{background:#ea580c}.btn-yellow{background:#a16207}.btn-red{background:#b91c1c}.btn-purple{background:#6d28d9}.btn-gray{background:#e5e7eb;color:#111827}.btn:hover{opacity:.9}.btn:disabled{opacity:.55;cursor:not-allowed}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:900px}th{background:#f9fafb;color:#6b7280;font-size:11px;text-transform:uppercase}th,td{padding:13px;border-bottom:1px solid var(--border);text-align:left;font-size:13px}code{font-size:11px;background:#f3f4f6;padding:4px 6px;border-radius:4px;word-break:break-all}.badge{display:inline-block;padding:5px 8px;border-radius:20px;font-size:10px;font-weight:700}.badge-app{background:#e0e7ff;color:#4338ca;font-size:10px;margin-top:4px}.approved,.online,.published{background:#dcfce7;color:#166534}.pending,.queued{background:#fef3c7;color:#92400e}.blocked,.offline,.failed{background:#fee2e2;color:#991b1b}.processing{background:#dbeafe;color:#1e40af}.action-cell{display:flex;gap:5px;flex-wrap:wrap;min-width:430px}.inline-form{margin:0;display:inline-flex;gap:5px;align-items:center}.nickname-input{width:125px;padding:7px;font-size:12px}.form-group{margin-bottom:15px}.form-group label{display:block;font-size:13px;font-weight:600;margin-bottom:6px}.form-group input,.form-group textarea{width:100%}.pagination{display:flex;gap:12px;align-items:center;padding:15px;justify-content:center}.pagination button{padding:8px 14px;border:1px solid #ddd;border-radius:6px;cursor:pointer}.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);align-items:center;justify-content:center;padding:20px;z-index:999}.modal{background:#fff;border-radius:12px;width:min(1100px,100%);max-height:90vh;overflow:auto}.modal-header{padding:16px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;font-weight:700}.modal-close{border:0;background:transparent;font-size:26px;cursor:pointer}.modal-body{padding:18px}.notice{background:#fffbeb;border:1px solid #fde68a;color:#92400e;padding:10px 14px;border-radius:8px;font-size:12px;margin-bottom:14px}@media(max-width:800px){.topbar{align-items:flex-start;flex-direction:column}.container{padding:12px}}
</style>`;

const TOPBAR_HTML = (csrfToken) => `
<div class="topbar">
  <div class="brand">Admin Console<span>V8.3.2 Ultimate Render Production Edition</span></div>
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
    <a href="/" class="btn btn-blue">Devices</a>
    <a href="/apps" class="btn btn-orange">App Systems</a>
    <a href="/apks" class="btn btn-purple">APK Manager</a>
    <form method="POST" action="/logout" style="margin:0"><input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}"><button class="btn btn-gray" type="submit">Logout</button></form>
  </div>
</div>`;

app.get("/login", csrfProtection, (req, res) => {
  if (req.session && req.session.adminAuthenticated) return res.redirect("/");
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title>${UI_STYLES}</head><body style="display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0"><div class="card" style="width:100%;max-width:420px;padding:24px"><h1 style="margin-top:0">Login</h1>${req.query.error ? '<div style="color:#b91c1c;margin-bottom:10px;font-size:13px">Invalid username/password</div>' : ""}<form method="POST" action="/login"><input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}"><div class="form-group"><label>Username</label><input type="text" name="username" required autocomplete="username"></div><div class="form-group"><label>Password</label><input type="password" name="password" required autocomplete="current-password"></div><button class="btn btn-dark" style="width:100%" type="submit">Sign In</button></form></div></body></html>`);
});

app.post("/login", loginLimiter, csrfProtection, async (req, res) => {
  try {
    const username = safeString(req.body.username, 100); const password = String(req.body.password || "");
    if (username !== ADMIN_USERNAME || !(await verifyPassword(password))) return res.redirect("/login?error=1");
    req.session.regenerate((err) => {
      if (err) return res.redirect("/login?error=1");
      req.session.adminAuthenticated = true; req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      req.session.save((saveErr) => res.redirect(saveErr ? "/login?error=1" : "/"));
    });
  } catch (err) { console.error("Login error:", err.message); res.redirect("/login?error=1"); }
});

app.post("/logout", requireLogin, csrfProtection, (req, res) => { req.session.destroy(() => { res.clearCookie("admin.sid"); res.redirect("/login"); }); });

app.get("/apps", requireLogin, csrfProtection, async (req, res) => {
  try {
    const apps = await AppRegistry.find().sort({ createdAt: -1 }).lean();
    const deviceCounts = await Device.aggregate([{ $group: { _id: "$appId", count: { $sum: 1 } } }]);
    const countMap = {}; deviceCounts.forEach((d) => { countMap[d._id] = d.count; });

    let rows = apps.map((item) => `
      <tr>
        <td><form class="inline-form" method="POST" action="/action/app-registry/edit">
          <input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}">
          <input type="hidden" name="id" value="${escapeHtml(item._id)}">
          <input type="hidden" name="oldAppId" value="${escapeHtml(item.appId)}">
          <input type="text" name="appName" value="${escapeHtml(item.appName)}" required maxlength="100" placeholder="Display Name">
          <input type="text" name="newAppId" value="${escapeHtml(item.appId)}" required maxlength="200" placeholder="App ID">
          <button class="btn btn-blue" type="submit">Save</button>
        </form></td>
        <td><strong>${Number(countMap[item.appId] || 0)}</strong> Devices</td>
        <td><form class="inline-form confirm-action" method="POST" action="/action/app-registry/delete" data-confirm="DANGER: This deletes the app and all tracking history for this app. Continue?">
          <input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}">
          <input type="hidden" name="id" value="${escapeHtml(item._id)}">
          <input type="hidden" name="appId" value="${escapeHtml(item.appId)}">
          <button class="btn btn-red" type="submit">Wipe Entire System</button>
        </form></td>
      </tr>`).join("");

    if (!rows) rows = `<tr><td colspan="3" style="text-align:center;padding:25px">No App Systems found.</td></tr>`;

    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>App Systems</title>${UI_STYLES}</head><body>${TOPBAR_HTML(res.locals.csrfToken)}<div class="container">
      <div class="page-title"><h1>App Systems Management</h1><p class="status-line">Create workspaces or packages to isolate tracking data.</p></div>
      <div class="card"><div class="card-header">Register New App Package</div><div class="card-body"><form method="POST" action="/action/app-registry/add" style="display:flex;gap:15px;align-items:flex-end;flex-wrap:wrap">
        <input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}"><div style="flex:1;min-width:220px"><label style="font-size:12px;font-weight:bold;display:block;margin-bottom:5px">Display Name</label><input style="width:100%" type="text" name="appName" required maxlength="100" placeholder="My Awesome Mod"></div>
        <div style="flex:1;min-width:220px"><label style="font-size:12px;font-weight:bold;display:block;margin-bottom:5px">App ID</label><input style="width:100%" type="text" name="appId" required maxlength="200" placeholder="com.myawesome.mod"></div>
        <button type="submit" class="btn btn-green" style="height:37px;padding:0 20px">Add System</button>
      </form></div></div>
      <div class="card"><div class="card-header">Existing Systems</div><div class="table-wrap"><table style="min-width:600px"><thead><tr><th>Rename & Edit App ID</th><th>Registered Devices</th><th>Danger Zone</th></tr></thead><tbody>${rows}</tbody></table></div></div>
    </div></body></html>`);
  } catch (err) { console.error("Apps page error:", err.message); res.status(500).send("Error: " + escapeHtml(err.message)); }
});

app.post("/action/app-registry/add", requireLogin, adminActionLimiter, csrfProtection, async (req, res) => {
  try {
    const appId = safeString(req.body.appId, MAX_APP_ID_LENGTH); const appName = safeString(req.body.appName, MAX_APP_NAME_LENGTH);
    if (!isValidAppId(appId) || !appName) return res.redirect("/apps");
    await AppRegistry.create({ appId, appName });
  } catch (err) { console.error("Add App Error:", err.message); } res.redirect("/apps");
});

app.post("/action/app-registry/edit", requireLogin, adminActionLimiter, csrfProtection, async (req, res) => {
  const session = await mongoose.startSession();
  try {
    const id = getObjectId(req.body.id); const oldAppId = safeString(req.body.oldAppId, MAX_APP_ID_LENGTH);
    const newAppId = safeString(req.body.newAppId, MAX_APP_ID_LENGTH); const appName = safeString(req.body.appName, MAX_APP_NAME_LENGTH);
    if (!id || !isValidAppId(newAppId) || !appName || !oldAppId) return res.redirect("/apps");
    
    await session.withTransaction(async () => {
      const registry = await AppRegistry.findOne({ _id: id, appId: oldAppId }).session(session);
      if (!registry) throw new Error("APP_REGISTRY_NOT_FOUND");
      const duplicate = await AppRegistry.findOne({ appId: newAppId, _id: { $ne: id } }).session(session);
      if (duplicate) throw new Error("APP_ID_ALREADY_EXISTS");
      
      await AppRegistry.updateOne({ _id: id, appId: oldAppId }, { $set: { appId: newAppId, appName } }, { session });
      await Device.updateMany({ appId: oldAppId }, { $set: { appId: newAppId } }, { session });
      await UsageSession.updateMany({ appId: oldAppId }, { $set: { appId: newAppId } }, { session });
    });
    
  } catch (err) { 
    console.error("Edit App Error:", err.message); 
  } finally {
    await session.endSession();
  }
  res.redirect("/apps");
});

app.post("/action/app-registry/delete", requireLogin, adminActionLimiter, csrfProtection, async (req, res) => {
  const session = await mongoose.startSession();
  try {
    const id = getObjectId(req.body.id); const appId = safeString(req.body.appId, MAX_APP_ID_LENGTH);
    if (id && appId) {
      await session.withTransaction(async () => {
        await AppRegistry.findByIdAndDelete(id).session(session);
        await Device.deleteMany({ appId }).session(session);
        await UsageSession.deleteMany({ appId }).session(session);
      });
    }
  } catch (err) { 
    console.error("Delete App Error:", err.message); 
  } finally {
    await session.endSession();
  }
  res.redirect("/apps");
});

/* =========================================================
   APK MANAGER
========================================================= */
function apkFormFields(editApk, csrfToken) {
  const isEditing = !!editApk;
  if (!isEditing) {
    return `<div class="notice" style="grid-column:1/-1">Legacy manual APK entry is disabled for security. Please use the "Upload Signed APK" form above.</div>`;
  }
  return `
    <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}">
    <input type="hidden" name="id" value="${escapeHtml(editApk._id)}">
    <input type="hidden" name="existingIconUrl" value="${escapeHtml(editApk.iconUrl || "")}">
    <input type="hidden" name="existingScreenshots" value="${escapeHtml(JSON.stringify(editApk.screenshots || []))}">
    
    <div class="form-group"><label>App Name</label><input type="text" name="appName" required maxlength="100" value="${escapeHtml(editApk.appName)}" placeholder="Example App"></div>
    <div class="form-group"><label>Package Name (Verified)</label><input type="text" readonly style="background:#e5e7eb" value="${escapeHtml(editApk.packageName)}"></div>
    <div class="form-group"><label>Version Name (Verified)</label><input type="text" readonly style="background:#e5e7eb" value="${escapeHtml(editApk.versionName)}"></div>
    <div class="form-group"><label>Version Code (Verified)</label><input type="number" readonly style="background:#e5e7eb" value="${escapeHtml(editApk.versionCode)}"></div>

    <div class="form-group" style="grid-column:1/-1; background:#f9fafb; padding:10px; border:1px dashed #d1d5db; border-radius:6px;">
      <label>1. Direct APK URL (Verified)</label>
      <input type="url" readonly style="background:#e5e7eb; margin-bottom:10px;" value="${escapeHtml(editApk.apkUrl)}">
      <label>2. Smart Update Patch URL (Verified)</label>
      <input type="url" readonly style="background:#e5e7eb" value="${escapeHtml(editApk.patchUrl || "")}">
    </div>

    <div class="form-group" style="grid-column:1/-1"><label>APK SHA-256 (Verified)</label><input type="text" readonly style="background:#e5e7eb" value="${escapeHtml(editApk.apkSha256 || "")}"></div>
    <div class="form-group" style="grid-column:1/-1"><label>Signing Certificate SHA-256 (Verified)</label><input type="text" readonly style="background:#e5e7eb" value="${escapeHtml(editApk.signatureSha256 || "")}"></div>
    
    <div class="form-group" style="grid-column:1/-1"><label>Update App Icon</label><input type="file" name="iconFile" accept="image/*">${editApk.iconUrl ? `<br><small style="color:green">Current icon active — leave empty to keep it.</small>` : ""}</div>
    <div class="form-group" style="grid-column:1/-1"><label>Update Feature Screenshots (max 10)</label><input type="file" name="screenshotFiles" accept="image/*" multiple></div>
    <div class="form-group" style="grid-column:1/-1"><label>Changelog / Description</label><textarea name="description" rows="3" maxlength="500">${escapeHtml(editApk.description || "")}</textarea></div>
    <div style="grid-column:1/-1;display:flex;gap:10px"><button type="submit" id="submitBtn" class="btn btn-blue">Update Display Details</button><a href="/apks" class="btn btn-gray">Cancel</a></div>`;
}

app.get("/apks", requireLogin, csrfProtection, async (req, res) => {
  try {
    const editId = safeString(req.query.edit, 100); let editApk = null;
    if (editId && mongoose.Types.ObjectId.isValid(editId)) editApk = await Apk.findById(editId).lean();

    const apks = await Apk.find({ status: "published" }).sort({ createdAt: -1 }).lean();
    let apkRows = apks.map((apk) => `
      <tr>
        <td><div style="display:flex;align-items:center;gap:10px">${apk.iconUrl ? `<img src="${escapeHtml(apk.iconUrl)}" style="width:36px;height:36px;border-radius:8px;object-fit:cover" alt="icon">` : '<div style="width:36px;height:36px;border-radius:8px;background:#e5e7eb"></div>'}<div><strong>${escapeHtml(apk.appName)}</strong><br><span class="status-line">${escapeHtml(apk.description)}</span></div></div></td>
        <td><span class="badge online">${escapeHtml(apk.versionName)}</span><br>Code: ${escapeHtml(apk.versionCode)}</td>
        <td><code>${escapeHtml(apk.packageName)}</code></td>
        <td>
          <a href="${escapeHtml(apk.apkUrl)}" target="_blank" rel="noopener noreferrer" style="color:var(--blue);font-size:12px">Full APK</a>
          ${apk.patchUrl ? `<br><a href="${escapeHtml(apk.patchUrl)}" target="_blank" rel="noopener noreferrer" style="color:#ea580c;font-size:12px">Smart Patch</a>` : ""}
          <br><span class="badge badge-app">${escapeHtml(apk.origin || "manual")}</span>
        </td>
        <td>${safeDate(apk.publishedAt || apk.createdAt)}</td>
        <td><div style="display:flex;gap:5px"><a href="/apks?edit=${escapeHtml(apk._id)}" class="btn btn-blue" style="padding:6px 10px">Edit</a><form class="inline-form confirm-action" method="POST" action="/action/apk/delete" data-confirm="Retire this APK from the store?"><input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}"><input type="hidden" name="id" value="${escapeHtml(apk._id)}"><button class="btn btn-red" type="submit" style="padding:6px 10px">Retire</button></form></div></td>
      </tr>`).join("");
    if (!apkRows) apkRows = `<tr><td colspan="6" style="text-align:center;padding:25px">No APKs published yet.</td></tr>`;

    const isEditing = !!editApk; const formAction = isEditing ? "/action/apk/edit" : "/action/apk/add";
    const formTitle = isEditing ? `Edit APK Display Details: ${escapeHtml(editApk.appName)}` : "Manual Entry";

    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>APK Manager</title>${UI_STYLES}</head><body>${TOPBAR_HTML(res.locals.csrfToken)}<div class="container"><div class="page-title"><h1>APK Store Manager</h1><p class="status-line">Upload a signed APK for the fully automatic release pipeline.</p></div>

      <div class="notice">
        <strong>Artifact Storage Mode:</strong> ${escapeHtml(ARTIFACT_STORAGE_MODE.toUpperCase())}.
        ${ARTIFACT_STORAGE_MODE === "manual"
          ? "Server will generate and cryptographically verify the APK/patch, then keep temporary artifacts ready for download. Upload them to GitHub/your host and paste the final URLs for server-side verification before publication."
          : ARTIFACT_STORAGE_MODE === "firebase"
            ? (firebaseEnabled ? "Firebase Storage is explicitly enabled by configuration." : "Firebase mode is selected but unavailable; the release worker is paused.")
            : `Server-side artifact upload is enabled through ${escapeHtml(ARTIFACT_STORAGE_MODE)}.`}
        ${ARTIFACT_STORAGE_MODE !== "firebase" ? " Firebase remains OFF until ARTIFACT_STORAGE_MODE=firebase is explicitly selected and valid credentials are supplied." : ""}
      </div>

      <div class="card"><div class="card-header">Upload Signed APK (Release Pipeline)</div><div class="card-body">
        <form id="releaseForm" method="POST" action="/action/apk/upload" enctype="multipart/form-data" style="display:grid;grid-template-columns:1fr 1fr;gap:15px">
          <input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}">
          <div class="form-group" style="grid-column:1/-1"><label>Signed APK file (.apk)</label><input type="file" name="apkFile" accept=".apk" required></div>
          <div class="form-group" style="grid-column:1/-1"><label>Changelog / Description (optional)</label><textarea name="description" rows="3" maxlength="500"></textarea></div>
          <div class="form-group"><label>App Icon (optional)</label><input type="file" name="iconFile" accept="image/*"></div>
          <div class="form-group"><label>Screenshots (optional, max 10)</label><input type="file" name="screenshotFiles" accept="image/*" multiple></div>
          <div style="grid-column:1/-1"><button type="submit" id="releaseSubmitBtn" class="btn btn-green">Upload & Auto-Publish</button></div>
        </form>
        <p class="status-line">Package name, version, and signing certificate are extracted from the APK itself — nothing here needs to be typed manually. The server will automatically diff against the previous published release, generate a Smart Patch, verify everything cryptographically, and publish atomically.</p>
      </div></div>

      <div class="card"><div class="card-header">Release Pipeline Status</div><div class="table-wrap"><table><thead><tr><th>File</th><th>Package</th><th>Version</th><th>Patch</th><th>Storage</th><th>Status</th><th>Submitted</th><th>Actions / Error</th></tr></thead><tbody id="releaseJobsTable"><tr><td colspan="8" style="text-align:center;padding:20px">Loading...</td></tr></tbody></table></div></div>

      <div class="card"><div class="card-header">${formTitle} ${isEditing ? '<a href="/apks" class="btn btn-gray" style="float:right;padding:3px 8px;font-size:11px">Cancel Edit</a>' : ""}</div><div class="card-body"><form id="apkForm" method="POST" action="${formAction}" enctype="multipart/form-data" style="display:grid;grid-template-columns:1fr 1fr;gap:15px">${apkFormFields(editApk, res.locals.csrfToken)}</form></div></div>
      <div class="card"><div class="card-header">Published Apps</div><div class="table-wrap"><table><thead><tr><th>App</th><th>Version</th><th>Package</th><th>Downloads</th><th>Published</th><th>Action</th></tr></thead><tbody>${apkRows}</tbody></table></div></div></div>
      <script nonce="__CSP_NONCE__">
        document.querySelectorAll(".confirm-action").forEach(function(form){form.addEventListener("submit",function(e){if(!window.confirm(form.getAttribute("data-confirm")||"Continue?"))e.preventDefault();});});
        const f = document.getElementById("apkForm"); if (f) { f.addEventListener("submit",function(){var b=document.getElementById("submitBtn"); if(b){b.disabled=true;b.style.opacity=".7";b.style.cursor="not-allowed";b.innerHTML="⏳ Processing...";}}); }
        document.querySelectorAll('form[enctype="multipart/form-data"]').forEach(function(form){
          form.addEventListener("submit",async function(e){
            e.preventDefault();
            var b=form.querySelector('button[type="submit"]'); if(b){b.disabled=true;b.style.opacity=".7";b.style.cursor="not-allowed";b.innerHTML="⏳ Uploading...";}
            try{
              var r=await fetch(form.action,{method:"POST",body:new FormData(form),credentials:"same-origin",headers:{"X-CSRF-Token":form.querySelector('input[name="_csrf"]')?.value||""},redirect:"follow"});
              if(r.redirected){window.location.href=r.url;return;}
              if(!r.ok){var t=await r.text();document.body.innerHTML=t;return;}
              window.location.reload();
            }catch(err){window.alert("Upload failed: "+(err&&err.message?err.message:"Network error"));if(b){b.disabled=false;b.innerHTML="Retry";}}
          });
        });
        function escapeHTML(v){return String(v??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;");}
        async function refreshReleaseJobs(){
          try{
            const r = await fetch("/api/releases",{credentials:"same-origin",cache:"no-store"});
            if(r.status===401){window.location.href="/login";return;}
            const data = await r.json(); if(!data.success) return;
            const tbody = document.getElementById("releaseJobsTable");
            if(!data.jobs.length){tbody.innerHTML='<tr><td colspan="8" style="text-align:center;padding:20px">No release jobs yet.</td></tr>';return;}
            tbody.innerHTML = data.jobs.map(function(j){
              var actions = "";
              if(j.manualReady){
                actions += '<div style="display:flex;gap:5px;flex-wrap:wrap;margin-bottom:8px">';
                actions += '<a class="btn btn-blue" target="_blank" rel="noopener" href="'+escapeHTML(j.manualApkDownloadUrl)+'">Download APK</a>';
                if(j.manualPatchDownloadUrl) actions += '<a class="btn btn-orange" target="_blank" rel="noopener" href="'+escapeHTML(j.manualPatchDownloadUrl)+'">Download Patch</a>';
                actions += '</div>';
                actions += '<form method="POST" action="'+escapeHTML(j.manualAttachUrl)+'" style="min-width:360px;display:grid;gap:5px">';
                actions += '<input type="hidden" name="_csrf" value="'+escapeHTML("${escapeHtml(res.locals.csrfToken)}")+'">';
                actions += '<input type="hidden" name="jobId" value="'+escapeHTML(j.id)+'">';
                actions += '<input type="url" name="apkUrl" required placeholder="Final hosted APK URL">';
                if(j.patchGenerated) actions += '<input type="url" name="patchUrl" required placeholder="Final hosted Smart Patch URL">';
                actions += '<button class="btn btn-green" type="submit">Verify URLs & Publish</button></form>';
                actions += '<form method="POST" action="/action/apk/manual-cancel" style="margin-top:5px"><input type="hidden" name="_csrf" value="'+escapeHTML("${escapeHtml(res.locals.csrfToken)}")+'"><input type="hidden" name="jobId" value="'+escapeHTML(j.id)+'"><button class="btn btn-red" type="submit">Cancel</button></form>';
              }
              if(j.lastError) actions += '<div style="max-width:360px;font-size:11px;color:#b91c1c;margin-top:6px">'+escapeHTML(j.lastError)+'</div>';
              return '<tr><td>'+escapeHTML(j.originalFilename)+'</td><td><code>'+escapeHTML(j.packageName||"—")+'</code></td><td>'+escapeHTML(j.versionName||"—")+' ('+escapeHTML(j.versionCode??"—")+')</td><td>'+(j.patchGenerated?'Yes':'No')+'</td><td><span class="badge badge-app">'+escapeHTML(j.artifactStorageMode||data.storageMode||"—")+'</span></td><td><span class="badge '+escapeHTML(j.status)+'">'+escapeHTML(j.status.toUpperCase())+'</span></td><td>'+escapeHTML(j.createdAt)+'</td><td>'+actions+'</td></tr>';
            }).join("");
          }catch(e){}
        }
        refreshReleaseJobs();
        setInterval(refreshReleaseJobs, 5000);
      </script>
    </body></html>`);
  } catch (err) { console.error("APK page error:", err.message); res.status(500).send("Error: " + escapeHtml(err.message)); }
});

app.post("/action/apk/upload", requireLogin, releaseUploadLimiter, requireMultipartCsrfHeader, releaseUpload.fields([{ name: "apkFile", maxCount: 1 }, { name: "iconFile", maxCount: 1 }, { name: "screenshotFiles", maxCount: 10 }]), csrfProtection, async (req, res) => {
  let apkTempPath = null;
  const newlyUploadedPublicIds = [];
  try {
    if (!req.files || !req.files.apkFile || !req.files.apkFile[0]) return res.status(400).send("A signed APK file is required.");
    apkTempPath = req.files.apkFile[0].path;

    const MAX_IMG_SIZE = 5 * 1024 * 1024;
    if (req.files.iconFile && req.files.iconFile[0] && req.files.iconFile[0].size > MAX_IMG_SIZE) {
      if (req.files.iconFile[0].path) await safeUnlink(req.files.iconFile[0].path);
      if (apkTempPath) await safeUnlink(apkTempPath);
      return res.status(400).send("Icon file exceeds 5MB limit.");
    }
    if (req.files.screenshotFiles) {
      for (const file of req.files.screenshotFiles) {
        if (file.size > MAX_IMG_SIZE) {
          for (const f of req.files.screenshotFiles) if (f.path) await safeUnlink(f.path);
          if (req.files.iconFile && req.files.iconFile[0]) await safeUnlink(req.files.iconFile[0].path);
          if (apkTempPath) await safeUnlink(apkTempPath);
          return res.status(400).send("A screenshot file exceeds 5MB limit.");
        }
      }
    }

    const description = safeString(req.body.description, MAX_DESCRIPTION_LENGTH);
    let iconUrl = "";
    const screenshots = [];
    if (req.files.iconFile && req.files.iconFile[0]) {
      const buf = await fsp.readFile(req.files.iconFile[0].path);
      iconUrl = await uploadToCloudinary(buf, "rd_store/icons");
      const pubId = extractCloudinaryPublicId(iconUrl);
      if (pubId) newlyUploadedPublicIds.push(pubId);
      await safeUnlink(req.files.iconFile[0].path);
    }
    if (req.files.screenshotFiles) {
      for (const file of req.files.screenshotFiles.slice(0, 10)) {
        const buf = await fsp.readFile(file.path);
        const sUrl = await uploadToCloudinary(buf, "rd_store/screenshots");
        screenshots.push(sUrl);
        const pubId = extractCloudinaryPublicId(sUrl);
        if (pubId) newlyUploadedPublicIds.push(pubId);
        await safeUnlink(file.path);
      }
    }

    await ReleaseJob.create({
      status: "queued",
      originalFilename: safeString(req.files.apkFile[0].originalname, 255),
      apkTempPath,
      submittedDescription: description,
      submittedIconUrl: iconUrl,
      submittedScreenshots: normalizeScreenshotUrls(screenshots)
    });

    return res.redirect("/apks");
  } catch (err) {
    console.error("APK upload enqueue error:", err.message);
    if (apkTempPath) await safeUnlink(apkTempPath);
    for (const pubId of newlyUploadedPublicIds) {
      try { await cloudinary.uploader.destroy(pubId); } catch (_) {}
    }
    return res.status(500).send("Failed to queue release: " + escapeHtml(err.message));
  }
});


async function getAwaitingManualJob(jobId) {
  const id = getObjectId(jobId);
  if (!id) return null;
  return ReleaseJob.findOne({ _id: id, status: "awaiting_upload", artifactStorageMode: "manual" });
}

app.get("/admin/release/:id/artifact/:kind", requireLogin, async (req, res) => {
  try {
    const job = await getAwaitingManualJob(req.params.id);
    if (!job) return res.status(404).send("Manual release artifact not found or no longer available.");

    const kind = String(req.params.kind || "").toLowerCase();
    let filePath = "";
    let filename = "";
    let contentType = "application/octet-stream";

    if (kind === "apk") {
      filePath = job.manualApkTempPath || job.apkTempPath;
      filename = `${job.extractedPackageName || "app"}-${job.extractedVersionCode || "release"}.apk`;
      contentType = "application/vnd.android.package-archive";
    } else if (kind === "patch") {
      if (!job.patchGenerated) return res.status(404).send("This release has no Smart Patch.");
      filePath = job.manualPatchTempPath;
      filename = `${job.extractedPackageName || "app"}-${job.previousVersionCode || "base"}-to-${job.extractedVersionCode || "release"}.patch`;
    } else {
      return res.status(400).send("Unknown artifact kind.");
    }

    if (!filePath || !fs.existsSync(filePath)) return res.status(410).send("The temporary artifact is no longer available. Re-run the release job.");
    res.setHeader("Content-Type", contentType);
    res.setHeader("Cache-Control", "no-store");
    return res.download(filePath, filename);
  } catch (err) {
    console.error("Manual artifact download error:", err.message);
    return res.status(500).send("Artifact download failed.");
  }
});

app.get("/admin/release/:id/metadata", requireLogin, async (req, res) => {
  try {
    const job = await getAwaitingManualJob(req.params.id);
    if (!job) return res.status(404).json({ success: false, error: "RELEASE_NOT_AVAILABLE" });

    return res.json({
      success: true,
      packageName: job.extractedPackageName,
      appName: job.extractedAppName,
      versionName: job.extractedVersionName,
      versionCode: job.extractedVersionCode,
      signatureSha256: job.extractedSignatureSha256,
      apkSha256: job.targetApkSha256,
      apkSizeBytes: Number(job.targetApkSizeBytes || 0),
      patchGenerated: !!job.patchGenerated,
      patchSha256: job.patchSha256 || "",
      patchSizeBytes: Number(job.patchSizeBytes || 0),
      previousVersionCode: job.previousVersionCode ?? null,
      previousApkSha256: job.previousApkSha256 || "",
      storageMode: "manual"
    });
  } catch (err) {
    console.error("Manual metadata error:", err.message);
    return res.status(500).json({ success: false, error: "METADATA_FAILED" });
  }
});

app.post("/action/apk/manual-attach", requireLogin, adminActionLimiter, csrfProtection, async (req, res) => {
  const tempFiles = [];
  try {
    const job = await getAwaitingManualJob(req.body.jobId);
    if (!job) return res.status(404).send("Release job is not awaiting manual upload.");

    const apkUrl = safeString(req.body.apkUrl, MAX_URL_LENGTH);
    const patchUrl = safeString(req.body.patchUrl, MAX_URL_LENGTH);
    if (!isValidHttpUrl(apkUrl)) return res.status(400).send("A valid APK HTTP/HTTPS URL is required.");
    if (job.patchGenerated && !isValidHttpUrl(patchUrl)) return res.status(400).send("A valid Smart Patch HTTP/HTTPS URL is required.");
    if (!job.patchGenerated && patchUrl) return res.status(400).send("This release does not expect a Smart Patch.");

    const apkVerifyPath = path.join(TEMP_UPLOAD_DIR, `manual-verify-${crypto.randomBytes(8).toString("hex")}.apk`);
    tempFiles.push(apkVerifyPath);
    await downloadHttpFile(apkUrl, apkVerifyPath);

    await assertZipLikeApk(apkVerifyPath);
    const apkSha = await sha256File(apkVerifyPath);
    if (apkSha.toLowerCase() !== String(job.targetApkSha256 || "").toLowerCase()) {
      throw new ReleaseSecurityError("Externally hosted APK SHA-256 does not match the server-generated APK.", "MANUAL_APK_HASH_MISMATCH");
    }

    const apkMeta = await extractApkManifestMetadata(apkVerifyPath);
    if (apkMeta.packageName !== job.extractedPackageName || apkMeta.versionCode !== job.extractedVersionCode || apkMeta.versionName !== job.extractedVersionName) {
      throw new ReleaseSecurityError("Externally hosted APK metadata does not match the verified release.", "MANUAL_APK_METADATA_MISMATCH");
    }

    const apkSignature = await extractApkSignatureSha256(apkVerifyPath);
    if (apkSignature !== job.extractedSignatureSha256) {
      throw new ReleaseSecurityError("Externally hosted APK signing certificate does not match the verified release.", "MANUAL_APK_SIGNATURE_MISMATCH");
    }

    let verifiedPatchSha = "";
    if (job.patchGenerated) {
      const patchVerifyPath = path.join(TEMP_UPLOAD_DIR, `manual-verify-${crypto.randomBytes(8).toString("hex")}.patch`);
      tempFiles.push(patchVerifyPath);
      await downloadHttpFile(patchUrl, patchVerifyPath);
      verifiedPatchSha = await sha256File(patchVerifyPath);
      if (verifiedPatchSha.toLowerCase() !== String(job.patchSha256 || "").toLowerCase()) {
        throw new ReleaseSecurityError("Externally hosted Smart Patch SHA-256 does not match the server-generated patch.", "MANUAL_PATCH_HASH_MISMATCH");
      }
    }

    await ensureReleasePackageLock(job.extractedPackageName);

    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        const currentJob = await ReleaseJob.findOne({ _id: job._id, status: "awaiting_upload", artifactStorageMode: "manual" }).session(session);
        if (!currentJob) throw new Error("RELEASE_JOB_STATE_CHANGED");

        const packageLock = await ReleasePackageLock.findOneAndUpdate(
          { packageName: currentJob.extractedPackageName },
          { $set: { lastTouchedAt: new Date() } },
          { new: true, session }
        );
        if (!packageLock) throw new Error("PACKAGE_RELEASE_LOCK_MISSING");
        const existing = await Apk.findOne({
          packageName: currentJob.extractedPackageName,
          versionCode: currentJob.extractedVersionCode,
          status: "published"
        }).session(session);
        if (existing) throw new Error("PUBLISHED_RELEASE_ALREADY_EXISTS");

        const latest = await Apk.findOne({
          packageName: currentJob.extractedPackageName,
          status: "published"
        }).sort({ versionCode: -1 }).session(session);
        if (latest && currentJob.extractedVersionCode <= latest.versionCode) {
          throw new Error(`Monotonic version policy violation at manual publication: target versionCode (${currentJob.extractedVersionCode}) is not greater than current published versionCode (${latest.versionCode}).`);
        }

        const [created] = await Apk.create([{
          appName: currentJob.extractedAppName,
          description: currentJob.submittedDescription || "",
          versionName: currentJob.extractedVersionName,
          versionCode: currentJob.extractedVersionCode,
          packageName: currentJob.extractedPackageName,
          apkUrl,
          patchUrl: currentJob.patchGenerated ? patchUrl : "",
          iconUrl: currentJob.submittedIconUrl || "",
          screenshots: currentJob.submittedScreenshots || [],
          apkSha256: currentJob.targetApkSha256,
          signatureSha256: currentJob.extractedSignatureSha256,
          status: "published",
          origin: "automatic",
          apkSizeBytes: Number(currentJob.targetApkSizeBytes || 0),
          apkSize: Number(currentJob.targetApkSizeBytes || 0),
          patchSha256: currentJob.patchGenerated ? verifiedPatchSha : "",
          patchSizeBytes: Number(currentJob.patchSizeBytes || 0),
          patchSize: Number(currentJob.patchSizeBytes || 0),
          patchFromVersionCode: currentJob.patchGenerated ? currentJob.previousVersionCode : null,
          patchToVersionCode: currentJob.patchGenerated ? currentJob.extractedVersionCode : null,
          previousVersionCode: currentJob.patchGenerated ? currentJob.previousVersionCode : null,
          baseApkSha256: currentJob.patchGenerated ? currentJob.previousApkSha256 : "",
          targetApkSha256: currentJob.targetApkSha256,
          apkStoragePath: "",
          patchStoragePath: "",
          artifactStorageMode: "manual",
          releaseJobId: currentJob._id,
          publishedAt: new Date()
        }], { session });

        const updateResult = await ReleaseJob.updateOne(
          { _id: currentJob._id, status: "awaiting_upload", artifactStorageMode: "manual" },
          {
            $set: {
              status: "published",
              releaseId: created._id,
              manualVerified: true,
              completedAt: new Date(),
              apkPublicUrl: apkUrl,
              patchPublicUrl: currentJob.patchGenerated ? patchUrl : ""
            },
            $unset: {
              workerId: 1,
              leaseToken: 1,
              claimedAt: 1,
              heartbeatAt: 1,
              manualApkTempPath: 1,
              manualPatchTempPath: 1,
              apkTempPath: 1
            }
          },
          { session }
        );
        if (Number(updateResult.matchedCount || 0) !== 1) throw new Error("RELEASE_JOB_STATE_CHANGED");
      });
    } finally {
      await session.endSession();
    }

    await safeUnlink(job.manualApkTempPath || job.apkTempPath);
    await safeUnlink(job.manualPatchTempPath);
    return res.redirect("/apks");
  } catch (err) {
    console.error("Manual artifact attach/verify error:", err.message);
    return res.status(err instanceof ReleaseSecurityError ? 409 : 500).send("Manual artifact verification failed: " + escapeHtml(err.message));
  } finally {
    for (const tempPath of tempFiles) await safeUnlink(tempPath);
  }
});

app.post("/action/apk/manual-cancel", requireLogin, adminActionLimiter, csrfProtection, async (req, res) => {
  try {
    const job = await getAwaitingManualJob(req.body.jobId);
    if (!job) return res.redirect("/apks");

    const result = await ReleaseJob.updateOne(
      { _id: job._id, status: "awaiting_upload", artifactStorageMode: "manual" },
      {
        $set: { status: "failed", lastError: "Manual release cancelled by administrator.", completedAt: new Date() },
        $unset: { manualApkTempPath: 1, manualPatchTempPath: 1, apkTempPath: 1 }
      }
    );
    if (result.modifiedCount === 1) {
      await safeUnlink(job.manualApkTempPath || job.apkTempPath);
      await safeUnlink(job.manualPatchTempPath);
    }
  } catch (err) {
    console.error("Manual release cancel error:", err.message);
  }
  return res.redirect("/apks");
});

async function processMediaUploads(req, existingIconUrl, existingScreenshots, outUploadedIds) {
  let iconUrl = isValidHttpUrl(existingIconUrl) ? String(existingIconUrl).trim().substring(0, MAX_URL_LENGTH) : "";
  const screenshots = normalizeScreenshotUrls(existingScreenshots);
  if (req.files && req.files.iconFile && req.files.iconFile[0]) { 
    iconUrl = await uploadToCloudinary(req.files.iconFile[0].buffer, "rd_store/icons"); 
    const pid = extractCloudinaryPublicId(iconUrl);
    if (pid) outUploadedIds.push(pid);
  }
  if (req.files && req.files.screenshotFiles) { 
    for (const file of req.files.screenshotFiles.slice(0, 10)) { 
      if (screenshots.length >= 10) break; 
      const sUrl = await uploadToCloudinary(file.buffer, "rd_store/screenshots");
      screenshots.push(sUrl); 
      const pid = extractCloudinaryPublicId(sUrl);
      if (pid) outUploadedIds.push(pid);
    } 
  }
  return { iconUrl, screenshots: normalizeScreenshotUrls(screenshots) };
}

app.post("/action/apk/add", requireLogin, adminActionLimiter, upload.fields([]), csrfProtection, async (req, res) => {
  return res.status(403).send("Legacy manual publication is disabled for security. All releases must go through the Automatic Release Pipeline (Upload Signed APK) to ensure artifact verification.");
});

app.post("/action/apk/edit", requireLogin, adminActionLimiter, requireMultipartCsrfHeader, upload.fields([{ name: "iconFile", maxCount: 1 }, { name: "screenshotFiles", maxCount: 10 }]), csrfProtection, async (req, res) => {
  const newlyUploadedPublicIds = [];
  try {
    const id = getObjectId(req.body.id); if (!id) return res.status(400).send("Invalid APK ID.");
    
    const oldApk = await Apk.findById(id).lean();
    if (!oldApk) return res.status(404).send("APK not found.");

    const appName = safeString(req.body.appName, MAX_APP_NAME_LENGTH);
    const description = safeString(req.body.description, MAX_DESCRIPTION_LENGTH);

    if (!appName) return res.status(400).send("App Name is required.");

    const existingScreenshots = parseExistingScreenshots(req.body.existingScreenshots);
    const media = await processMediaUploads(req, req.body.existingIconUrl || "", existingScreenshots, newlyUploadedPublicIds);
    
    const orphanedImages = [];
    if (oldApk.iconUrl && oldApk.iconUrl !== media.iconUrl) {
      const pubId = extractCloudinaryPublicId(oldApk.iconUrl);
      if (pubId) orphanedImages.push(pubId);
    }
    const newScreenshotsSet = new Set(media.screenshots || []);
    for (const oldShot of (oldApk.screenshots || [])) {
      if (!newScreenshotsSet.has(oldShot)) {
        const pubId = extractCloudinaryPublicId(oldShot);
        if (pubId) orphanedImages.push(pubId);
      }
    }

    const updated = await Apk.findByIdAndUpdate(id, { $set: { appName, description, ...media } }, { runValidators: true, new: true });
    if (!updated) throw new Error("APK not found during update."); 
    
    for (const pubId of orphanedImages) {
      cloudinary.uploader.destroy(pubId).catch(()=>{});
    }

    return res.redirect("/apks");
  } catch (err) { 
    console.error("Edit APK Error:", err.message); 
    for (const pubId of newlyUploadedPublicIds) {
      try { await cloudinary.uploader.destroy(pubId); } catch (_) {}
    }
    return res.status(500).send("Edit Failed: " + escapeHtml(err.message)); 
  }
});

app.post("/action/apk/delete", requireLogin, adminActionLimiter, csrfProtection, async (req, res) => {
  try {
    const id = getObjectId(req.body.id);
    if (id) {
      await Apk.updateOne(
        { _id: id, status: "published" },
        { $set: { status: "retired" } }
      );
    }
  } catch (err) { console.error("Retire APK Error:", err.message); } 
  res.redirect("/apks");
});

/* =========================================================
   DEVICE ACTIONS
========================================================= */
app.post("/action/device/:type", requireLogin, adminActionLimiter, csrfProtection, async (req, res) => {
  const type = String(req.params.type || ""); const deviceId = safeString(req.body.deviceId, MAX_DEVICE_ID_LENGTH); const appId = safeString(req.body.appId, MAX_APP_ID_LENGTH);
  if (!deviceId && type !== "clear-all-history") return res.redirect("/");
  try {
    if (type === "nickname") { await Device.updateOne({ deviceId, appId }, { $set: { nickname: safeString(req.body.nickname, MAX_NICKNAME_LENGTH) } }); }
    if (type === "approve") { await Device.updateOne({ deviceId, appId }, { $set: { status: "approved" } }); }
    if (type === "pending") { await Device.updateOne({ deviceId, appId }, { $set: { status: "pending" } }); await closeOnlineSession(deviceId, appId, "pending", Date.now()); }
    if (type === "block") { await Device.updateOne({ deviceId, appId }, { $set: { status: "blocked" } }); await closeOnlineSession(deviceId, appId, "blocked", Date.now()); }
    if (type === "clear-history") await UsageSession.deleteMany({ deviceId, appId });
    if (type === "delete") {
      const session = await mongoose.startSession();
      try { await session.withTransaction(async () => { await Device.deleteOne({ deviceId, appId }, { session }); await UsageSession.deleteMany({ deviceId, appId }, { session }); }); }
      finally { await session.endSession(); }
    }
    if (type === "clear-all-history") await UsageSession.deleteMany({});
  } catch (err) { console.error("Device Action Error:", err.message); }
  res.redirect("/");
});

/* =========================================================
   DASHBOARD API
========================================================= */
app.get("/api/sessions/:deviceId", requireApiLogin, async (req, res) => {
  try {
    const deviceId = safeString(req.params.deviceId, MAX_DEVICE_ID_LENGTH); const appId = safeString(req.query.appId, MAX_APP_ID_LENGTH);
    if (!deviceId || !appId) return res.status(400).json({ success: false });
    await markStaleSessionsOffline();
    const sessions = await UsageSession.find({ deviceId, appId }).sort({ startTimestamp: -1 }).limit(200).lean();
    const now = Date.now();
    const formatted = sessions.map((item) => {
      const start = Number(item.startTimestamp); let end = Number(item.endTimestamp || item.lastSeenTimestamp); if (item.status === "online") end = now;
      const duration = item.status === "offline" && Number(item.durationMs) > 0 ? Number(item.durationMs) : Math.max(0, end - start);
      return { startTime: safeDate(item.startTime), lastSeenTime: safeDate(item.lastSeenTime), endTime: item.endTime ? safeDate(item.endTime) : item.status === "online" ? "Active" : safeDate(item.lastSeenTime), duration: formatDuration(duration), durationMs: duration, status: item.status, endReason: item.endReason || "unknown" };
    });
    return res.json({ success: true, sessions: formatted });
  } catch (err) { console.error("Sessions API error:", err.message); return res.status(500).json({ success: false }); }
});

app.get("/api/dashboard", requireApiLogin, async (req, res) => {
  try {
    await markStaleSessionsOffline();
    const search = safeString(req.query.search, MAX_SEARCH_LENGTH);
    const filter = ["all", "today", "7d", "30d"].includes(String(req.query.filter || "all")) ? String(req.query.filter || "all") : "all";
    const appFilter = safeString(req.query.appFilter, MAX_APP_ID_LENGTH) || "all";
    const requestedPage = Math.max(1, parseInt(req.query.page || "1", 10) || 1);
    const range = getRange(filter, "", ""); const now = Date.now(); const deviceMatch = {};

    if (appFilter !== "all") deviceMatch.appId = appFilter;
    if (search) {
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      deviceMatch.$or = [ { deviceId: { $regex: escaped, $options: "i" } }, { nickname: { $regex: escaped, $options: "i" } }, { status: { $regex: escaped, $options: "i" } } ];
    }

    const effectiveEndExpression = { $cond: [ { $eq: ["$status", "online"] }, now, { $ifNull: ["$endTimestamp", "$lastSeenTimestamp"] } ] };
    const sessionMatch = range.from !== null ? { startTimestamp: { $lte: range.to }, $or: [ { endTimestamp: { $gte: range.from } }, { endTimestamp: null, lastSeenTimestamp: { $gte: range.from } }, { status: "online" } ] } : {};
    if (appFilter !== "all") sessionMatch.appId = appFilter;

    const durationStartExpression = range.from !== null ? { $max: ["$startTimestamp", range.from] } : "$startTimestamp";
    const durationEndExpression = range.from !== null ? { $min: [effectiveEndExpression, range.to] } : effectiveEndExpression;

    const usagePipeline = [
      { $match: sessionMatch }, { $project: { deviceId: 1, appId: 1, durationStart: durationStartExpression, durationEnd: durationEndExpression } },
      { $project: { deviceId: 1, appId: 1, duration: { $max: [0, { $subtract: ["$durationEnd", "$durationStart"] }] } } },
      { $group: { _id: { deviceId: "$deviceId", appId: "$appId" }, totalUsage: { $sum: "$duration" }, sessionCount: { $sum: 1 } } }
    ];
    const chartPipeline = [
      { $match: sessionMatch }, { $project: { day: { $dateToString: { format: "%Y-%m-%d", date: "$startTime", timezone: "Asia/Kolkata" } }, durationStart: durationStartExpression, durationEnd: durationEndExpression } },
      { $project: { day: 1, duration: { $max: [0, { $subtract: ["$durationEnd", "$durationStart"] }] } } },
      { $group: { _id: "$day", usage: { $sum: "$duration" } } }, { $sort: { _id: 1 } }
    ];

    const onlineCutoff = now - ONLINE_TIMEOUT_MS; const skip = (requestedPage - 1) * DEVICES_PER_PAGE;
    const onlineMatch = { status: "online", lastSeenTimestamp: { $gte: onlineCutoff } };
    if (appFilter !== "all") onlineMatch.appId = appFilter;

    const results = await Promise.all([
      Device.aggregate([{ $match: deviceMatch }, { $group: { _id: "$status", count: { $sum: 1 } } }]),
      Device.countDocuments(deviceMatch),
      Device.find(deviceMatch).sort({ registeredAt: -1 }).skip(skip).limit(DEVICES_PER_PAGE).lean(),
      UsageSession.aggregate(usagePipeline),
      UsageSession.aggregate(chartPipeline),
      UsageSession.find(onlineMatch).select({ deviceId: 1, appId: 1 }).lean(),
      AppRegistry.find().select("appId appName").sort({ appName: 1 }).lean()
    ]);

    let totalDevices = 0, approved = 0, pending = 0, blocked = 0;
    results[0].forEach((item) => {
      const count = Number(item.count || 0); totalDevices += count;
      if (item._id === "approved") approved = count; if (item._id === "pending") pending = count; if (item._id === "blocked") blocked = count;
    });

    const usageMap = {}; let totalUsage = 0;
    results[3].forEach((item) => {
      const usage = Number(item.totalUsage || 0); const key = `${item._id.deviceId}_${item._id.appId}`;
      usageMap[key] = { totalUsage: usage, sessionCount: Number(item.sessionCount || 0) }; totalUsage += usage;
    });

    const onlineSet = new Set(results[5].map((item) => `${item.deviceId}_${item.appId}`));
    const totalPages = Math.max(1, Math.ceil(results[1] / DEVICES_PER_PAGE)); const currentPage = Math.min(requestedPage, totalPages);
    let devices = results[2];
    if (currentPage !== requestedPage) { devices = await Device.find(deviceMatch).sort({ registeredAt: -1 }).skip((currentPage - 1) * DEVICES_PER_PAGE).limit(DEVICES_PER_PAGE).lean(); }

    const deviceData = devices.map((device) => {
      const key = `${device.deviceId}_${device.appId}`; const stat = usageMap[key] || { totalUsage: 0, sessionCount: 0 };
      return { deviceId: device.deviceId, appId: device.appId, nickname: device.nickname || "", status: device.status, registeredAt: safeDate(device.registeredAt), usage: formatDuration(stat.totalUsage), sessions: stat.sessionCount, online: onlineSet.has(key) };
    });

    return res.json({
      success: true, stats: { totalDevices, approved, pending, blocked, online: onlineSet.size, totalUsage: formatDuration(totalUsage) },
      devices: deviceData, apps: results[6], pagination: { page: currentPage, totalPages, totalDevices: results[1] },
      chart: { labels: results[4].map((i) => i._id), data: results[4].map((i) => Math.round(Number(i.usage || 0) / 60000)) }
    });
  } catch (err) { console.error("Dashboard API error:", err.message); return res.status(500).json({ success: false }); }
});

/* =========================================================
   DASHBOARD PAGE
========================================================= */
app.get("/", requireLogin, csrfProtection, (req, res) => {
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Console V8.3.2</title><script nonce="__CSP_NONCE__" src="https://cdn.jsdelivr.net/npm/chart.js@4.5.0/dist/chart.umd.min.js"></script>${UI_STYLES}</head>
<body>${TOPBAR_HTML(res.locals.csrfToken)}<div class="container">
  <div class="page-title"><h1>Device Management</h1><p id="refreshStatus" class="status-line">Loading dashboard...</p></div>
  <div class="card"><div class="card-body"><form id="filterForm" class="filters"><input id="search" class="search" placeholder="Search device ID or nickname"><select id="appFilter"><option value="all">All Apps</option></select><select id="filter"><option value="all">All Time</option><option value="today">Today (IST)</option><option value="7d">Last 7 Days</option><option value="30d">Last 30 Days</option></select><button class="btn btn-blue" type="submit">Apply Filter</button><button type="button" class="btn btn-gray" id="manualRefreshBtn">Refresh</button></form>
  <div style="margin-top:12px"><form method="POST" action="/action/device/clear-all-history" class="confirm-action" data-confirm="WARNING: Permanently delete ALL session history for ALL apps?"><input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}"><button type="submit" class="btn btn-red">Clear All History</button></form></div></div></div>
  <div class="stats"><div class="stat"><div class="stat-label">TOTAL DEVICES</div><div class="stat-value" id="totalDevices">-</div></div><div class="stat"><div class="stat-label">APPROVED</div><div class="stat-value" id="approved">-</div></div><div class="stat"><div class="stat-label">PENDING</div><div class="stat-value" id="pending">-</div></div><div class="stat"><div class="stat-label">BLOCKED</div><div class="stat-value" id="blocked">-</div></div><div class="stat"><div class="stat-label">ONLINE NOW</div><div class="stat-value" id="online">-</div></div><div class="stat"><div class="stat-label">TOTAL USAGE</div><div class="stat-value" id="totalUsage">-</div></div></div>
  <div class="card"><div class="card-header">Usage Trend</div><div class="card-body"><div style="height:310px"><canvas id="usageChart"></canvas></div></div></div>
  <div class="card"><div class="card-header">Device Permissions</div><div class="table-wrap"><table><thead><tr><th>Nickname</th><th>Device ID & App</th><th>Permission</th><th>Live Status</th><th>Usage</th><th>Registered</th><th>Actions</th></tr></thead><tbody id="deviceTable"><tr><td colspan="7" style="text-align:center;padding:25px">Loading devices...</td></tr></tbody></table></div><div class="pagination"><button id="prevPage">Previous</button><span id="pageInfo">Page -</span><button id="nextPage">Next</button></div></div>
  <div class="modal-overlay" id="historyModal"><div class="modal"><div class="modal-header"><div id="modalTitle">Session History</div><button class="modal-close" id="closeModalBtn">×</button></div><div class="modal-body"><div class="table-wrap"><table><thead><tr><th>Started</th><th>Last Seen</th><th>Ended</th><th>Duration</th><th>Status</th><th>Reason</th></tr></thead><tbody id="historyTableBody"><tr><td colspan="6" style="text-align:center">Loading...</td></tr></tbody></table></div></div></div></div>
</div>
<script nonce="__CSP_NONCE__">
  const csrfToken = "${escapeHtml(res.locals.csrfToken)}";
  const REFRESH_SECONDS = ${DASHBOARD_REFRESH_SECONDS};
  let currentPage = 1;
  let chartInstance = null;
  let refreshTimer = null;
  let refreshInProgress = false;
  const refreshStatus = document.getElementById("refreshStatus");

  function escapeHTML(value) { return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;"); }

  async function refreshDashboard() {
    if (refreshInProgress) return; refreshInProgress = true; clearTimeout(refreshTimer);
    try {
      refreshStatus.textContent = "Refreshing data...";
      const params = new URLSearchParams();
      params.set("search", document.getElementById("search").value); params.set("filter", document.getElementById("filter").value); params.set("appFilter", document.getElementById("appFilter").value); params.set("page", currentPage);

      const response = await fetch("/api/dashboard?" + params.toString(), { credentials: "same-origin", cache: "no-store" });
      if (response.status === 401) { window.location.href = "/login"; return; }
      const data = await response.json(); if (!data.success) throw new Error("API error");

      updateAppDropdown(data.apps); updateStats(data.stats); updateTable(data.devices); updatePagination(data.pagination);

      if (chartInstance) chartInstance.destroy();
      chartInstance = new Chart(document.getElementById("usageChart"), {
        type: "line",
        data: { labels: data.chart.labels, datasets: [{ label: "Usage (mins)", data: data.chart.data, borderColor: "#2563eb", backgroundColor: "rgba(37,99,235,.08)", borderWidth: 2, fill: true }] },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }
      });
      refreshStatus.textContent = "Last refreshed: " + new Date().toLocaleTimeString("en-IN");
    } catch (error) { console.error(error); refreshStatus.textContent = "Unable to refresh."; } finally { refreshInProgress = false; scheduleRefresh(); }
  }

  document.getElementById("manualRefreshBtn").addEventListener("click", function(){ refreshDashboard(); });
  document.getElementById("closeModalBtn").addEventListener("click", function(){ closeModal(); });
  document.querySelectorAll(".confirm-action").forEach(function(form){ form.addEventListener("submit", function(e){ if(!window.confirm(form.getAttribute("data-confirm")||"Continue?")) e.preventDefault(); }); });
  function manualRefresh() { refreshDashboard(); }
  function updateAppDropdown(apps) {
    const appSelect = document.getElementById("appFilter"); const currentValue = appSelect.value;
    appSelect.innerHTML = '<option value="all">All Apps</option>';
    (apps || []).forEach(app => { if (app && app.appId) { const option = document.createElement("option"); option.value = app.appId; option.textContent = app.appName + " (" + app.appId + ")"; if (app.appId === currentValue) option.selected = true; appSelect.appendChild(option); } });
  }

  function updateStats(stats) {
    document.getElementById("totalDevices").textContent = stats.totalDevices; document.getElementById("approved").textContent = stats.approved; document.getElementById("pending").textContent = stats.pending; document.getElementById("blocked").textContent = stats.blocked; document.getElementById("online").textContent = stats.online; document.getElementById("totalUsage").textContent = stats.totalUsage;
  }

  function updateTable(devices) {
    const tbody = document.getElementById("deviceTable");
    if (!devices.length) { tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:25px">No devices found.</td></tr>'; return; }
    tbody.innerHTML = devices.map(function(device) {
      const deviceId = escapeHTML(device.deviceId); const appId = escapeHTML(device.appId); const nickname = escapeHTML(device.nickname); const status = escapeHTML(device.status); const liveClass = device.online ? "online" : "offline"; const liveText = device.online ? "ONLINE" : "OFFLINE";
      let actions = '<button type="button" class="btn btn-purple" data-history="' + deviceId + '" data-app="' + appId + '">History</button>';
      actions += '<form class="inline-form" method="POST" action="/action/device/clear-history"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><input type="hidden" name="appId" value="' + appId + '"><button class="btn btn-red" type="submit">Clear History</button></form>';
      if (device.status !== "approved") { actions += '<form class="inline-form" method="POST" action="/action/device/approve"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><input type="hidden" name="appId" value="' + appId + '"><button class="btn btn-green" type="submit">Approve</button></form>'; }
      if (device.status !== "blocked") { actions += '<form class="inline-form" method="POST" action="/action/device/block"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><input type="hidden" name="appId" value="' + appId + '"><button class="btn btn-orange" type="submit">Block</button></form>'; }
      if (device.status !== "pending") { actions += '<form class="inline-form" method="POST" action="/action/device/pending"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><input type="hidden" name="appId" value="' + appId + '"><button class="btn btn-yellow" type="submit">Pending</button></form>'; }
      actions += '<form class="inline-form" method="POST" action="/action/device/delete" class="inline-form confirm-action" data-confirm="Delete device and its history?"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><input type="hidden" name="appId" value="' + appId + '"><button class="btn btn-red" type="submit">Delete Device</button></form>';
      return '<tr><td><form class="inline-form" method="POST" action="/action/device/nickname"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><input type="hidden" name="appId" value="' + appId + '"><input class="nickname-input" name="nickname" maxlength="50" placeholder="Nickname" value="' + nickname + '"><button class="btn btn-blue" type="submit">Save</button></form></td><td><code>' + deviceId + '</code><br><span class="badge badge-app">' + appId + '</span></td><td><span class="badge ' + status + '">' + status.toUpperCase() + '</span></td><td><span class="badge ' + liveClass + '">' + liveText + '</span></td><td><strong>' + escapeHTML(device.usage) + '</strong><br><span style="font-size:11px;color:#6b7280">' + Number(device.sessions) + ' sessions</span></td><td>' + escapeHTML(device.registeredAt) + '</td><td class="action-cell">' + actions + '</td></tr>';
    }).join("");
    document.querySelectorAll("[data-history]").forEach(function(btn) { btn.addEventListener("click", function() { openHistory(btn.getAttribute("data-history"), btn.getAttribute("data-app")); }); });
  }

  async function openHistory(deviceId, appId) {
    const modal = document.getElementById("historyModal"); const title = document.getElementById("modalTitle"); const body = document.getElementById("historyTableBody");
    title.textContent = "History — " + deviceId + " (" + appId + ")"; body.innerHTML = '<tr><td colspan="6" style="text-align:center">Loading...</td></tr>'; modal.style.display = "flex";
    try {
      const response = await fetch("/api/sessions/" + encodeURIComponent(deviceId) + "?appId=" + encodeURIComponent(appId), { credentials: "same-origin", cache: "no-store" });
      if (response.status === 401) { window.location.href = "/login"; return; } const data = await response.json();
      if (!data.success || !data.sessions.length) { body.innerHTML = '<tr><td colspan="6" style="text-align:center">No session history available.</td></tr>'; return; }
      body.innerHTML = data.sessions.map(function(item) { const statusClass = item.status === "online" ? "online" : "offline"; return '<tr><td>' + escapeHTML(item.startTime) + '</td><td>' + escapeHTML(item.lastSeenTime) + '</td><td>' + escapeHTML(item.endTime) + '</td><td><strong>' + escapeHTML(item.duration) + '</strong></td><td><span class="badge ' + statusClass + '">' + escapeHTML(String(item.status).toUpperCase()) + '</span></td><td>' + escapeHTML(item.endReason) + '</td></tr>'; }).join("");
    } catch (error) { body.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#b91c1c">Failed to load session history.</td></tr>'; }
  }

  function closeModal() { document.getElementById("historyModal").style.display = "none"; } window.addEventListener("click", function(event) { if (event.target === document.getElementById("historyModal")) { closeModal(); } });
  function updatePagination(p) { currentPage = p.page; document.getElementById("pageInfo").textContent = "Page " + p.page + " of " + p.totalPages; document.getElementById("prevPage").disabled = p.page <= 1; document.getElementById("nextPage").disabled = p.page >= p.totalPages; }
  function scheduleRefresh() { clearTimeout(refreshTimer); if (!document.hidden) { refreshTimer = setTimeout(refreshDashboard, REFRESH_SECONDS * 1000); } }
  document.getElementById("filterForm").addEventListener("submit", function(event) { event.preventDefault(); currentPage = 1; refreshDashboard(); }); document.getElementById("prevPage").addEventListener("click", function() { if (currentPage > 1) { currentPage--; refreshDashboard(); } }); document.getElementById("nextPage").addEventListener("click", function() { currentPage++; refreshDashboard(); }); document.addEventListener("visibilitychange", function() { if (document.hidden) { clearTimeout(refreshTimer); } else { scheduleRefresh(); } });
  refreshDashboard();
</script></body></html>`);
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) { console.error("Upload error:", err.code, err.message); return res.status(400).send("Upload failed: " + escapeHtml(err.message)); }
  if (err) { console.error("Unhandled request error:", err.stack || err.message || err); return res.status(500).send("Internal server error."); }
  next();
});
app.use((req, res) => res.status(404).send("404 Not Found"));

let server = null; let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return; shuttingDown = true; console.log(signal + " received. Shutting down...");
  clearInterval(cleanupInterval); clearInterval(releaseWorkerInterval); clearInterval(staleRecoveryInterval);
  try { if (server) await new Promise((resolve) => server.close(resolve)); await mongoose.disconnect(); console.log("Shutdown complete."); process.exit(0); } catch (err) { console.error("Shutdown error:", err.message); process.exit(1); }
}
process.on("SIGTERM", () => shutdown("SIGTERM")); process.on("SIGINT", () => shutdown("SIGINT"));

async function verifyMongoTransactionSupport() {
  const session = await mongoose.startSession();
  try {
    session.startTransaction();
    await session.commitTransaction();
    console.log("MongoDB transaction capability verified.");
  } catch (err) {
    try { await session.abortTransaction(); } catch (_) {}
    throw new Error("MongoDB transactions are required for release publication: " + err.message);
  } finally {
    await session.endSession();
  }
}

async function verifyReleaseToolchain() {
  const checks = [
    { name: "aapt2", cmd: AAPT_PATH, args: ["version"] },
    { name: "aapt", cmd: AAPT_FALLBACK_PATH, args: ["version"] },
    { name: "apksigner", cmd: APKSIGNER_PATH, args: ["version"] },
    { name: "bsdiff", cmd: BSDIFF_CLI_PATH, args: [] },
    { name: "bspatch", cmd: BSPATCH_CLI_PATH, args: [] }
  ];
  const failures = [];
  for (const check of checks) {
    try {
      await runCli(check.cmd, check.args, { timeout: 15000 });
      console.log(`Release toolchain OK: ${check.name} -> ${check.cmd}`);
    } catch (err) {
      // bsdiff/bspatch intentionally exit non-zero when called without their
      // required file arguments; ENOENT is the decisive missing-tool signal.
      if (err && err.code !== "ENOENT" && (check.name === "bsdiff" || check.name === "bspatch")) {
        console.log(`Release toolchain OK: ${check.name} -> ${check.cmd}`);
      } else {
        failures.push(`${check.name} (${check.cmd}): ${err && err.code === "ENOENT" ? "not found" : String(err && err.message || err)}`);
      }
    }
  }
  if (failures.length) throw new Error("Release toolchain is incomplete: " + failures.join(" | "));
}

async function startServer() {
  try {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 10000, socketTimeoutMS: 45000 });

    try {
      assertArtifactStorageReady();
      console.log("Artifact storage ready: " + storageModeLabel());
    } catch (storageErr) {
      console.error("Artifact storage is not ready; release worker will remain paused:", storageErr.message);
    }
    await verifyMongoTransactionSupport();

    try {
      await Device.updateMany({ appId: { $exists: false } }, { $set: { appId: "default_app" } });
      await UsageSession.updateMany({ appId: { $exists: false } }, { $set: { appId: "default_app" } });
      const distinctAppIds = await Device.distinct("appId");
      for (const appId of distinctAppIds) { if (!appId) continue; await AppRegistry.updateOne({ appId }, { $setOnInsert: { appId, appName: appId } }, { upsert: true }).catch((err) => console.error("App registry backfill error:", err.message)); }
    } catch (err) {}
    
    try { 
      await Device.syncIndexes(); 
      await UsageSession.syncIndexes(); 
      await Apk.syncIndexes(); 
      await AppRegistry.syncIndexes(); 
      await ReleaseJob.syncIndexes();
      await ReleasePackageLock.syncIndexes();
    } catch (err) {
      console.error("FATAL: MongoDB index synchronization failed:", err);
      process.exit(1);
    }

    await ensureTempDir();
    await verifyReleaseToolchain();

    await reconcileOrphanedPublications();
    await recoverStaleJobs();

    server = app.listen(PORT, () => {
      console.log("V8.3.2 Ultimate Render Production Edition running on port " + PORT + " (artifact storage mode: " + storageModeLabel() + ")");
    });
  } catch (err) { 
    console.error("Server startup failed:", err);
    process.exit(1); 
  }
}

startServer();
