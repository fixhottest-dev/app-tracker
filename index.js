"use strict";

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const streamifier = require("streamifier");

const app = express();

/* =========================================================
   V6.5.0 PRODUCTION EDITION (FULLY BUG FIXED)
   - Existing device/session dashboard preserved
   - Strict APK metadata validation
   - APK SHA-256 + signing certificate SHA-256 support
   - Safer URL/package/version validation
   - Better multipart limits and error handling
   - Safer app-registry rename/delete handling
   - HSTS in production
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

if (!MONGO_URI) {
  console.error("FATAL: MONGO_URI is missing.");
  process.exit(1);
}
if (!ADMIN_PASSWORD && !ADMIN_PASSWORD_HASH) {
  console.error("FATAL: ADMIN_PASSWORD or ADMIN_PASSWORD_HASH is required.");
  process.exit(1);
}
if (IS_PRODUCTION && !SESSION_SECRET) {
  console.error("FATAL: SESSION_SECRET is required in production.");
  process.exit(1);
}

try {
  cloudinary.config({
    cloud_name: String(process.env.CLOUDINARY_CLOUD_NAME || "").trim(),
    api_key: String(process.env.CLOUDINARY_API_KEY || "").trim(),
    api_secret: String(process.env.CLOUDINARY_API_SECRET || "").trim()
  });
} catch (err) {
  console.error("Cloudinary config error:", err);
}

/* =========================================================
   SECURITY / HTTP SETUP
========================================================= */
app.set("trust proxy", true);
app.disable("x-powered-by");
app.use(express.urlencoded({ extended: true, limit: "100kb" }));
app.use(express.json({ limit: "100kb" }));
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  if (IS_PRODUCTION) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
});

app.use(session({
  name: "admin.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: MONGO_URI,
    collectionName: "admin_sessions",
    ttl: ADMIN_SESSION_MAX_AGE / 1000,
    autoRemove: "native"
  }),
  cookie: {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: "lax",
    maxAge: ADMIN_SESSION_MAX_AGE
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many login attempts."
});
const trackingLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: "ERROR", message: "RATE_LIMITED" }
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});
const adminActionLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many admin actions. Please try again shortly."
});

/* =========================================================
   UPLOADS
========================================================= */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024,
    files: 11,
    fields: 30,
    parts: 45
  },
  fileFilter: (req, file, cb) => {
    if (file.fieldname === "iconFile" || file.fieldname === "screenshotFiles") {
      if (!String(file.mimetype || "").toLowerCase().startsWith("image/")) {
        return cb(new Error("Only image files are allowed for icon/screenshots."));
      }
      return cb(null, true);
    }
    return cb(new Error("Unexpected upload field."));
  }
});

function uploadToCloudinary(buffer, folderName) {
  return new Promise((resolve, reject) => {
    if (!buffer || !buffer.length) return reject(new Error("Empty upload."));
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder: folderName, resource_type: "image" },
      (error, result) => {
        if (error) return reject(error);
        if (!result || !result.secure_url) return reject(new Error("Cloudinary did not return a secure URL."));
        resolve(result.secure_url);
      }
    );
    streamifier.createReadStream(buffer).pipe(uploadStream);
  });
}

/* =========================================================
   DATABASE SCHEMAS
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
SessionSchema.index(
  { deviceId: 1, appId: 1 },
  { unique: true, partialFilterExpression: { status: "online" }, name: "unique_online_session_per_device_app" }
);

const ApkSchema = new mongoose.Schema({
  appName: { type: String, required: true, trim: true, maxlength: MAX_APP_NAME_LENGTH },
  description: { type: String, default: "", trim: true, maxlength: MAX_DESCRIPTION_LENGTH },
  versionName: { type: String, required: true, trim: true, maxlength: MAX_VERSION_NAME_LENGTH },
  versionCode: { type: Number, required: true, min: 1, index: true },
  packageName: { type: String, required: true, trim: true, maxlength: MAX_PACKAGE_LENGTH, index: true },
  apkUrl: { type: String, required: true, trim: true, maxlength: MAX_URL_LENGTH },
  iconUrl: { type: String, default: "", trim: true, maxlength: MAX_URL_LENGTH },
  screenshots: { type: [String], default: [] },
  apkSha256: { type: String, default: "", trim: true, lowercase: true, maxlength: MAX_HASH_LENGTH },
  signatureSha256: { type: String, default: "", trim: true, lowercase: true, maxlength: MAX_HASH_LENGTH },
  createdAt: { type: Date, default: Date.now, index: true }
}, { versionKey: false });

ApkSchema.index({ packageName: 1, versionCode: -1, createdAt: -1 }, { name: "apk_package_version_history" });

const AppRegistry = mongoose.model("AppRegistry", AppRegistrySchema);
const Device = mongoose.model("Device", DeviceSchema);
const UsageSession = mongoose.model("UsageSession", SessionSchema);
const Apk = mongoose.model("Apk", ApkSchema);

/* =========================================================
   HELPERS / VALIDATION
========================================================= */
function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
function safeString(value, maxLength) {
  return String(value ?? "").trim().substring(0, maxLength);
}
// Relaxed regex to allow legacy package names (without dots)
function isValidPackageName(value) {
  return /^[A-Za-z][A-Za-z0-9_\.]*$/.test(String(value || ""));
}
function isValidAppId(value) {
  const s = String(value || "").trim();
  return s.length > 0 && s.length <= MAX_APP_ID_LENGTH && !/[\r\n<>"']/.test(s);
}
function isValidVersionName(value) {
  const s = String(value || "").trim();
  return s.length > 0 && s.length <= MAX_VERSION_NAME_LENGTH && !/[\r\n<>]/.test(s);
}
function parsePositiveVersionCode(value) {
  const s = String(value ?? "").trim();
  if (!/^\d+$/.test(s)) return null;
  const n = Number(s);
  if (!Number.isSafeInteger(n) || n < 1) return null;
  return n;
}
function normalizeSha256(value) {
  const s = String(value ?? "").trim().toLowerCase();
  if (!s) return "";
  return /^[a-f0-9]{64}$/.test(s) ? s : null;
}
function isValidHttpUrl(value) {
  try {
    const u = new URL(String(value || "").trim());
    return (u.protocol === "https:" || u.protocol === "http:") && !!u.hostname;
  } catch (err) {
    return false;
  }
}
function safeDate(value) {
  if (!value) return "N/A";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("en-IN", {
    timeZone: "Asia/Kolkata",
    dateStyle: "medium",
    timeStyle: "medium",
    hour12: true
  });
}
function formatDuration(ms) {
  const safeMs = Number(ms);
  if (!Number.isFinite(safeMs) || safeMs <= 0) return "0s";
  const totalSeconds = Math.floor(safeMs / 1000);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const parts = [];
  if (days > 0) parts.push(days + "d");
  if (hours > 0) parts.push(hours + "h");
  if (minutes > 0) parts.push(minutes + "m");
  if (seconds > 0 || parts.length === 0) parts.push(seconds + "s");
  return parts.join(" ");
}
function getISTStartOfDay() {
  const now = new Date();
  const formatter = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Kolkata",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  });
  const parts = formatter.formatToParts(now);
  const values = {};
  parts.forEach((part) => {
    if (part.type !== "literal") values[part.type] = part.value;
  });
  return Date.UTC(Number(values.year), Number(values.month) - 1, Number(values.day), 0, 0, 0) - (5.5 * 60 * 60 * 1000);
}
function getRange(filter, customFrom, customTo) {
  const now = Date.now();
  let from = null;
  let to = now;
  if (filter === "today") from = getISTStartOfDay();
  if (filter === "7d") from = now - (7 * 24 * 60 * 60 * 1000);
  if (filter === "30d") from = now - (30 * 24 * 60 * 60 * 1000);
  if (filter === "custom") {
    if (customFrom) {
      const parsed = new Date(customFrom + "T00:00:00+05:30");
      if (!Number.isNaN(parsed.getTime())) from = parsed.getTime();
    }
    if (customTo) {
      const parsed = new Date(customTo + "T23:59:59.999+05:30");
      if (!Number.isNaN(parsed.getTime())) to = parsed.getTime();
    }
  }
  if (from !== null && from > to) {
    const temp = from;
    from = to;
    to = temp;
  }
  return { from, to };
}
function getObjectId(value) {
  const s = safeString(value, 100);
  return mongoose.Types.ObjectId.isValid(s) ? s : null;
}
function parseExistingScreenshots(value) {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((x) => typeof x === "string" && isValidHttpUrl(x))
      .slice(0, 10)
      .map((x) => x.substring(0, MAX_URL_LENGTH));
  } catch (err) {
    return [];
  }
}
function normalizeScreenshotUrls(list) {
  return Array.from(new Set((Array.isArray(list) ? list : [])
    .filter((x) => typeof x === "string" && isValidHttpUrl(x))
    .map((x) => x.trim().substring(0, MAX_URL_LENGTH)))).slice(0, 10);
}

/* =========================================================
   AUTH / CSRF
========================================================= */
function csrfProtection(req, res, next) {
  if (!req.session) return res.status(500).send("Session unavailable.");
  const method = req.method.toUpperCase();
  const protectedMethod = ["POST", "PUT", "PATCH", "DELETE"].includes(method);
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  res.locals.csrfToken = req.session.csrfToken;
  if (protectedMethod) {
    const token = req.body?._csrf || req.get("x-csrf-token");
    if (!token || token !== req.session.csrfToken) return res.status(403).send("CSRF validation failed.");
  }
  next();
}
function requireLogin(req, res, next) {
  if (req.session && req.session.adminAuthenticated === true) return next();
  return res.redirect("/login");
}
function requireApiLogin(req, res, next) {
  if (req.session && req.session.adminAuthenticated === true) return next();
  return res.status(401).json({ success: false, error: "UNAUTHORIZED" });
}
async function verifyPassword(password) {
  if (ADMIN_PASSWORD_HASH) return bcrypt.compare(String(password || ""), ADMIN_PASSWORD_HASH);
  if (!ADMIN_PASSWORD) return false;
  const input = Buffer.from(String(password || ""));
  const stored = Buffer.from(ADMIN_PASSWORD);
  if (input.length !== stored.length) return false;
  return crypto.timingSafeEqual(input, stored);
}

/* =========================================================
   SESSION CLEANUP
========================================================= */
async function closeOnlineSession(deviceId, appId, reason, timestamp) {
  const now = Number(timestamp) || Date.now();
  const nowDate = new Date(now);
  const sessionDoc = await UsageSession.findOneAndUpdate(
    { deviceId, appId, status: "online" },
    {
      $set: {
        status: "offline",
        endReason: reason,
        endTime: nowDate,
        endTimestamp: now,
        lastSeenTime: nowDate,
        lastSeenTimestamp: now,
        durationMs: 0
      }
    },
    { new: true, sort: { startTimestamp: -1 } }
  );
  if (!sessionDoc) return null;
  const duration = Math.max(0, now - Number(sessionDoc.startTimestamp));
  sessionDoc.durationMs = duration;
  await sessionDoc.save();
  return sessionDoc;
}

let cleanupRunning = false;
async function markStaleSessionsOffline() {
  if (cleanupRunning) return;
  cleanupRunning = true;
  try {
    const now = Date.now();
    const cutoff = now - ONLINE_TIMEOUT_MS;
    const staleSessions = await UsageSession.find({
      status: "online",
      lastSeenTimestamp: { $lt: cutoff }
    }).select({ _id: 1, startTimestamp: 1, lastSeenTimestamp: 1 }).lean();
    if (!staleSessions.length) return;
    const operations = staleSessions.map((item) => {
      const endTimestamp = Number(item.lastSeenTimestamp);
      const duration = Math.max(0, endTimestamp - Number(item.startTimestamp));
      return {
        updateOne: {
          filter: { _id: item._id, status: "online" },
          update: {
            $set: {
              status: "offline",
              endReason: "timeout",
              endTime: new Date(endTimestamp),
              endTimestamp,
              durationMs: duration
            }
          }
        }
      };
    });
    if (operations.length) await UsageSession.bulkWrite(operations, { ordered: false });
  } catch (err) {
    console.error("Session cleanup error:", err.message);
  } finally {
    cleanupRunning = false;
  }
}
const cleanupInterval = setInterval(markStaleSessionsOffline, CLEANUP_INTERVAL_MS);
cleanupInterval.unref();

/* =========================================================
   TRACKING API
========================================================= */
const knownApps = new Set();

async function ensureAppRegistry(appId) {
  if (!knownApps.has(appId)) {
    await AppRegistry.updateOne(
      { appId },
      { $setOnInsert: { appId, appName: appId } },
      { upsert: true }
    );
    knownApps.add(appId);
  }
}

async function handleTracking(req, res) {
  const deviceId = safeString(req.query.id || req.body?.id, MAX_DEVICE_ID_LENGTH);
  const appId = safeString(req.query.appId || req.body?.appId, MAX_APP_ID_LENGTH) || "default_app";
  let rawAction = String(req.query.action || req.body?.action || req.query.status || req.body?.status || "start").trim().toLowerCase();
  if (rawAction === "offline") rawAction = "stop";
  const action = ["start", "ping", "stop"].includes(rawAction) ? rawAction : "start";

  if (!deviceId) return res.status(400).json({ status: "ERROR", message: "DEVICE_ID_MISSING" });
  if (mongoose.connection.readyState !== 1) return res.status(503).json({ status: "ERROR", message: "DATABASE_OFFLINE" });

  try {
    await ensureAppRegistry(appId);

    let device = await Device.findOne({ deviceId, appId });
    if (!device) {
      try {
        device = await Device.create({ deviceId, appId, status: "pending", registeredAt: new Date() });
      } catch (err) {
        if (err && err.code === 11000) device = await Device.findOne({ deviceId, appId });
        else throw err;
      }
    }

    if (!device || device.status !== "approved") {
      await closeOnlineSession(deviceId, appId, device && device.status === "blocked" ? "blocked" : "pending", Date.now());
      return res.json({ status: "BLOCKED", redirectUrl: REDIRECT_URL });
    }

    const now = Date.now();
    const nowDate = new Date(now);
    if (action === "stop") {
      const stopped = await closeOnlineSession(deviceId, appId, "stop", now);
      return res.json({ status: "ALLOWED", action: stopped ? "STOPPED" : "NO_ACTIVE_SESSION" });
    }

    let activeSession = await UsageSession.findOne({ deviceId, appId, status: "online" });
    if (activeSession) {
      activeSession.lastSeenTime = nowDate;
      activeSession.lastSeenTimestamp = now;
      await activeSession.save();
      return res.json({ status: "ALLOWED", action: "HEARTBEAT" });
    }

    try {
      activeSession = await UsageSession.create({
        deviceId,
        appId,
        startTime: nowDate,
        lastSeenTime: nowDate,
        startTimestamp: now,
        lastSeenTimestamp: now,
        status: "online"
      });
    } catch (err) {
      if (err && err.code === 11000) {
        activeSession = await UsageSession.findOneAndUpdate(
          { deviceId, appId, status: "online" },
          { $set: { lastSeenTime: nowDate, lastSeenTimestamp: now } },
          { new: true }
        );
      } else {
        throw err;
      }
    }

    return res.json({
      status: "ALLOWED",
      action: "STARTED",
      sessionId: activeSession ? String(activeSession._id) : null
    });
  } catch (err) {
    console.error("Tracking error:", err.message);
    return res.status(500).json({ status: "ERROR", message: "TRACKING_FAILED" });
  }
}

app.get(["/track", "/index.php"], trackingLimiter, handleTracking);
app.post(["/track", "/index.php"], trackingLimiter, handleTracking);

/* =========================================================
   PUBLIC APK CATALOG API
========================================================= */
app.get("/api/updates", apiLimiter, async (req, res) => {
  try {
    const apks = await Apk.find()
      .sort({ packageName: 1, versionCode: -1, createdAt: -1 })
      .select("-_id -createdAt") // Space removed to prevent API crash
      .lean();
    return res.status(200).json(apks);
  } catch (err) {
    console.error("Updates API error:", err.message);
    return res.status(500).json({ error: "Failed to fetch updates" });
  }
});

/* =========================================================
   UI
========================================================= */
const UI_STYLES = `
<style>
:root{--bg:#f5f6f8;--border:#e5e7eb;--text:#111827;--blue:#2563eb}*{box-sizing:border-box;font-family:Inter,system-ui,sans-serif}body{margin:0;background:var(--bg);color:var(--text)}.topbar{min-height:64px;background:#111827;color:white;display:flex;align-items:center;justify-content:space-between;padding:10px 24px;gap:15px}.brand{font-size:17px;font-weight:700}.brand span{color:#9ca3af;font-weight:400;margin-left:8px;font-size:13px}.container{max-width:1500px;margin:auto;padding:24px}.page-title{margin-bottom:20px}.page-title h1{font-size:24px;margin:0 0 4px}.status-line{font-size:12px;color:#6b7280}.card{background:white;border:1px solid var(--border);border-radius:10px;margin-bottom:18px}.card-header{padding:16px 18px;border-bottom:1px solid var(--border);font-weight:650;font-size:14px}.card-body{padding:18px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:18px}.stat{background:white;border:1px solid var(--border);border-radius:10px;padding:18px}.stat-label{font-size:12px;color:#6b7280;margin-bottom:8px}.stat-value{font-size:25px;font-weight:700}.filters{display:flex;flex-wrap:wrap;gap:10px;align-items:center}input,select,textarea{padding:9px 11px;border:1px solid #d1d5db;border-radius:7px;font-size:13px;background:white}.search{min-width:260px}.btn{border:0;border-radius:7px;padding:9px 12px;font-size:12px;font-weight:600;cursor:pointer;color:white;display:inline-flex;align-items:center;justify-content:center;gap:5px;text-decoration:none}.btn-dark{background:#111827}.btn-blue{background:#2563eb}.btn-green{background:#15803d}.btn-orange{background:#ea580c}.btn-yellow{background:#a16207}.btn-red{background:#b91c1c}.btn-purple{background:#6d28d9}.btn-gray{background:#e5e7eb;color:#111827}.btn:hover{opacity:.9}.btn:disabled{opacity:.55;cursor:not-allowed}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:900px}th{background:#f9fafb;color:#6b7280;font-size:11px;text-transform:uppercase}th,td{padding:13px;border-bottom:1px solid var(--border);text-align:left;font-size:13px}code{font-size:11px;background:#f3f4f6;padding:4px 6px;border-radius:4px;word-break:break-all}.badge{display:inline-block;padding:5px 8px;border-radius:20px;font-size:10px;font-weight:700}.badge-app{background:#e0e7ff;color:#4338ca;font-size:10px;margin-top:4px}.approved,.online{background:#dcfce7;color:#166534}.pending{background:#fef3c7;color:#92400e}.blocked,.offline{background:#fee2e2;color:#991b1b}.action-cell{display:flex;gap:5px;flex-wrap:wrap;min-width:430px}.inline-form{margin:0;display:inline-flex;gap:5px;align-items:center}.nickname-input{width:125px;padding:7px;font-size:12px}.form-group{margin-bottom:15px}.form-group label{display:block;font-size:13px;font-weight:600;margin-bottom:6px}.form-group input,.form-group textarea{width:100%}.pagination{display:flex;gap:12px;align-items:center;padding:15px;justify-content:center}.pagination button{padding:8px 14px;border:1px solid #ddd;border-radius:6px;cursor:pointer}.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);align-items:center;justify-content:center;padding:20px;z-index:999}.modal{background:#fff;border-radius:12px;width:min(1100px,100%);max-height:90vh;overflow:auto}.modal-header{padding:16px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;font-weight:700}.modal-close{border:0;background:transparent;font-size:26px;cursor:pointer}.modal-body{padding:18px}@media(max-width:800px){.topbar{align-items:flex-start;flex-direction:column}.container{padding:12px}}
</style>`;

const TOPBAR_HTML = (csrfToken) => `
<div class="topbar">
  <div class="brand">Admin Console<span>V6.5.0 Production Edition</span></div>
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
    <a href="/" class="btn btn-blue">Devices</a>
    <a href="/apps" class="btn btn-orange">App Systems</a>
    <a href="/apks" class="btn btn-purple">APK Manager</a>
    <form method="POST" action="/logout" style="margin:0"><input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}"><button class="btn btn-gray" type="submit">Logout</button></form>
  </div>
</div>`;

/* =========================================================
   LOGIN
========================================================= */
app.get("/login", csrfProtection, (req, res) => {
  if (req.session && req.session.adminAuthenticated) return res.redirect("/");
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title>${UI_STYLES}</head><body style="display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0"><div class="card" style="width:100%;max-width:420px;padding:24px"><h1 style="margin-top:0">Login</h1>${req.query.error ? '<div style="color:#b91c1c;margin-bottom:10px;font-size:13px">Invalid username/password</div>' : ""}<form method="POST" action="/login"><input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}"><div class="form-group"><label>Username</label><input type="text" name="username" required autocomplete="username"></div><div class="form-group"><label>Password</label><input type="password" name="password" required autocomplete="current-password"></div><button class="btn btn-dark" style="width:100%" type="submit">Sign In</button></form></div></body></html>`);
});

app.post("/login", loginLimiter, csrfProtection, async (req, res) => {
  try {
    const username = safeString(req.body.username, 100);
    const password = String(req.body.password || "");
    if (username !== ADMIN_USERNAME || !(await verifyPassword(password))) return res.redirect("/login?error=1");

    req.session.regenerate((err) => {
      if (err) return res.redirect("/login?error=1");
      req.session.adminAuthenticated = true;
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      req.session.save((saveErr) => res.redirect(saveErr ? "/login?error=1" : "/"));
    });
  } catch (err) {
    console.error("Login error:", err.message);
    res.redirect("/login?error=1");
  }
});

app.post("/logout", requireLogin, csrfProtection, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("admin.sid");
    res.redirect("/login");
  });
});

/* =========================================================
   APP MANAGER
========================================================= */
app.get("/apps", requireLogin, csrfProtection, async (req, res) => {
  try {
    const apps = await AppRegistry.find().sort({ createdAt: -1 }).lean();
    const deviceCounts = await Device.aggregate([{ $group: { _id: "$appId", count: { $sum: 1 } } }]);
    const countMap = {};
    deviceCounts.forEach((d) => { countMap[d._id] = d.count; });

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
        <td><form class="inline-form" method="POST" action="/action/app-registry/delete" onsubmit="return confirm('DANGER: This deletes the app and all tracking history for this app. Continue?')">
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
  } catch (err) {
    console.error("Apps page error:", err.message);
    res.status(500).send("Error: " + escapeHtml(err.message));
  }
});

app.post("/action/app-registry/add", requireLogin, adminActionLimiter, csrfProtection, async (req, res) => {
  try {
    const appId = safeString(req.body.appId, MAX_APP_ID_LENGTH);
    const appName = safeString(req.body.appName, MAX_APP_NAME_LENGTH);
    if (!isValidAppId(appId) || !appName) return res.redirect("/apps");
    await AppRegistry.create({ appId, appName });
  } catch (err) {
    console.error("Add App Error:", err.message);
  }
  res.redirect("/apps");
});

app.post("/action/app-registry/edit", requireLogin, adminActionLimiter, csrfProtection, async (req, res) => {
  try {
    const id = getObjectId(req.body.id);
    const oldAppId = safeString(req.body.oldAppId, MAX_APP_ID_LENGTH);
    const newAppId = safeString(req.body.newAppId, MAX_APP_ID_LENGTH);
    const appName = safeString(req.body.appName, MAX_APP_NAME_LENGTH);
    if (!id || !isValidAppId(newAppId) || !appName || !oldAppId) return res.redirect("/apps");

    if (oldAppId === newAppId) {
      await AppRegistry.findByIdAndUpdate(id, { $set: { appId: newAppId, appName } });
      knownApps.add(newAppId);
      return res.redirect("/apps");
    }

    const duplicate = await AppRegistry.findOne({ appId: newAppId }).select("_id").lean();
    if (duplicate && String(duplicate._id) !== String(id)) return res.redirect("/apps");

    await AppRegistry.findByIdAndUpdate(id, { $set: { appId: newAppId, appName } });
    await Device.updateMany({ appId: oldAppId }, { $set: { appId: newAppId } });
    await UsageSession.updateMany({ appId: oldAppId }, { $set: { appId: newAppId } });
    knownApps.delete(oldAppId);
    knownApps.add(newAppId);
  } catch (err) {
    console.error("Edit App Error:", err.message);
  }
  res.redirect("/apps");
});

app.post("/action/app-registry/delete", requireLogin, adminActionLimiter, csrfProtection, async (req, res) => {
  try {
    const id = getObjectId(req.body.id);
    const appId = safeString(req.body.appId, MAX_APP_ID_LENGTH);
    if (id && appId) {
      await Promise.all([
        AppRegistry.findByIdAndDelete(id),
        Device.deleteMany({ appId }),
        UsageSession.deleteMany({ appId })
      ]);
      knownApps.delete(appId);
    }
  } catch (err) {
    console.error("Delete App Error:", err.message);
  }
  res.redirect("/apps");
});

/* =========================================================
   APK MANAGER
========================================================= */
function apkFormFields(editApk, csrfToken) {
  const isEditing = !!editApk;
  return `
    <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}">
    ${isEditing ? `<input type="hidden" name="id" value="${escapeHtml(editApk._id)}"><input type="hidden" name="existingIconUrl" value="${escapeHtml(editApk.iconUrl || "")}"><input type="hidden" name="existingScreenshots" value="${escapeHtml(JSON.stringify(editApk.screenshots || []))}">` : ""}
    <div class="form-group"><label>App Name</label><input type="text" name="appName" required maxlength="100" value="${isEditing ? escapeHtml(editApk.appName) : ""}" placeholder="Example App"></div>
    <div class="form-group"><label>Package Name</label><input type="text" name="packageName" required maxlength="200" value="${isEditing ? escapeHtml(editApk.packageName) : ""}" placeholder="com.example.app"></div>
    <div class="form-group"><label>Version Name</label><input type="text" name="versionName" required maxlength="50" value="${isEditing ? escapeHtml(editApk.versionName) : ""}" placeholder="2.0"></div>
    <div class="form-group"><label>Version Code</label><input type="number" name="versionCode" required min="1" step="1" value="${isEditing ? escapeHtml(editApk.versionCode) : ""}" placeholder="20"></div>
    <div class="form-group" style="grid-column:1/-1"><label>Direct APK URL</label><input type="url" name="apkUrl" required maxlength="500" value="${isEditing ? escapeHtml(editApk.apkUrl) : ""}" placeholder="https://example.com/app.apk"></div>
    <div class="form-group" style="grid-column:1/-1"><label>APK SHA-256 <span class="status-line">(64 hex characters; strongly recommended)</span></label><input type="text" name="apkSha256" maxlength="64" pattern="[A-Fa-f0-9]{64}" value="${isEditing ? escapeHtml(editApk.apkSha256 || "") : ""}" placeholder="SHA-256 of the complete APK file"></div>
    <div class="form-group" style="grid-column:1/-1"><label>Signing Certificate SHA-256 <span class="status-line">(64 hex characters; recommended)</span></label><input type="text" name="signatureSha256" maxlength="64" pattern="[A-Fa-f0-9]{64}" value="${isEditing ? escapeHtml(editApk.signatureSha256 || "") : ""}" placeholder="SHA-256 of the APK signing certificate"></div>
    <div class="form-group" style="grid-column:1/-1"><label>Upload App Icon</label><input type="file" name="iconFile" accept="image/*">${isEditing && editApk.iconUrl ? `<br><small style="color:green">Current icon active — leave empty to keep it.</small>` : ""}</div>
    <div class="form-group" style="grid-column:1/-1"><label>Upload Feature Screenshots (max 10)</label><input type="file" name="screenshotFiles" accept="image/*" multiple></div>
    <div class="form-group" style="grid-column:1/-1"><label>Changelog / Description</label><textarea name="description" rows="3" maxlength="500">${isEditing ? escapeHtml(editApk.description || "") : ""}</textarea></div>
    <div style="grid-column:1/-1;display:flex;gap:10px"><button type="submit" id="submitBtn" class="btn ${isEditing ? "btn-blue" : "btn-green"}">${isEditing ? "Update APK Details" : "Publish APK"}</button>${isEditing ? '<a href="/apks" class="btn btn-gray">Cancel</a>' : ""}</div>`;
}

app.get("/apks", requireLogin, csrfProtection, async (req, res) => {
  try {
    const editId = safeString(req.query.edit, 100);
    let editApk = null;
    if (editId && mongoose.Types.ObjectId.isValid(editId)) editApk = await Apk.findById(editId).lean();

    const apks = await Apk.find().sort({ createdAt: -1 }).lean();
    let apkRows = apks.map((apk) => `
      <tr>
        <td><div style="display:flex;align-items:center;gap:10px">${apk.iconUrl ? `<img src="${escapeHtml(apk.iconUrl)}" style="width:36px;height:36px;border-radius:8px;object-fit:cover" alt="icon">` : '<div style="width:36px;height:36px;border-radius:8px;background:#e5e7eb"></div>'}<div><strong>${escapeHtml(apk.appName)}</strong><br><span class="status-line">${escapeHtml(apk.description)}</span></div></div></td>
        <td><span class="badge online">${escapeHtml(apk.versionName)}</span><br>Code: ${escapeHtml(apk.versionCode)}</td>
        <td><code>${escapeHtml(apk.packageName)}</code></td>
        <td><a href="${escapeHtml(apk.apkUrl)}" target="_blank" rel="noopener noreferrer" style="color:var(--blue);font-size:12px">Download</a><br><span class="status-line">${apk.apkSha256 ? "SHA-256 ✓" : "No file hash"}${apk.signatureSha256 ? " · Signer ✓" : " · No signer hash"}</span></td>
        <td>${safeDate(apk.createdAt)}</td>
        <td><div style="display:flex;gap:5px"><a href="/apks?edit=${escapeHtml(apk._id)}" class="btn btn-blue" style="padding:6px 10px">Edit</a><form class="inline-form" method="POST" action="/action/apk/delete" onsubmit="return confirm('Delete this APK from the store?')"><input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}"><input type="hidden" name="id" value="${escapeHtml(apk._id)}"><button class="btn btn-red" type="submit" style="padding:6px 10px">Delete</button></form></div></td>
      </tr>`).join("");
    if (!apkRows) apkRows = `<tr><td colspan="6" style="text-align:center;padding:25px">No APKs published yet.</td></tr>`;

    const isEditing = !!editApk;
    const formAction = isEditing ? "/action/apk/edit" : "/action/apk/add";
    const formTitle = isEditing ? `Edit APK: ${escapeHtml(editApk.appName)}` : "Publish New APK";

    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>APK Manager</title>${UI_STYLES}</head><body>${TOPBAR_HTML(res.locals.csrfToken)}<div class="container"><div class="page-title"><h1>APK Store Manager</h1><p class="status-line">Package + versionCode are authoritative. SHA-256 fields protect content/signing identity when supplied.</p></div>
      <div class="card"><div class="card-header">${formTitle}${isEditing ? '<a href="/apks" class="btn btn-gray" style="float:right;padding:3px 8px;font-size:11px">Cancel Edit</a>' : ""}</div><div class="card-body"><form id="apkForm" method="POST" action="${formAction}" enctype="multipart/form-data" style="display:grid;grid-template-columns:1fr 1fr;gap:15px">${apkFormFields(editApk, res.locals.csrfToken)}</form></div></div>
      <div class="card"><div class="card-header">Published Apps</div><div class="table-wrap"><table><thead><tr><th>App</th><th>Version</th><th>Package</th><th>APK</th><th>Published</th><th>Action</th></tr></thead><tbody>${apkRows}</tbody></table></div></div></div>
      <script>document.getElementById("apkForm").addEventListener("submit",function(){var b=document.getElementById("submitBtn");b.disabled=true;b.style.opacity=".7";b.style.cursor="not-allowed";b.innerHTML="⏳ Uploading... Please wait!";});</script>
    </body></html>`);
  } catch (err) {
    console.error("APK page error:", err.message);
    res.status(500).send("Error: " + escapeHtml(err.message));
  }
});

async function validateApkInput(body) {
  const appName = safeString(body.appName, MAX_APP_NAME_LENGTH);
  const packageName = safeString(body.packageName, MAX_PACKAGE_LENGTH);
  const versionName = safeString(body.versionName, MAX_VERSION_NAME_LENGTH);
  const apkUrl = safeString(body.apkUrl, MAX_URL_LENGTH);
  const description = safeString(body.description, MAX_DESCRIPTION_LENGTH);
  const versionCode = parsePositiveVersionCode(body.versionCode);
  const apkSha256 = normalizeSha256(body.apkSha256);
  const signatureSha256 = normalizeSha256(body.signatureSha256);

  if (!appName || !isValidPackageName(packageName) || !isValidVersionName(versionName) || !versionCode || !isValidHttpUrl(apkUrl)) {
    return { error: "Invalid APK metadata. Check app name, package, version, versionCode and HTTPS/HTTP APK URL." };
  }
  if (apkSha256 === null) return { error: "APK SHA-256 must be exactly 64 hexadecimal characters." };
  if (signatureSha256 === null) return { error: "Signing certificate SHA-256 must be exactly 64 hexadecimal characters." };

  return { appName, packageName, versionName, apkUrl, description, versionCode, apkSha256, signatureSha256 };
}

async function processMediaUploads(req, existingIconUrl, existingScreenshots) {
  let iconUrl = isValidHttpUrl(existingIconUrl) ? String(existingIconUrl).trim().substring(0, MAX_URL_LENGTH) : "";
  const screenshots = normalizeScreenshotUrls(existingScreenshots);

  if (req.files && req.files.iconFile && req.files.iconFile[0]) {
    iconUrl = await uploadToCloudinary(req.files.iconFile[0].buffer, "rd_store/icons");
  }
  if (req.files && req.files.screenshotFiles) {
    for (const file of req.files.screenshotFiles.slice(0, 10)) {
      if (screenshots.length >= 10) break;
      screenshots.push(await uploadToCloudinary(file.buffer, "rd_store/screenshots"));
    }
  }
  return { iconUrl, screenshots: normalizeScreenshotUrls(screenshots) };
}

app.post("/action/apk/add", requireLogin, adminActionLimiter, upload.fields([
  { name: "iconFile", maxCount: 1 },
  { name: "screenshotFiles", maxCount: 10 }
]), csrfProtection, async (req, res) => {
  try {
    const data = await validateApkInput(req.body);
    if (data.error) return res.status(400).send(escapeHtml(data.error));

    const duplicate = await Apk.findOne({ packageName: data.packageName, versionCode: data.versionCode }).select("_id").lean();
    if (duplicate) return res.status(409).send("This package + versionCode already exists. Edit the existing record instead.");

    const media = await processMediaUploads(req, "", []);
    await Apk.create({ ...data, ...media });
    return res.redirect("/apks");
  } catch (err) {
    console.error("Add APK Error:", err.message);
    return res.status(500).send("Add Failed: " + escapeHtml(err.message));
  }
});

app.post("/action/apk/edit", requireLogin, adminActionLimiter, upload.fields([
  { name: "iconFile", maxCount: 1 },
  { name: "screenshotFiles", maxCount: 10 }
]), csrfProtection, async (req, res) => {
  try {
    const id = getObjectId(req.body.id);
    if (!id) return res.status(400).send("Invalid APK ID.");

    const data = await validateApkInput(req.body);
    if (data.error) return res.status(400).send(escapeHtml(data.error));

    const duplicate = await Apk.findOne({ packageName: data.packageName, versionCode: data.versionCode, _id: { $ne: id } }).select("_id").lean();
    if (duplicate) return res.status(409).send("Another APK already uses this package + versionCode.");

    const existingScreenshots = parseExistingScreenshots(req.body.existingScreenshots);
    const media = await processMediaUploads(req, req.body.existingIconUrl || "", existingScreenshots);

    const updated = await Apk.findByIdAndUpdate(id, { $set: { ...data, ...media } }, { runValidators: true, new: true });
    if (!updated) return res.status(404).send("APK not found.");
    return res.redirect("/apks");
  } catch (err) {
    console.error("Edit APK Error:", err.message);
    if (err && err.code === 11000) return res.status(409).send("This package + versionCode already exists.");
    return res.status(500).send("Edit Failed: " + escapeHtml(err.message));
  }
});

app.post("/action/apk/delete", requireLogin, adminActionLimiter, csrfProtection, async (req, res) => {
  try {
    const id = getObjectId(req.body.id);
    if (id) await Apk.findByIdAndDelete(id);
  } catch (err) {
    console.error("Delete APK Error:", err.message);
  }
  res.redirect("/apks");
});

/* =========================================================
   DEVICE ACTIONS
========================================================= */
app.post("/action/device/:type", requireLogin, adminActionLimiter, csrfProtection, async (req, res) => {
  const type = String(req.params.type || "");
  const deviceId = safeString(req.body.deviceId, MAX_DEVICE_ID_LENGTH);
  const appId = safeString(req.body.appId, MAX_APP_ID_LENGTH);
  if (!deviceId && type !== "clear-all-history") return res.redirect("/");

  try {
    if (type === "nickname") {
      await Device.updateOne({ deviceId, appId }, { $set: { nickname: safeString(req.body.nickname, MAX_NICKNAME_LENGTH) } });
    }
    if (type === "approve") {
      await Device.updateOne({ deviceId, appId }, { $set: { status: "approved" } });
    }
    if (type === "pending") {
      await Device.updateOne({ deviceId, appId }, { $set: { status: "pending" } });
      await closeOnlineSession(deviceId, appId, "pending", Date.now());
    }
    if (type === "block") {
      await Device.updateOne({ deviceId, appId }, { $set: { status: "blocked" } });
      await closeOnlineSession(deviceId, appId, "blocked", Date.now());
    }
    if (type === "clear-history") await UsageSession.deleteMany({ deviceId, appId });
    if (type === "delete") {
      await Promise.all([Device.deleteOne({ deviceId, appId }), UsageSession.deleteMany({ deviceId, appId })]);
    }
    if (type === "clear-all-history") await UsageSession.deleteMany({});
  } catch (err) {
    console.error("Device Action Error:", err.message);
  }
  res.redirect("/");
});

/* =========================================================
   DASHBOARD API
========================================================= */
app.get("/api/sessions/:deviceId", requireApiLogin, async (req, res) => {
  try {
    const deviceId = safeString(req.params.deviceId, MAX_DEVICE_ID_LENGTH);
    const appId = safeString(req.query.appId, MAX_APP_ID_LENGTH);
    if (!deviceId || !appId) return res.status(400).json({ success: false });

    await markStaleSessionsOffline();
    const sessions = await UsageSession.find({ deviceId, appId }).sort({ startTimestamp: -1 }).limit(200).lean();
    const now = Date.now();
    const formatted = sessions.map((item) => {
      const start = Number(item.startTimestamp);
      let end = Number(item.endTimestamp || item.lastSeenTimestamp);
      if (item.status === "online") end = now;
      const duration = item.status === "offline" && Number(item.durationMs) > 0 ? Number(item.durationMs) : Math.max(0, end - start);
      return {
        startTime: safeDate(item.startTime),
        lastSeenTime: safeDate(item.lastSeenTime),
        endTime: item.endTime ? safeDate(item.endTime) : item.status === "online" ? "Active" : safeDate(item.lastSeenTime),
        duration: formatDuration(duration),
        durationMs: duration,
        status: item.status,
        endReason: item.endReason || "unknown"
      };
    });
    return res.json({ success: true, sessions: formatted });
  } catch (err) {
    console.error("Sessions API error:", err.message);
    return res.status(500).json({ success: false });
  }
});

app.get("/api/dashboard", requireApiLogin, async (req, res) => {
  try {
    await markStaleSessionsOffline();
    const search = safeString(req.query.search, MAX_SEARCH_LENGTH);
    const filter = ["all", "today", "7d", "30d"].includes(String(req.query.filter || "all")) ? String(req.query.filter || "all") : "all";
    const appFilter = safeString(req.query.appFilter, MAX_APP_ID_LENGTH) || "all";
    const requestedPage = Math.max(1, parseInt(req.query.page || "1", 10) || 1);
    const range = getRange(filter, "", "");
    const now = Date.now();
    const deviceMatch = {};

    if (appFilter !== "all") deviceMatch.appId = appFilter;
    if (search) {
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      deviceMatch.$or = [
        { deviceId: { $regex: escaped, $options: "i" } },
        { nickname: { $regex: escaped, $options: "i" } },
        { status: { $regex: escaped, $options: "i" } }
      ];
    }

    const effectiveEndExpression = {
      $cond: [
        { $eq: ["$status", "online"] },
        now,
        { $ifNull: ["$endTimestamp", "$lastSeenTimestamp"] }
      ]
    };
    const sessionMatch = range.from !== null
      ? {
          startTimestamp: { $lte: range.to },
          $or: [
            { endTimestamp: { $gte: range.from } },
            { endTimestamp: null, lastSeenTimestamp: { $gte: range.from } },
            { status: "online" }
          ]
        }
      : {};
    if (appFilter !== "all") sessionMatch.appId = appFilter;

    const durationStartExpression = range.from !== null ? { $max: ["$startTimestamp", range.from] } : "$startTimestamp";
    const durationEndExpression = range.from !== null ? { $min: [effectiveEndExpression, range.to] } : effectiveEndExpression;

    const usagePipeline = [
      { $match: sessionMatch },
      { $project: { deviceId: 1, appId: 1, durationStart: durationStartExpression, durationEnd: durationEndExpression } },
      { $project: { deviceId: 1, appId: 1, duration: { $max: [0, { $subtract: ["$durationEnd", "$durationStart"] }] } } },
      { $group: { _id: { deviceId: "$deviceId", appId: "$appId" }, totalUsage: { $sum: "$duration" }, sessionCount: { $sum: 1 } } }
    ];
    const chartPipeline = [
      { $match: sessionMatch },
      { $project: { day: { $dateToString: { format: "%Y-%m-%d", date: "$startTime", timezone: "Asia/Kolkata" } }, durationStart: durationStartExpression, durationEnd: durationEndExpression } },
      { $project: { day: 1, duration: { $max: [0, { $subtract: ["$durationEnd", "$durationStart"] }] } } },
      { $group: { _id: "$day", usage: { $sum: "$duration" } } },
      { $sort: { _id: 1 } }
    ];

    const onlineCutoff = now - ONLINE_TIMEOUT_MS;
    const skip = (requestedPage - 1) * DEVICES_PER_PAGE;
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
      const count = Number(item.count || 0);
      totalDevices += count;
      if (item._id === "approved") approved = count;
      if (item._id === "pending") pending = count;
      if (item._id === "blocked") blocked = count;
    });

    const usageMap = {};
    let totalUsage = 0;
    results[3].forEach((item) => {
      const usage = Number(item.totalUsage || 0);
      const key = `${item._id.deviceId}_${item._id.appId}`;
      usageMap[key] = { totalUsage: usage, sessionCount: Number(item.sessionCount || 0) };
      totalUsage += usage;
    });

    const onlineSet = new Set(results[5].map((item) => `${item.deviceId}_${item.appId}`));
    const totalPages = Math.max(1, Math.ceil(results[1] / DEVICES_PER_PAGE));
    const currentPage = Math.min(requestedPage, totalPages);
    let devices = results[2];
    if (currentPage !== requestedPage) {
      devices = await Device.find(deviceMatch).sort({ registeredAt: -1 }).skip((currentPage - 1) * DEVICES_PER_PAGE).limit(DEVICES_PER_PAGE).lean();
    }

    const deviceData = devices.map((device) => {
      const key = `${device.deviceId}_${device.appId}`;
      const stat = usageMap[key] || { totalUsage: 0, sessionCount: 0 };
      return {
        deviceId: device.deviceId,
        appId: device.appId,
        nickname: device.nickname || "",
        status: device.status,
        registeredAt: safeDate(device.registeredAt),
        usage: formatDuration(stat.totalUsage),
        sessions: stat.sessionCount,
        online: onlineSet.has(key)
      };
    });

    return res.json({
      success: true,
      stats: { totalDevices, approved, pending, blocked, online: onlineSet.size, totalUsage: formatDuration(totalUsage) },
      devices: deviceData,
      apps: results[6],
      pagination: { page: currentPage, totalPages, totalDevices: results[1] },
      chart: {
        labels: results[4].map((i) => i._id),
        data: results[4].map((i) => Math.round(Number(i.usage || 0) / 60000))
      }
    });
  } catch (err) {
    console.error("Dashboard API error:", err.message);
    return res.status(500).json({ success: false });
  }
});

/* =========================================================
   DASHBOARD PAGE
========================================================= */
app.get("/", requireLogin, csrfProtection, (req, res) => {
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Console V6.5.0</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>${UI_STYLES}</head><body>${TOPBAR_HTML(res.locals.csrfToken)}<div class="container">
  <div class="page-title"><h1>Device Management</h1><p id="refreshStatus" class="status-line">Loading dashboard...</p></div>
  <div class="card"><div class="card-body"><form id="filterForm" class="filters"><input id="search" class="search" placeholder="Search device ID or nickname"><select id="appFilter"><option value="all">All Apps</option></select><select id="filter"><option value="all">All Time</option><option value="today">Today (IST)</option><option value="7d">Last 7 Days</option><option value="30d">Last 30 Days</option></select><button class="btn btn-blue" type="submit">Apply Filter</button><button type="button" class="btn btn-gray" onclick="manualRefresh()">Refresh</button></form>
  <div style="margin-top:12px"><form method="POST" action="/action/device/clear-all-history" onsubmit="return confirm('WARNING: Permanently delete ALL session history for ALL apps?')"><input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}"><button type="submit" class="btn btn-red">Clear All History</button></form></div></div></div>
  <div class="stats"><div class="stat"><div class="stat-label">TOTAL DEVICES</div><div class="stat-value" id="totalDevices">-</div></div><div class="stat"><div class="stat-label">APPROVED</div><div class="stat-value" id="approved">-</div></div><div class="stat"><div class="stat-label">PENDING</div><div class="stat-value" id="pending">-</div></div><div class="stat"><div class="stat-label">BLOCKED</div><div class="stat-value" id="blocked">-</div></div><div class="stat"><div class="stat-label">ONLINE NOW</div><div class="stat-value" id="online">-</div></div><div class="stat"><div class="stat-label">TOTAL USAGE</div><div class="stat-value" id="totalUsage">-</div></div></div>
  <div class="card"><div class="card-header">Usage Trend</div><div class="card-body"><div style="height:310px"><canvas id="usageChart"></canvas></div></div></div>
  <div class="card"><div class="card-header">Device Permissions</div><div class="table-wrap"><table><thead><tr><th>Nickname</th><th>Device ID & App</th><th>Permission</th><th>Live Status</th><th>Usage</th><th>Registered</th><th>Actions</th></tr></thead><tbody id="deviceTable"><tr><td colspan="7" style="text-align:center;padding:25px">Loading devices...</td></tr></tbody></table></div><div class="pagination"><button id="prevPage">Previous</button><span id="pageInfo">Page -</span><button id="nextPage">Next</button></div></div>
  <div class="modal-overlay" id="historyModal"><div class="modal"><div class="modal-header"><div id="modalTitle">Session History</div><button class="modal-close" onclick="closeModal()">×</button></div><div class="modal-body"><div class="table-wrap"><table><thead><tr><th>Started</th><th>Last Seen</th><th>Ended</th><th>Duration</th><th>Status</th><th>Reason</th></tr></thead><tbody id="historyTableBody"><tr><td colspan="6" style="text-align:center">Loading...</td></tr></tbody></table></div></div></div></div>
</div>
<script>
const csrfToken="${escapeHtml(res.locals.csrfToken)}";const REFRESH_SECONDS=${DASHBOARD_REFRESH_SECONDS};let currentPage=1;let chartInstance=null;let refreshTimer=null;let refreshInProgress=false;const refreshStatus=document.getElementById("refreshStatus");
function escapeHTML(value){return String(value??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;");}
async function refreshDashboard(){if(refreshInProgress)return;refreshInProgress=true;clearTimeout(refreshTimer);try{refreshStatus.textContent="Refreshing data...";const params=new URLSearchParams();params.set("search",document.getElementById("search").value);params.set("filter",document.getElementById("filter").value);params.set("appFilter",document.getElementById("appFilter").value);params.set("page",currentPage);const response=await fetch("/api/dashboard?"+params.toString(),{credentials:"same-origin",cache:"no-store"});if(response.status===401){window.location.href="/login";return;}if(!response.ok)throw new Error("HTTP "+response.status);const data=await response.json();if(!data.success)throw new Error("API error");updateAppDropdown(data.apps);updateStats(data.stats);updateTable(data.devices);updatePagination(data.pagination);if(chartInstance)chartInstance.destroy();chartInstance=new Chart(document.getElementById("usageChart"),{type:"line",data:{labels:data.chart.labels,datasets:[{label:"Usage (mins)",data:data.chart.data,borderColor:"#2563eb",backgroundColor:"rgba(37,99,235,.08)",borderWidth:2,fill:true}]},options:{responsive:true,maintainAspectRatio:false,scales:{y:{beginAtZero:true}}}});refreshStatus.textContent="Last refreshed: "+new Date().toLocaleTimeString("en-IN");}catch(error){console.error(error);refreshStatus.textContent="Unable to refresh.";}finally{refreshInProgress=false;scheduleRefresh();}}
function manualRefresh(){refreshDashboard();}
function updateAppDropdown(apps){const s=document.getElementById("appFilter");const v=s.value;s.innerHTML='<option value="all">All Apps</option>';(apps||[]).forEach(function(app){if(app&&app.appId){const o=document.createElement("option");o.value=app.appId;o.textContent=app.appName+" ("+app.appId+")";if(app.appId===v)o.selected=true;s.appendChild(o);}});}
function updateStats(stats){document.getElementById("totalDevices").textContent=stats.totalDevices;document.getElementById("approved").textContent=stats.approved;document.getElementById("pending").textContent=stats.pending;document.getElementById("blocked").textContent=stats.blocked;document.getElementById("online").textContent=stats.online;document.getElementById("totalUsage").textContent=stats.totalUsage;}
function updateTable(devices){const tbody=document.getElementById("deviceTable");if(!devices.length){tbody.innerHTML='<tr><td colspan="7" style="text-align:center;padding:25px">No devices found.</td></tr>';return;}tbody.innerHTML=devices.map(function(device){const deviceId=escapeHTML(device.deviceId);const appId=escapeHTML(device.appId);const nickname=escapeHTML(device.nickname);const status=escapeHTML(device.status);const liveClass=device.online?"online":"offline";const liveText=device.online?"ONLINE":"OFFLINE";let actions='<button type="button" class="btn btn-purple" data-history="'+deviceId+'" data-app="'+appId+'">History</button>';actions+='<form class="inline-form" method="POST" action="/action/device/clear-history"><input type="hidden" name="_csrf" value="'+csrfToken+'"><input type="hidden" name="deviceId" value="'+deviceId+'"><input type="hidden" name="appId" value="'+appId+'"><button class="btn btn-red" type="submit">Clear History</button></form>';if(device.status!=="approved")actions+='<form class="inline-form" method="POST" action="/action/device/approve"><input type="hidden" name="_csrf" value="'+csrfToken+'"><input type="hidden" name="deviceId" value="'+deviceId+'"><input type="hidden" name="appId" value="'+appId+'"><button class="btn btn-green" type="submit">Approve</button></form>';if(device.status!=="blocked")actions+='<form class="inline-form" method="POST" action="/action/device/block"><input type="hidden" name="_csrf" value="'+csrfToken+'"><input type="hidden" name="deviceId" value="'+deviceId+'"><input type="hidden" name="appId" value="'+appId+'"><button class="btn btn-orange" type="submit">Block</button></form>';if(device.status!=="pending")actions+='<form class="inline-form" method="POST" action="/action/device/pending"><input type="hidden" name="_csrf" value="'+csrfToken+'"><input type="hidden" name="deviceId" value="'+deviceId+'"><input type="hidden" name="appId" value="'+appId+'"><button class="btn btn-yellow" type="submit">Pending</button></form>';actions+='<form class="inline-form" method="POST" action="/action/device/delete" onsubmit="return confirm(&quot;Delete device and its history?&quot;)"><input type="hidden" name="_csrf" value="'+csrfToken+'"><input type="hidden" name="deviceId" value="'+deviceId+'"><input type="hidden" name="appId" value="'+appId+'"><button class="btn btn-red" type="submit">Delete Device</button></form>';return '<tr><td><form class="inline-form" method="POST" action="/action/device/nickname"><input type="hidden" name="_csrf" value="'+csrfToken+'"><input type="hidden" name="deviceId" value="'+deviceId+'"><input type="hidden" name="appId" value="'+appId+'"><input class="nickname-input" name="nickname" maxlength="50" placeholder="Nickname" value="'+nickname+'"><button class="btn btn-blue" type="submit">Save</button></form></td><td><code>'+deviceId+'</code><br><span class="badge badge-app">'+appId+'</span></td><td><span class="badge '+status+'">'+status.toUpperCase()+'</span></td><td><span class="badge '+liveClass+'">'+liveText+'</span></td><td><strong>'+escapeHTML(device.usage)+'</strong><br><span style="font-size:11px;color:#6b7280">'+Number(device.sessions)+' sessions</span></td><td>'+escapeHTML(device.registeredAt)+'</td><td class="action-cell">'+actions+'</td></tr>';}).join("");document.querySelectorAll("[data-history]").forEach(function(btn){btn.addEventListener("click",function(){openHistory(btn.getAttribute("data-history"),btn.getAttribute("data-app"));});});}
async function openHistory(deviceId,appId){const modal=document.getElementById("historyModal");const title=document.getElementById("modalTitle");const body=document.getElementById("historyTableBody");title.textContent="History — "+deviceId+" ("+appId+")";body.innerHTML='<tr><td colspan="6" style="text-align:center">Loading...</td></tr>';modal.style.display="flex";try{const response=await fetch("/api/sessions/"+encodeURIComponent(deviceId)+"?appId="+encodeURIComponent(appId),{credentials:"same-origin",cache:"no-store"});if(response.status===401){window.location.href="/login";return;}if(!response.ok)throw new Error("HTTP "+response.status);const data=await response.json();if(!data.success||!data.sessions.length){body.innerHTML='<tr><td colspan="6" style="text-align:center">No session history available.</td></tr>';return;}body.innerHTML=data.sessions.map(function(item){const statusClass=item.status==="online"?"online":"offline";return '<tr><td>'+escapeHTML(item.startTime)+'</td><td>'+escapeHTML(item.lastSeenTime)+'</td><td>'+escapeHTML(item.endTime)+'</td><td><strong>'+escapeHTML(item.duration)+'</strong></td><td><span class="badge '+statusClass+'">'+escapeHTML(String(item.status).toUpperCase())+'</span></td><td>'+escapeHTML(item.endReason)+'</td></tr>';}).join("");}catch(error){body.innerHTML='<tr><td colspan="6" style="text-align:center;color:#b91c1c">Failed to load session history.</td></tr>';}}
function closeModal(){document.getElementById("historyModal").style.display="none";}window.addEventListener("click",function(event){if(event.target===document.getElementById("historyModal"))closeModal();});
function updatePagination(p){currentPage=p.page;document.getElementById("pageInfo").textContent="Page "+p.page+" of "+p.totalPages;document.getElementById("prevPage").disabled=p.page<=1;document.getElementById("nextPage").disabled=p.page>=p.totalPages;}
function scheduleRefresh(){clearTimeout(refreshTimer);if(!document.hidden)refreshTimer=setTimeout(refreshDashboard,REFRESH_SECONDS*1000);}document.getElementById("filterForm").addEventListener("submit",function(event){event.preventDefault();currentPage=1;refreshDashboard();});document.getElementById("prevPage").addEventListener("click",function(){if(currentPage>1){currentPage--;refreshDashboard();}});document.getElementById("nextPage").addEventListener("click",function(){currentPage++;refreshDashboard();});document.addEventListener("visibilitychange",function(){if(document.hidden)clearTimeout(refreshTimer);else refreshDashboard();});refreshDashboard();
</script></body></html>`);
});

/* =========================================================
   ERROR / 404 HANDLERS
========================================================= */
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    console.error("Upload error:", err.code, err.message);
    return res.status(400).send("Upload failed: " + escapeHtml(err.message));
  }
  if (err) {
    console.error("Unhandled request error:", err.stack || err.message || err);
    return res.status(500).send("Internal server error.");
  }
  next();
});
app.use((req, res) => res.status(404).send("404 Not Found"));

/* =========================================================
   SHUTDOWN / STARTUP
========================================================= */
let server = null;
let shuttingDown = false;

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(signal + " received. Shutting down...");
  clearInterval(cleanupInterval);
  try {
    if (server) await new Promise((resolve) => server.close(resolve));
    await mongoose.disconnect();
    console.log("Shutdown complete.");
    process.exit(0);
  } catch (err) {
    console.error("Shutdown error:", err.message);
    process.exit(1);
  }
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

async function startServer() {
  try {
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000
    });
    console.log("MongoDB connected.");

    try {
      await Device.updateMany({ appId: { $exists: false } }, { $set: { appId: "default_app" } });
      await UsageSession.updateMany({ appId: { $exists: false } }, { $set: { appId: "default_app" } });

      const distinctAppIds = await Device.distinct("appId");
      for (const appId of distinctAppIds) {
        if (!appId) continue;
        await AppRegistry.updateOne(
          { appId },
          { $setOnInsert: { appId, appName: appId } },
          { upsert: true }
        ).catch((err) => console.error("App registry backfill error:", err.message));
        knownApps.add(appId);
      }
    } catch (err) {
      console.error("Backfill error:", err.message);
    }

    try {
      console.log("Syncing database indexes...");
      await Device.syncIndexes();
      await UsageSession.syncIndexes();
      await Apk.syncIndexes();
      await AppRegistry.syncIndexes();
      console.log("Indexes synced perfectly!");
    } catch (err) {
      console.error("Index sync error:", err.message);
    }

    server = app.listen(PORT, () => {
      console.log("V6.5.0 Production Edition running on port " + PORT);
    });
  } catch (err) {
    console.error("FATAL startup error:", err.message);
    process.exit(1);
  }
}

startServer();
