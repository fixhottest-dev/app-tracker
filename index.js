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
   V6.4.5 PRODUCTION EDITION (WITH CLOUDINARY FILE UPLOAD)
========================================================= */

const PORT = Number(process.env.PORT || 3000);
const MONGO_URI = process.env.MONGO_URI;
const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || "admin");
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PRODUCTION = NODE_ENV === "production";
const SESSION_SECRET = process.env.SESSION_SECRET || (!IS_PRODUCTION ? crypto.randomBytes(48).toString("hex") : "");
const REDIRECT_URL = process.env.REDIRECT_URL || "https://wa.me/918099188409?text=Hello%20Developer,%20please%20activate%20my%20app";

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const upload = multer({ storage: multer.memoryStorage() });

function uploadToCloudinary(buffer, folderName = "rd_store") {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder: folderName, resource_type: "auto" },
      (error, result) => {
        if (error) return reject(error);
        resolve(result.secure_url);
      }
    );
    streamifier.createReadStream(buffer).pipe(uploadStream);
  });
}

const ONLINE_TIMEOUT_MS = Number(process.env.ONLINE_TIMEOUT_MS || 45000);
const CLEANUP_INTERVAL_MS = Number(process.env.CLEANUP_INTERVAL_MS || 15000);
const DASHBOARD_REFRESH_SECONDS = 15;
const DEVICES_PER_PAGE = 20;

const MAX_DEVICE_ID_LENGTH = 200;
const MAX_NICKNAME_LENGTH = 50;
const MAX_SEARCH_LENGTH = 100;
const MAX_APP_ID_LENGTH = 200;
const ADMIN_SESSION_MAX_AGE = 24 * 60 * 60 * 1000;

if (!MONGO_URI) { console.error("FATAL: MONGO_URI is missing."); process.exit(1); }
if (!ADMIN_PASSWORD && !ADMIN_PASSWORD_HASH) { console.error("FATAL: ADMIN_PASSWORD or ADMIN_PASSWORD_HASH is required."); process.exit(1); }
if (IS_PRODUCTION && !SESSION_SECRET) { console.error("FATAL: SESSION_SECRET is required in production."); process.exit(1); }

app.set("trust proxy", 1);
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
  next();
});

app.use(
  session({
    name: "admin.sid",
    secret: SESSION_SECRET,
    resave: false, saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGO_URI, collectionName: "admin_sessions", ttl: ADMIN_SESSION_MAX_AGE / 1000, autoRemove: "native" }),
    cookie: { httpOnly: true, secure: IS_PRODUCTION, sameSite: "lax", maxAge: ADMIN_SESSION_MAX_AGE }
  })
);

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: "Too many login attempts." });
const trackingLimiter = rateLimit({ windowMs: 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false, message: { status: "ERROR", message: "RATE_LIMITED" } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });

/* =========================================================
   DATABASE SCHEMAS
========================================================= */

const AppRegistrySchema = new mongoose.Schema({
  appId: { type: String, required: true, unique: true, index: true, trim: true, maxlength: MAX_APP_ID_LENGTH },
  appName: { type: String, required: true, trim: true, maxlength: 100 },
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
  appName: { type: String, required: true, trim: true, maxlength: 100 },
  description: { type: String, default: "", trim: true, maxlength: 500 },
  versionName: { type: String, required: true, trim: true, maxlength: 50 },
  versionCode: { type: Number, required: true, index: true },
  packageName: { type: String, required: true, trim: true, maxlength: 200, index: true },
  apkUrl: { type: String, required: true, trim: true, maxlength: 500 },
  iconUrl: { type: String, default: "", trim: true, maxlength: 500 },
  screenshots: { type: [String], default: [] },
  createdAt: { type: Date, default: Date.now, index: true }
}, { versionKey: false });

const AppRegistry = mongoose.model("AppRegistry", AppRegistrySchema);
const Device = mongoose.model("Device", DeviceSchema);
const UsageSession = mongoose.model("UsageSession", SessionSchema);
const Apk = mongoose.model("Apk", ApkSchema);

/* =========================================================
   HELPERS
========================================================= */
function escapeHtml(value) { return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;"); }
function safeString(value, maxLength) { return String(value || "").trim().substring(0, maxLength); }

/* =========================================================
   AUTH & CSRF
========================================================= */
function csrfProtection(req, res, next) {
  if (!req.session) return res.status(500).send("Session unavailable.");
  const method = req.method.toUpperCase();
  const protectedMethod = method === "POST" || method === "PUT" || method === "PATCH" || method === "DELETE";
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  res.locals.csrfToken = req.session.csrfToken;
  if (protectedMethod) {
    const token = req.body?._csrf || req.get("x-csrf-token");
    if (!token || token !== req.session.csrfToken) return res.status(403).send("CSRF validation failed.");
  }
  next();
}
function requireLogin(req, res, next) { if (req.session && req.session.adminAuthenticated === true) return next(); return res.redirect("/login"); }
function requireApiLogin(req, res, next) { if (req.session && req.session.adminAuthenticated === true) return next(); return res.status(401).json({ success: false, error: "UNAUTHORIZED" }); }
async function verifyPassword(password) {
  if (ADMIN_PASSWORD_HASH) return bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!ADMIN_PASSWORD) return false;
  const input = Buffer.from(String(password)); const stored = Buffer.from(ADMIN_PASSWORD);
  if (input.length !== stored.length) return false; return crypto.timingSafeEqual(input, stored);
}

/* =========================================================
   SESSION CLEANUP
========================================================= */
async function closeOnlineSession(deviceId, appId, reason, timestamp) {
  const now = Number(timestamp) || Date.now(); const nowDate = new Date(now);
  const sessionDoc = await UsageSession.findOneAndUpdate({ deviceId, appId, status: "online" }, { $set: { status: "offline", endReason: reason, endTime: nowDate, endTimestamp: now, lastSeenTime: nowDate, lastSeenTimestamp: now } }, { new: true, sort: { startTimestamp: -1 } });
  if (!sessionDoc) return null;
  const duration = Math.max(0, now - Number(sessionDoc.startTimestamp));
  await UsageSession.updateOne({ _id: sessionDoc._id }, { $set: { durationMs: duration } });
  return sessionDoc;
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
  } catch (err) {} finally { cleanupRunning = false; }
}
const cleanupInterval = setInterval(markStaleSessionsOffline, CLEANUP_INTERVAL_MS);
cleanupInterval.unref();

/* =========================================================
   TRACKING API
========================================================= */
async function handleTracking(req, res) {
  const deviceId = safeString(req.query.id || req.body?.id, MAX_DEVICE_ID_LENGTH);
  const appId = safeString(req.query.appId || req.body?.appId, MAX_APP_ID_LENGTH) || "default_app";
  let rawAction = String(req.query.action || req.body?.action || req.query.status || req.body?.status || "start").trim().toLowerCase();
  
  if (rawAction === "offline") rawAction = "stop";
  const action = ["start", "ping", "stop"].includes(rawAction) ? rawAction : "start";

  if (!deviceId) return res.status(400).json({ status: "ERROR", message: "DEVICE_ID_MISSING" });
  if (mongoose.connection.readyState !== 1) return res.status(503).json({ status: "ERROR", message: "DATABASE_OFFLINE" });

  try {
    await AppRegistry.updateOne({ appId }, { $setOnInsert: { appId, appName: appId } }, { upsert: true }).catch(() => {});

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
      if (err && err.code === 11000) { activeSession = await UsageSession.findOneAndUpdate({ deviceId, appId, status: "online" }, { $set: { lastSeenTime: nowDate, lastSeenTimestamp: now } }, { new: true }); } 
      else { throw err; }
    }
    return res.json({ status: "ALLOWED", action: "STARTED", sessionId: activeSession ? String(activeSession._id) : null });
  } catch (err) { return res.status(500).json({ status: "ERROR", message: "TRACKING_FAILED" }); }
}

app.get(["/track", "/index.php"], trackingLimiter, handleTracking);
app.post(["/track", "/index.php"], trackingLimiter, handleTracking);

app.get("/api/updates", apiLimiter, async (req, res) => {
  try { 
    const apks = await Apk.find().sort({ createdAt: -1 }).select("-_id -createdAt").lean(); 
    return res.status(200).json(apks); 
  } catch (err) { return res.status(500).json({ error: "Failed to fetch updates" }); }
});

/* =========================================================
   UI & HTML COMPONENTS
========================================================= */
const UI_STYLES = `
<style>
:root{--bg:#f5f6f8;--border:#e5e7eb;--text:#111827;--blue:#2563eb;} *{box-sizing:border-box;font-family:Inter,system-ui,sans-serif;} body{margin:0;background:var(--bg);color:var(--text);}
.topbar{height:64px;background:#111827;color:white;display:flex;align-items:center;justify-content:space-between;padding:0 24px;} .brand{font-size:17px;font-weight:700;} .brand span{color:#9ca3af;font-weight:400;margin-left:8px;font-size:13px;}
.container{max-width:1500px;margin:auto;padding:24px;} .page-title{margin-bottom:20px;} .page-title h1{font-size:24px;margin:0 0 4px;} .status-line{font-size:12px;color:#6b7280;}
.card{background:white;border:1px solid var(--border);border-radius:10px;margin-bottom:18px;} .card-header{padding:16px 18px;border-bottom:1px solid var(--border);font-weight:650;font-size:14px;} .card-body{padding:18px;}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:18px;} .stat{background:white;border:1px solid var(--border);border-radius:10px;padding:18px;} .stat-label{font-size:12px;color:#6b7280;margin-bottom:8px;} .stat-value{font-size:25px;font-weight:700;}
.filters{display:flex;flex-wrap:wrap;gap:10px;align-items:center;} input,select,textarea{padding:9px 11px;border:1px solid #d1d5db;border-radius:7px;font-size:13px;background:white;} .search{min-width:260px;}
.btn{border:0;border-radius:7px;padding:9px 12px;font-size:12px;font-weight:600;cursor:pointer;color:white;display:inline-flex;align-items:center;justify-content:center;gap:5px;text-decoration:none;}
.btn-dark{background:#111827;} .btn-blue{background:#2563eb;} .btn-green{background:#15803d;} .btn-orange{background:#ea580c;} .btn-yellow{background:#a16207;} .btn-red{background:#b91c1c;} .btn-purple{background:#6d28d9;} .btn-gray{background:#e5e7eb;color:#111827;} .btn:hover{opacity:.9;}
.table-wrap{overflow-x:auto;} table{width:100%;border-collapse:collapse;min-width:900px;} th{background:#f9fafb;color:#6b7280;font-size:11px;text-transform:uppercase;} th,td{padding:13px;border-bottom:1px solid var(--border);text-align:left;font-size:13px;} code{font-size:11px;background:#f3f4f6;padding:4px 6px;border-radius:4px;word-break:break-all;}
.badge{display:inline-block;padding:5px 8px;border-radius:20px;font-size:10px;font-weight:700;} .badge-app{background:#e0e7ff;color:#4338ca;font-size:10px;margin-top:4px;}
.approved,.online{background:#dcfce7;color:#166534;} .pending{background:#fef3c7;color:#92400e;} .blocked,.offline{background:#fee2e2;color:#991b1b;}
.action-cell{display:flex;gap:5px;flex-wrap:wrap;min-width:430px;} .inline-form{margin:0;display:inline-flex;gap:5px;} .nickname-input{width:125px;padding:7px;font-size:12px;}
.form-group{margin-bottom:15px;} .form-group label{display:block;font-size:13px;font-weight:600;margin-bottom:6px;} .form-group input,.form-group textarea{width:100%;}
.pagination{display:flex;gap:12px;align-items:center;padding:15px;justify-content:center;} .pagination button{padding:8px 14px;border:1px solid #ddd;border-radius:6px;cursor:pointer;}
</style>
`;

const TOPBAR_HTML = (csrfToken) => `
<div class="topbar">
  <div class="brand">Admin Console<span>V6.4.5 Production Edition</span></div>
  <div style="display:flex;gap:8px;align-items:center;">
    <a href="/" class="btn btn-blue">Devices</a>
    <a href="/apps" class="btn btn-orange">App Systems</a>
    <a href="/apks" class="btn btn-purple">APK Manager</a>
    <form method="POST" action="/logout" style="margin:0"><input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}"><button class="btn btn-gray" type="submit">Logout</button></form>
  </div>
</div>
`;

/* =========================================================
   ROUTES & PAGES
========================================================= */

app.get("/login", csrfProtection, (req, res) => {
  if (req.session && req.session.adminAuthenticated) return res.redirect("/");
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Login</title>${UI_STYLES}</head>
    <body style="display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;"><div class="card" style="width:100%;max-width:420px;margin:auto;"><h1>Login</h1>
    ${req.query.error ? '<div style="color:red;margin-bottom:10px;font-size:13px;">Invalid username/password</div>' : ""}
    <form method="POST" action="/login"><input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}"><div class="form-group"><label>Username</label><input type="text" name="username" required></div><div class="form-group"><label>Password</label><input type="password" name="password" required></div><button class="btn btn-dark" style="width:100%" type="submit">Sign In</button></form></div></body></html>`);
});
app.post("/login", loginLimiter, csrfProtection, async (req, res) => {
  try {
    const username = safeString(req.body.username, 100); const password = String(req.body.password || "");
    if (username !== ADMIN_USERNAME) return res.redirect("/login?error=1");
    if (!(await verifyPassword(password))) return res.redirect("/login?error=1");
    req.session.regenerate((err) => {
      if (err) return res.redirect("/login?error=1");
      req.session.adminAuthenticated = true; req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      req.session.save((saveErr) => res.redirect(saveErr ? "/login?error=1" : "/"));
    });
  } catch (err) { res.redirect("/login?error=1"); }
});
app.post("/logout", requireLogin, csrfProtection, (req, res) => { req.session.destroy(() => { res.clearCookie("admin.sid"); res.redirect("/login"); }); });

/* =========================================================
   APP MANAGER
========================================================= */
app.get("/apps", requireLogin, csrfProtection, async (req, res) => {
  try {
    const apps = await AppRegistry.find().sort({ createdAt: -1 }).lean();
    const deviceCounts = await Device.aggregate([{ $group: { _id: "$appId", count: { $sum: 1 } } }]);
    const countMap = {}; deviceCounts.forEach(d => countMap[d._id] = d.count);

    let rows = apps.map(app => `
      <tr>
        <td>
          <form class="inline-form" method="POST" action="/action/app-registry/edit">
            <input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}">
            <input type="hidden" name="id" value="${app._id}">
            <input type="hidden" name="oldAppId" value="${escapeHtml(app.appId)}">
            <input type="text" name="appName" value="${escapeHtml(app.appName)}" required placeholder="Display Name">
            <input type="text" name="newAppId" value="${escapeHtml(app.appId)}" required placeholder="Package (com.xyz)">
            <button class="btn btn-blue" type="submit">Save</button>
          </form>
        </td>
        <td><strong>${countMap[app.appId] || 0}</strong> Devices</td>
        <td>
          <form class="inline-form" method="POST" action="/action/app-registry/delete" onsubmit="return confirm('DANGER: This will delete the app AND wipe ALL tracking history, users, and data for this app. Continue?')">
            <input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}">
            <input type="hidden" name="id" value="${app._id}">
            <input type="hidden" name="appId" value="${escapeHtml(app.appId)}">
            <button class="btn btn-red" type="submit">Wipe Entire System</button>
          </form>
        </td>
      </tr>
    `).join("");

    if (!rows) rows = `<tr><td colspan="3" style="text-align:center;padding:25px;">No App Systems found.</td></tr>`;

    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>App Systems</title>${UI_STYLES}</head>
      <body>${TOPBAR_HTML(res.locals.csrfToken)}<div class="container">
      <div class="page-title"><h1>App Systems Management</h1><p class="status-line">Create workspaces or packages to isolate tracking data.</p></div>
      <div class="card"><div class="card-header">Register New App Package</div><div class="card-body">
        <form method="POST" action="/action/app-registry/add" style="display:flex;gap:15px;align-items:flex-end;">
          <input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}">
          <div style="flex:1"><label style="font-size:12px;font-weight:bold;margin-bottom:5px;display:block;">Display Name</label><input type="text" name="appName" required placeholder="My Awesome Mod"></div>
          <div style="flex:1"><label style="font-size:12px;font-weight:bold;margin-bottom:5px;display:block;">Package Name (App ID)</label><input type="text" name="appId" required placeholder="com.myawesome.mod"></div>
          <button type="submit" class="btn btn-green" style="height:37px;padding:0 20px;">Add System</button>
        </form>
      </div></div>
      <div class="card"><div class="card-header">Existing Systems</div><div class="table-wrap">
        <table style="min-width:600px;"><thead><tr><th>Rename & Edit Package</th><th>Registered Devices</th><th>Danger Zone</th></tr></thead><tbody>${rows}</tbody></table>
      </div></div></div></body></html>`);
  } catch (err) { res.status(500).send("Error loading apps"); }
});

app.post("/action/app-registry/add", requireLogin, csrfProtection, async (req, res) => {
  try {
    const appId = safeString(req.body.appId, MAX_APP_ID_LENGTH); const appName = safeString(req.body.appName, 100);
    if (appId && appName) await AppRegistry.create({ appId, appName });
  } catch (err) {}
  res.redirect("/apps");
});

app.post("/action/app-registry/edit", requireLogin, csrfProtection, async (req, res) => {
  try {
    const { id, oldAppId } = req.body;
    const newAppId = safeString(req.body.newAppId, MAX_APP_ID_LENGTH); const appName = safeString(req.body.appName, 100);
    if (mongoose.Types.ObjectId.isValid(id) && newAppId) {
      await AppRegistry.findByIdAndUpdate(id, { appId: newAppId, appName });
      if (oldAppId !== newAppId) {
        await Device.updateMany({ appId: oldAppId }, { $set: { appId: newAppId } });
        await UsageSession.updateMany({ appId: oldAppId }, { $set: { appId: newAppId } });
      }
    }
  } catch (err) {} res.redirect("/apps");
});

app.post("/action/app-registry/delete", requireLogin, csrfProtection, async (req, res) => {
  try {
    const { id, appId } = req.body;
    if (mongoose.Types.ObjectId.isValid(id)) {
      await AppRegistry.findByIdAndDelete(id);
      await Device.deleteMany({ appId });
      await UsageSession.deleteMany({ appId });
    }
  } catch (err) {} res.redirect("/apps");
});

/* =========================================================
   APK MANAGER (WITH FILE UPLOAD FORM)
========================================================= */
app.get("/apks", requireLogin, csrfProtection, async (req, res) => {
  try {
    const editId = req.query.edit || null;
    let editApk = null;
    if (editId && mongoose.Types.ObjectId.isValid(editId)) {
      editApk = await Apk.findById(editId).lean();
    }

    const apks = await Apk.find().sort({ createdAt: -1 }).lean();
    let apkRows = apks.map((apk) => `
      <tr>
        <td>
          <div style="display:flex;align-items:center;gap:10px;">
            ${apk.iconUrl ? `<img src="${escapeHtml(apk.iconUrl)}" style="width:36px;height:36px;border-radius:8px;object-fit:cover;" alt="icon">` : '<div style="width:36px;height:36px;border-radius:8px;background:#e5e7eb;"></div>'}
            <div><strong>${escapeHtml(apk.appName)}</strong><br><span class="status-line">${escapeHtml(apk.description)}</span></div>
          </div>
        </td>
        <td><span class="badge online">${escapeHtml(apk.versionName)}</span><br>Code: ${escapeHtml(apk.versionCode)}</td>
        <td><code>${escapeHtml(apk.packageName)}</code></td>
        <td><a href="${escapeHtml(apk.apkUrl)}" target="_blank" rel="noopener" style="color:var(--blue);font-size:12px;">Download</a></td>
        <td>${safeDate(apk.createdAt)}</td>
        <td>
          <div style="display:flex;gap:5px;">
            <a href="/apks?edit=${apk._id}" class="btn btn-blue" style="padding:6px 10px;">Edit</a>
            <form class="inline-form" method="POST" action="/action/apk/delete" onsubmit="return confirm('Delete this APK from the store?')">
              <input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}">
              <input type="hidden" name="id" value="${escapeHtml(apk._id)}">
              <button class="btn btn-red" type="submit" style="padding:6px 10px;">Delete</button>
            </form>
          </div>
        </td>
      </tr>
    `).join("");

    if (!apkRows) apkRows = `<tr><td colspan="6" style="text-align:center;padding:25px;">No APKs published yet.</td></tr>`;
    
    const isEditing = !!editApk;
    const formAction = isEditing ? `/action/apk/edit` : `/action/apk/add`;
    const formTitle = isEditing ? `Edit APK: ${escapeHtml(editApk.appName)}` : `Publish New APK`;
    const submitBtnText = isEditing ? `Update APK Details` : `Publish APK`;

    return res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>APK Manager</title>${UI_STYLES}</head>
      <body>${TOPBAR_HTML(res.locals.csrfToken)}<div class="container"><div class="page-title"><h1>APK Store Manager</h1></div>
      <div class="card"><div class="card-header">${formTitle} ${isEditing ? '<a href="/apks" class="btn btn-gray" style="float:right;padding:3px 8px;font-size:11px;">Cancel Edit</a>' : ''}</div><div class="card-body">
      <form method="POST" action="${formAction}" enctype="multipart/form-data" style="display:grid;grid-template-columns:1fr 1fr;gap:15px;">
        <input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}">
        ${isEditing ? `<input type="hidden" name="id" value="${editApk._id}"><input type="hidden" name="existingIconUrl" value="${escapeHtml(editApk.iconUrl || "")}"><input type="hidden" name="existingScreenshots" value="${escapeHtml(JSON.stringify(editApk.screenshots || []))}">` : ""}
        <div class="form-group"><label>App Name</label><input type="text" name="appName" required value="${isEditing ? escapeHtml(editApk.appName) : ""}" placeholder="Example App"></div>
        <div class="form-group"><label>Package Name</label><input type="text" name="packageName" required value="${isEditing ? escapeHtml(editApk.packageName) : ""}" placeholder="com.example.app"></div>
        <div class="form-group"><label>Version Name</label><input type="text" name="versionName" required value="${isEditing ? escapeHtml(editApk.versionName) : ""}" placeholder="2.0"></div>
        <div class="form-group"><label>Version Code</label><input type="number" name="versionCode" required value="${isEditing ? editApk.versionCode : ""}" placeholder="20"></div>
        <div class="form-group" style="grid-column:1/-1;"><label>Direct APK URL</label><input type="url" name="apkUrl" required value="${isEditing ? escapeHtml(editApk.apkUrl) : ""}" placeholder="https://example.com/app.apk"></div>
        
        <div class="form-group" style="grid-column:1/-1;">
          <label>Upload App Icon (Image File)</label>
          <input type="file" name="iconFile" accept="image/*">
          ${isEditing && editApk.iconUrl ? `<br><small style="color:green;">Current Icon active</small>` : ""}
        </div>

        <div class="form-group" style="grid-column:1/-1;">
          <label>Upload Feature Screenshots (Multiple files allowed)</label>
          <input type="file" name="screenshotFiles" accept="image/*" multiple>
        </div>

        <div class="form-group" style="grid-column:1/-1;"><label>Changelog / Description</label><textarea name="description" rows="3">${isEditing ? escapeHtml(editApk.description || "") : ""}</textarea></div>
        <div style="grid-column:1/-1;display:flex;gap:10px;"><button type="submit" class="btn ${isEditing ? 'btn-blue' : 'btn-green'}">${submitBtnText}</button>${isEditing ? '<a href="/apks" class="btn btn-gray">Cancel</a>' : ''}</div>
      </form></div></div>
      <div class="card"><div class="card-header">Published Apps</div><div class="table-wrap">
      <table><thead><tr><th>App</th><th>Version</th><th>Package</th><th>APK</th><th>Published</th><th>Action</th></tr></thead><tbody>${apkRows}</tbody></table>
      </div></div></div></body></html>`);
  } catch (err) { return res.status(500).send("Error"); }
});

app.post("/action/apk/add", requireLogin, csrfProtection, upload.fields([{ name: 'iconFile', maxCount: 1 }, { name: 'screenshotFiles', maxCount: 10 }]), async (req, res) => {
  try {
    const appName = safeString(req.body.appName, 100); 
    const packageName = safeString(req.body.packageName, 200); 
    const versionName = safeString(req.body.versionName, 50); 
    const apkUrl = safeString(req.body.apkUrl, 500);
    const description = safeString(req.body.description, 500);
    const versionCode = parseInt(req.body.versionCode, 10) || 1;

    let iconUrl = "";
    if (req.files && req.files.iconFile && req.files.iconFile[0]) {
      iconUrl = await uploadToCloudinary(req.files.iconFile[0].buffer, "rd_store/icons");
    }

    let screenshots = [];
    if (req.files && req.files.screenshotFiles) {
      for (const file of req.files.screenshotFiles) {
        const url = await uploadToCloudinary(file.buffer, "rd_store/screenshots");
        screenshots.push(url);
      }
    }
    
    if (appName && packageName && versionName && apkUrl) {
      await Apk.create({ appName, description, versionName, versionCode, packageName, apkUrl, iconUrl, screenshots });
    }
  } catch (err) {} res.redirect("/apks");
});

app.post("/action/apk/edit", requireLogin, csrfProtection, upload.fields([{ name: 'iconFile', maxCount: 1 }, { name: 'screenshotFiles', maxCount: 10 }]), async (req, res) => {
  try {
    const id = safeString(req.body.id, 100);
    const appName = safeString(req.body.appName, 100); 
    const packageName = safeString(req.body.packageName, 200); 
    const versionName = safeString(req.body.versionName, 50); 
    const apkUrl = safeString(req.body.apkUrl, 500);
    const description = safeString(req.body.description, 500);
    const versionCode = parseInt(req.body.versionCode, 10) || 1;

    let iconUrl = req.body.existingIconUrl || "";
    if (req.files && req.files.iconFile && req.files.iconFile[0]) {
      iconUrl = await uploadToCloudinary(req.files.iconFile[0].buffer, "rd_store/icons");
    }

    let screenshots = [];
    try {
      if (req.body.existingScreenshots) {
        screenshots = JSON.parse(req.body.existingScreenshots);
      }
    } catch(e) {}

    if (req.files && req.files.screenshotFiles) {
      for (const file of req.files.screenshotFiles) {
        const url = await uploadToCloudinary(file.buffer, "rd_store/screenshots");
        screenshots.push(url);
      }
    }

    if (mongoose.Types.ObjectId.isValid(id) && appName && packageName && versionName && apkUrl) {
      await Apk.findByIdAndUpdate(id, { appName, description, versionName, versionCode, packageName, apkUrl, iconUrl, screenshots });
    }
  } catch (err) {} res.redirect("/apks");
});

app.post("/action/apk/delete", requireLogin, csrfProtection, async (req, res) => {
  try { const id = safeString(req.body.id, 100); if (mongoose.Types.ObjectId.isValid(id)) await Apk.findByIdAndDelete(id); } catch (err) {} res.redirect("/apks");
});

app.post("/action/device/:type", requireLogin, csrfProtection, async (req, res) => {
  const type = String(req.params.type || ""); const deviceId = safeString(req.body.deviceId, MAX_DEVICE_ID_LENGTH); const appId = safeString(req.body.appId, MAX_APP_ID_LENGTH);
  if (!deviceId && type !== "clear-all-history") return res.redirect("/");
  try {
    if (type === "nickname") await Device.updateOne({ deviceId, appId }, { $set: { nickname: safeString(req.body.nickname, MAX_NICKNAME_LENGTH) } });
    if (type === "approve") await Device.updateOne({ deviceId, appId }, { $set: { status: "approved" } });
    if (type === "pending") { await Device.updateOne({ deviceId, appId }, { $set: { status: "pending" } }); await closeOnlineSession(deviceId, appId, "pending", Date.now()); }
    if (type === "block") { await Device.updateOne({ deviceId, appId }, { $set: { status: "blocked" } }); await closeOnlineSession(deviceId, appId, "blocked", Date.now()); }
    if (type === "clear-history") await UsageSession.deleteMany({ deviceId, appId });
    if (type === "delete") { await Promise.all([ Device.deleteOne({ deviceId, appId }), UsageSession.deleteMany({ deviceId, appId }) ]); }
    if (type === "clear-all-history") await UsageSession.deleteMany({});
  } catch (err) {} res.redirect("/");
});

/* =========================================================
   DASHBOARD API & UI
========================================================= */
app.get("/api/sessions/:deviceId", requireApiLogin, async (req, res) => {
  try {
    const deviceId = safeString(req.params.deviceId, MAX_DEVICE_ID_LENGTH); const appId = safeString(req.query.appId, MAX_APP_ID_LENGTH);
    if (!deviceId || !appId) return res.status(400).json({ success: false });
    await markStaleSessionsOffline();
    const sessions = await UsageSession.find({ deviceId, appId }).sort({ startTimestamp: -1 }).limit(200).lean();
    const now = Date.now();
    const formatted = sessions.map((item) => {
      const start = Number(item.startTimestamp); let end = Number(item.endTimestamp || item.lastSeenTimestamp);
      if (item.status === "online") end = now;
      const duration = item.status === "offline" && Number(item.durationMs) > 0 ? Number(item.durationMs) : Math.max(0, end - start);
      return { startTime: safeDate(item.startTime), lastSeenTime: safeDate(item.lastSeenTime), endTime: item.endTime ? safeDate(item.endTime) : item.status === "online" ? "Active" : safeDate(item.lastSeenTime), duration: formatDuration(duration), durationMs: duration, status: item.status, endReason: item.endReason || "unknown" };
    });
    return res.json({ success: true, sessions: formatted });
  } catch (err) { return res.status(500).json({ success: false }); }
});

app.get("/api/dashboard", requireApiLogin, async (req, res) => {
  try {
    await markStaleSessionsOffline();
    const search = safeString(req.query.search, MAX_SEARCH_LENGTH); const filter = String(req.query.filter || "all"); const appFilter = String(req.query.appFilter || "all");
    const requestedPage = Math.max(1, parseInt(req.query.page || "1", 10) || 1);
    const range = getRange(filter, "", ""); const now = Date.now(); const deviceMatch = {};

    if (appFilter && appFilter !== "all") deviceMatch.appId = appFilter;
    if (search) {
      const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      deviceMatch.$or = [{ deviceId: { $regex: escaped, $options: "i" } }, { nickname: { $regex: escaped, $options: "i" } }, { status: { $regex: escaped, $options: "i" } }];
    }

    const effectiveEndExpression = { $cond: [ { $eq: ["$status", "online"] }, now, { $ifNull: ["$endTimestamp", "$lastSeenTimestamp"] } ] };
    const sessionMatch = range.from !== null ? { startTimestamp: { $lte: range.to }, $or: [ { endTimestamp: { $gte: range.from } }, { endTimestamp: null, lastSeenTimestamp: { $gte: range.from } }, { status: "online" } ] } : {};
    if (appFilter && appFilter !== "all") sessionMatch.appId = appFilter;
    const durationStartExpression = range.from !== null ? { $max: ["$startTimestamp", range.from] } : "$startTimestamp"; const durationEndExpression = range.from !== null ? { $min: [effectiveEndExpression, range.to] } : effectiveEndExpression;
    const usagePipeline = [{ $match: sessionMatch }, { $project: { deviceId: 1, appId: 1, durationStart: durationStartExpression, durationEnd: durationEndExpression } }, { $project: { deviceId: 1, appId: 1, duration: { $max: [0, { $subtract: ["$durationEnd", "$durationStart"] }] } } }, { $group: { _id: { deviceId: "$deviceId", appId: "$appId" }, totalUsage: { $sum: "$duration" }, sessionCount: { $sum: 1 } } }];
    const chartPipeline = [{ $match: sessionMatch }, { $project: { day: { $dateToString: { format: "%Y-%m-%d", date: "$startTime", timezone: "Asia/Kolkata" } }, durationStart: durationStartExpression, durationEnd: durationEndExpression } }, { $project: { day: 1, duration: { $max: [0, { $subtract: ["$durationEnd", "$durationStart"] }] } } }, { $group: { _id: "$day", usage: { $sum: "$duration" } } }, { $sort: { _id: 1 } }];
    const onlineCutoff = now - ONLINE_TIMEOUT_MS; const skip = (requestedPage - 1) * DEVICES_PER_PAGE;
    const onlineMatch = { status: "online", lastSeenTimestamp: { $gte: onlineCutoff } }; if (appFilter && appFilter !== "all") onlineMatch.appId = appFilter;

    const results = await Promise.all([
      Device.aggregate([{ $match: deviceMatch }, { $group: { _id: "$status", count: { $sum: 1 } } }]), Device.countDocuments(deviceMatch), Device.find(deviceMatch).sort({ registeredAt: -1 }).skip(skip).limit(DEVICES_PER_PAGE).lean(),
      UsageSession.aggregate(usagePipeline), UsageSession.aggregate(chartPipeline), UsageSession.find(onlineMatch).select({ deviceId: 1, appId: 1 }).lean(), AppRegistry.find().select("appId appName").sort({ appName: 1 }).lean()
    ]);

    let totalDevices = 0, approved = 0, pending = 0, blocked = 0;
    results[0].forEach((item) => { const count = Number(item.count || 0); totalDevices += count; if (item._id === "approved") approved = count; if (item._id === "pending") pending = count; if (item._id === "blocked") blocked = count; });
    const usageMap = {}; let totalUsage = 0;
    results[3].forEach((item) => { const usage = Number(item.totalUsage || 0); const key = `${item._id.deviceId}_${item._id.appId}`; usageMap[key] = { totalUsage: usage, sessionCount: Number(item.sessionCount || 0) }; totalUsage += usage; });
    const onlineSet = new Set(results[5].map((item) => `${item.deviceId}_${item.appId}`));
    const totalPages = Math.max(1, Math.ceil(results[1] / DEVICES_PER_PAGE)); const currentPage = Math.min(requestedPage, totalPages);
    
    let devices = results[2];
    if (currentPage !== requestedPage) devices = await Device.find(deviceMatch).sort({ registeredAt: -1 }).skip((currentPage - 1) * DEVICES_PER_PAGE).limit(DEVICES_PER_PAGE).lean();

    const deviceData = devices.map((device) => {
      const key = `${device.deviceId}_${device.appId}`; const stat = usageMap[key] || { totalUsage: 0, sessionCount: 0 };
      return { deviceId: device.deviceId, appId: device.appId, nickname: device.nickname || "", status: device.status, registeredAt: safeDate(device.registeredAt), usage: formatDuration(stat.totalUsage), sessions: stat.sessionCount, online: onlineSet.has(key) };
    });

    return res.json({ success: true, stats: { totalDevices, approved, pending, blocked, online: onlineSet.size, totalUsage: formatDuration(totalUsage) }, devices: deviceData, apps: results[6], pagination: { page: currentPage, totalPages, totalDevices: results[1] }, chart: { labels: results[4].map(i => i._id), data: results[4].map(i => Math.round(Number(i.usage || 0) / 60000)) } });
  } catch (err) { return res.status(500).json({ success: false }); }
});

app.get("/", requireLogin, csrfProtection, (req, res) => {
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Console V6.4.5</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>${UI_STYLES}</head>
    <body>${TOPBAR_HTML(res.locals.csrfToken)}<div class="container"><div class="page-title"><h1>Device Management</h1><p id="refreshStatus" class="status-line">Loading dashboard...</p></div>
    <div class="card"><div class="card-body"><form id="filterForm" class="filters"><input id="search" class="search" placeholder="Search device ID or nickname"><select id="appFilter"><option value="all">All Apps</option></select><select id="filter"><option value="all">All Time</option><option value="today">Today (IST)</option><option value="7d">Last 7 Days</option><option value="30d">Last 30 Days</option></select><button class="btn btn-blue" type="submit">Apply Filter</button><button type="button" class="btn btn-gray" onclick="manualRefresh()">Refresh</button></form>
    <div style="margin-top:12px;"><form method="POST" action="/action/device/clear-all-history" onsubmit="return confirm('WARNING: Permanently delete ALL session history for ALL apps?')"><input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}"><button type="submit" class="btn btn-red">Clear All History</button></form></div></div></div>
    <div class="stats"><div class="stat"><div class="stat-label">TOTAL DEVICES</div><div class="stat-value" id="totalDevices">-</div></div><div class="stat"><div class="stat-label">APPROVED</div><div class="stat-value" id="approved">-</div></div><div class="stat"><div class="stat-label">PENDING</div><div class="stat-value" id="pending">-</div></div><div class="stat"><div class="stat-label">BLOCKED</div><div class="stat-value" id="blocked">-</div></div><div class="stat"><div class="stat-label">ONLINE NOW</div><div class="stat-value" id="online">-</div></div><div class="stat"><div class="stat-label">TOTAL USAGE</div><div class="stat-value" id="totalUsage">-</div></div></div>
    <div class="card"><div class="card-header">Usage Trend</div><div class="card-body"><div style="height:310px;"><canvas id="usageChart"></canvas></div></div></div>
    <div class="card"><div class="card-header">Device Permissions</div><div class="table-wrap"><table><thead><tr><th>Nickname</th><th>Device ID & App</th><th>Permission</th><th>Live Status</th><th>Usage</th><th>Registered</th><th>Actions</th></tr></thead><tbody id="deviceTable"><tr><td colspan="7" style="text-align:center;padding:25px;">Loading devices...</td></tr></tbody></table></div><div class="pagination"><button id="prevPage">Previous</button><span id="pageInfo">Page -</span><button id="nextPage">Next</button></div></div></div>
    <div class="modal-overlay" id="historyModal"><div class="modal"><div class="modal-header"><div id="modalTitle">Session History</div><button class="modal-close" onclick="closeModal()">×</button></div><div class="modal-body"><div class="table-wrap"><table><thead><tr><th>Started</th><th>Last Seen</th><th>Ended</th><th>Duration</th><th>Status</th><th>Reason</th></tr></thead><tbody id="historyTableBody"><tr><td colspan="6" style="text-align:center">Loading...</td></tr></tbody></table></div></div></div></div>
    <script>
      const csrfToken = "${escapeHtml(res.locals.csrfToken)}"; const REFRESH_SECONDS = ${DASHBOARD_REFRESH_SECONDS}; let currentPage = 1; let chartInstance = null; let refreshTimer = null; let refreshInProgress = false; const refreshStatus = document.getElementById("refreshStatus");
      function escapeHTML(value){ return String(value ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;"); }
      async function refreshDashboard(){
        if(refreshInProgress) return; refreshInProgress = true; clearTimeout(refreshTimer);
        try{
          refreshStatus.textContent = "Refreshing data..."; const params = new URLSearchParams(); params.set("search", document.getElementById("search").value); params.set("filter", document.getElementById("filter").value); params.set("appFilter", document.getElementById("appFilter").value); params.set("page", currentPage);
          const response = await fetch("/api/dashboard?" + params.toString(), { credentials: "same-origin", cache: "no-store" });
          if(response.status === 401){ window.location.href = "/login"; return; } const data = await response.json(); if(!data.success) throw new Error("API error");
          updateAppDropdown(data.apps); updateStats(data.stats); updateTable(data.devices); updatePagination(data.pagination);
          if(chartInstance) chartInstance.destroy(); chartInstance = new Chart(document.getElementById("usageChart"), { type: "line", data: { labels: data.chart.labels, datasets: [{ label: "Usage (mins)", data: data.chart.data, borderColor: "#2563eb", backgroundColor: "rgba(37,99,235,.08)", borderWidth: 2, fill: true }] }, options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } } });
          refreshStatus.textContent = "Last refreshed: " + new Date().toLocaleTimeString("en-IN");
        } catch(error) { refreshStatus.textContent = "Unable to refresh."; } finally { refreshInProgress = false; scheduleRefresh(); }
      }
      function manualRefresh(){ refreshDashboard(); }
      function updateAppDropdown(apps) {
        const appSelect = document.getElementById("appFilter"); const currentValue = appSelect.value;
        appSelect.innerHTML = '<option value="all">All Apps</option>';
        apps.forEach(app => { if(app && app.appId){ const option = document.createElement("option"); option.value = app.appId; option.textContent = app.appName + " (" + app.appId + ")"; if(app.appId === currentValue) option.selected = true; appSelect.appendChild(option); } });
      }
      function updateStats(stats){ document.getElementById("totalDevices").textContent = stats.totalDevices; document.getElementById("approved").textContent = stats.approved; document.getElementById("pending").textContent = stats.pending; document.getElementById("blocked").textContent = stats.blocked; document.getElementById("online").textContent = stats.online; document.getElementById("totalUsage").textContent = stats.totalUsage; }
      function updateTable(devices){
        const tbody = document.getElementById("deviceTable"); if(!devices.length){ tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:25px">No devices found.</td></tr>'; return; }
        tbody.innerHTML = devices.map(function(device){
          const deviceId = escapeHTML(device.deviceId); const appId = escapeHTML(device.appId); const nickname = escapeHTML(device.nickname); const status = escapeHTML(device.status); const liveClass = device.online ? "online" : "offline"; const liveText = device.online ? "ONLINE" : "OFFLINE";
          let actions = '<button type="button" class="btn btn-purple" data-history="' + deviceId + '" data-app="' + appId + '">History</button>';
          actions += '<form class="inline-form" method="POST" action="/action/device/clear-history"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><input type="hidden" name="appId" value="' + appId + '"><button class="btn btn-red" type="submit">Clear History</button></form>';
          if(device.status !== "approved"){ actions += '<form class="inline-form" method="POST" action="/action/device/approve"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><input type="hidden" name="appId" value="' + appId + '"><button class="btn btn-green" type="submit">Approve</button></form>'; }
          if(device.status !== "blocked"){ actions += '<form class="inline-form" method="POST" action="/action/device/block"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><input type="hidden" name="appId" value="' + appId + '"><button class="btn btn-orange" type="submit">Block</button></form>'; }
          if(device.status !== "pending"){ actions += '<form class="inline-form" method="POST" action="/action/device/pending"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><input type="hidden" name="appId" value="' + appId + '"><button class="btn btn-yellow" type="submit">Pending</button></form>'; }
          actions += '<form class="inline-form" method="POST" action="/action/device/delete"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><input type="hidden" name="appId" value="' + appId + '"><button class="btn btn-red" type="submit">Delete Device</button></form>';
          return '<tr><td><form class="inline-form" method="POST" action="/action/device/nickname"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><input type="hidden" name="appId" value="' + appId + '"><input class="nickname-input" name="nickname" maxlength="50" placeholder="Nickname" value="' + nickname + '"><button class="btn btn-blue" type="submit">Save</button></form></td><td><code>' + deviceId + '</code><br><span class="badge badge-app">' + appId + '</span></td><td><span class="badge ' + status + '">' + status.toUpperCase() + '</span></td><td><span class="badge ' + liveClass + '">' + liveText + '</span></td><td><strong>' + escapeHTML(device.usage) + '</strong><br><span style="font-size:11px;color:#6b7280">' + Number(device.sessions) + ' sessions</span></td><td>' + escapeHTML(device.registeredAt) + '</td><td class="action-cell">' + actions + '</td></tr>';
        }).join("");
        document.querySelectorAll("[data-history]").forEach(function(btn){ btn.addEventListener("click", function(){ openHistory(btn.getAttribute("data-history"), btn.getAttribute("data-app")); }); });
      }
      async function openHistory(deviceId, appId){
        const modal = document.getElementById("historyModal"); const title = document.getElementById("modalTitle"); const body = document.getElementById("historyTableBody");
        title.textContent = "History — " + deviceId + " (" + appId + ")"; body.innerHTML = '<tr><td colspan="6" style="text-align:center">Loading...</td></tr>'; modal.style.display = "flex";
        try {
          const response = await fetch("/api/sessions/" + encodeURIComponent(deviceId) + "?appId=" + encodeURIComponent(appId), { credentials: "same-origin", cache: "no-store" });
          if(response.status === 401){ window.location.href = "/login"; return; } const data = await response.json();
          if(!data.success || !data.sessions.length){ body.innerHTML = '<tr><td colspan="6" style="text-align:center">No session history available.</td></tr>'; return; }
          body.innerHTML = data.sessions.map(function(item){ const statusClass = item.status === "online" ? "online" : "offline"; return '<tr><td>' + escapeHTML(item.startTime) + '</td><td>' + escapeHTML(item.lastSeenTime) + '</td><td>' + escapeHTML(item.endTime) + '</td><td><strong>' + escapeHTML(item.duration) + '</strong></td><td><span class="badge ' + statusClass + '">' + escapeHTML(String(item.status).toUpperCase()) + '</span></td><td>' + escapeHTML(item.endReason) + '</td></tr>'; }).join("");
        } catch(error) { body.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#b91c1c">Failed to load session history.</td></tr>'; }
      }
      function closeModal(){ document.getElementById("historyModal").style.display = "none"; }
      window.addEventListener("click", function(event){ if(event.target === document.getElementById("historyModal")){ closeModal(); } });
      function updatePagination(p){ currentPage = p.page; document.getElementById("pageInfo").textContent = "Page " + p.page + " of " + p.totalPages; document.getElementById("prevPage").disabled = p.page <= 1; document.getElementById("nextPage").disabled = p.page >= p.totalPages; }
      function scheduleRefresh(){ clearTimeout(refreshTimer); if(!document.hidden){ refreshTimer = setTimeout(refreshDashboard, REFRESH_SECONDS * 1000); } }
      document.getElementById("filterForm").addEventListener("submit", function(event){ event.preventDefault(); currentPage = 1; refreshDashboard(); });
      document.getElementById("prevPage").addEventListener("click", function(){ if(currentPage > 1){ currentPage--; refreshDashboard(); } });
      document.getElementById("nextPage").addEventListener("click", function(){ currentPage++; refreshDashboard(); });
      document.addEventListener("visibilitychange", function(){ if(document.hidden){ clearTimeout(refreshTimer); } else { scheduleRefresh(); } });
      refreshDashboard();
    </script></body></html>`);
});

app.use((req, res) => { res.status(404).send("404 Not Found"); });

/* =========================================================
   SHUTDOWN & STARTUP
========================================================= */
let server = null;
async function shutdown(signal) {
  console.log(signal + " received. Shutting down..."); clearInterval(cleanupInterval);
  try { if (server) await new Promise((resolve) => { server.close(resolve); }); await mongoose.disconnect(); console.log("Shutdown complete."); process.exit(0); } 
  catch (err) { process.exit(1); }
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

async function startServer() {
  try {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 10000, socketTimeoutMS: 45000 });
    
    try {
      await Device.updateMany({ appId: { $exists: false } }, { $set: { appId: "default_app" } });
      await UsageSession.updateMany({ appId: { $exists: false } }, { $set: { appId: "default_app" } });
      
      const distinctAppIds = await Device.distinct("appId");
      for (const appId of distinctAppIds) {
        await AppRegistry.updateOne({ appId }, { $setOnInsert: { appId, appName: appId } }, { upsert: true }).catch(() => {});
      }
    } catch (e) {}

    try { await Device.init(); await UsageSession.init(); await Apk.init(); await AppRegistry.init(); } catch (err) { }
    
    server = app.listen(PORT, () => { console.log("V6.4.5 Production Edition running on port " + PORT); });
  } catch (err) { process.exit(1); }
}
startServer();
