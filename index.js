const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();

/* =========================================================
ULTIMATE ADMIN DASHBOARD V5 SINGLE-FILE SERVER
========================================================= */

/* =========================================================
CONFIGURATION
========================================================= */
const PORT = Number(process.env.PORT || 3000);
const MONGO_URI = process.env.MONGO_URI;

const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || "admin");
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

const IS_PRODUCTION = process.env.NODE_ENV === "production";

const SESSION_SECRET = process.env.SESSION_SECRET || (IS_PRODUCTION ? null : crypto.randomBytes(32).toString("hex"));

const REDIRECT_URL = process.env.REDIRECT_URL || "https://wa.me/918099188409?text=Hello%20Developer,%20please%20activate%20my%20app";

const ONLINE_TIMEOUT_MS = 25000;
const DASHBOARD_REFRESH_SECONDS = 15;
const DEVICES_PER_PAGE = 20;
const MAX_DEVICE_ID_LENGTH = 200;
const MAX_SEARCH_LENGTH = 100;

/* =========================================================
HARD FAIL SECURITY CHECKS
========================================================= */
if (!MONGO_URI) {
  console.error("FATAL ERROR: MONGO_URI is missing.");
  process.exit(1);
}

if (!ADMIN_PASSWORD && !ADMIN_PASSWORD_HASH) {
  console.error("FATAL ERROR: ADMIN_PASSWORD or ADMIN_PASSWORD_HASH is required.");
  process.exit(1);
}

if (IS_PRODUCTION && !SESSION_SECRET) {
  console.error("FATAL ERROR: SESSION_SECRET is required in production.");
  process.exit(1);
}

/* =========================================================
EXPRESS SETUP
========================================================= */
app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(express.urlencoded({ extended: true, limit: "100kb" }));
app.use(express.json({ limit: "100kb" }));

/* =========================================================
SECURITY HEADERS
========================================================= */
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

/* =========================================================
MONGODB SESSION STORE
========================================================= */
app.use(
  session({
    name: "admin.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: MONGO_URI,
      collectionName: "admin_sessions",
      ttl: 60 * 60 * 24,
      autoRemove: "native"
    }),
    cookie: {
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

/* =========================================================
RATE LIMITERS
========================================================= */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many login attempts. Please try again later."
});

const trackingLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false
});

/* =========================================================
DATABASE SCHEMAS
========================================================= */
const DeviceSchema = new mongoose.Schema({
  deviceId: { type: String, required: true, unique: true, index: true, trim: true, maxlength: MAX_DEVICE_ID_LENGTH },
  nickname: { type: String, default: "", trim: true, maxlength: 50 },
  status: { type: String, enum: ["pending", "approved", "blocked"], default: "pending", index: true },
  registeredAt: { type: Date, default: Date.now, index: true }
}, { versionKey: false });

const SessionSchema = new mongoose.Schema({
  deviceId: { type: String, required: true, index: true, maxlength: MAX_DEVICE_ID_LENGTH },
  startTime: { type: Date, required: true },
  lastSeenTime: { type: Date, required: true },
  startTimestamp: { type: Number, required: true, index: true },
  lastSeenTimestamp: { type: Number, required: true, index: true },
  status: { type: String, enum: ["online", "offline"], default: "online", index: true }
}, { versionKey: false });

/* Fast device history lookup. */
SessionSchema.index({ deviceId: 1, startTimestamp: -1 });

/* Fast stale-session cleanup. */
SessionSchema.index({ status: 1, lastSeenTimestamp: 1 });

/* Prevent more than ONE active online session per device.
MongoDB partial unique index: only documents where status = online are unique. 
Added custom 'name' to fix the Render MongoDB conflict error! */
SessionSchema.index(
  { deviceId: 1 },
  { 
    unique: true, 
    partialFilterExpression: { status: "online" },
    name: "unique_online_device_idx"
  }
);

const Device = mongoose.model("Device", DeviceSchema);
const UsageSession = mongoose.model("UsageSession", SessionSchema);

/* =========================================================
DATABASE CONNECTION
========================================================= */
mongoose.connection.on("error", (err) => { console.error("MongoDB Error:", err.message); });
mongoose.connection.on("disconnected", () => { console.warn("MongoDB DISCONNECTED"); });

/* =========================================================
HELPERS
========================================================= */
function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatDuration(ms) {
  const safeMs = Number(ms);
  if (!Number.isFinite(safeMs) || safeMs <= 0) { return "0s"; }
  const totalSeconds = Math.floor(safeMs / 1000);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  
  const result = [];
  if (days > 0) { result.push(days + "d"); }
  if (hours > 0) { result.push(hours + "h"); }
  if (minutes > 0) { result.push(minutes + "m"); }
  if (seconds > 0 || result.length === 0) { result.push(seconds + "s"); }
  return result.join(" ");
}

function safeDate(value) {
  if (!value) { return "N/A"; }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) { return String(value); }
  return date.toLocaleString("en-IN", { timeZone: "Asia/Kolkata", dateStyle: "medium", timeStyle: "medium" });
}

/* Returns IST midnight timestamp. */
function getISTStartOfDay() {
  const now = new Date();
  const formatter = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Kolkata", year: "numeric", month: "2-digit", day: "2-digit" });
  const parts = formatter.formatToParts(now);
  const values = {};
  parts.forEach((part) => { if (part.type !== "literal") { values[part.type] = part.value; } });
  
  return (
    Date.UTC(Number(values.year), Number(values.month) - 1, Number(values.day), 0, 0, 0) -
    5.5 * 60 * 60 * 1000
  );
}

function getRange(filter, customFrom, customTo) {
  const now = Date.now();
  let from = null;
  let to = now;

  if (filter === "today") { from = getISTStartOfDay(); }
  if (filter === "7d") { from = now - 7 * 24 * 60 * 60 * 1000; }
  if (filter === "30d") { from = now - 30 * 24 * 60 * 60 * 1000; }
  
  if (filter === "custom") {
    if (customFrom) {
      const parsedFrom = new Date(customFrom + "T00:00:00+05:30");
      if (!Number.isNaN(parsedFrom.getTime())) { from = parsedFrom.getTime(); }
    }
    if (customTo) {
      const parsedTo = new Date(customTo + "T23:59:59.999+05:30");
      if (!Number.isNaN(parsedTo.getTime())) { to = parsedTo.getTime(); }
    }
  }

  /* Invalid custom range protection. */
  if (from !== null && Number.isFinite(from) && Number.isFinite(to) && from > to) {
    return { from: to, to: from };
  }
  return { from, to };
}

function safeString(value, maxLength) {
  return String(value || "").trim().substring(0, maxLength);
}

/* =========================================================
CSRF
========================================================= */
function csrfProtection(req, res, next) {
  if (!req.session) { return res.status(500).send("Session unavailable."); }
  if (!req.session.csrfToken) { req.session.csrfToken = crypto.randomBytes(24).toString("hex"); }
  res.locals.csrfToken = req.session.csrfToken;
  
  if (req.method === "POST" || req.method === "PUT" || req.method === "PATCH" || req.method === "DELETE") {
    const token = req.body?._csrf || req.get("x-csrf-token");
    if (!token || token !== req.session.csrfToken) {
      return res.status(403).send("CSRF validation failed.");
    }
  }
  next();
}

/* =========================================================
AUTH
========================================================= */
function requireLogin(req, res, next) {
  if (req.session && req.session.adminAuthenticated === true) { return next(); }
  return res.redirect("/login");
}

function requireApiLogin(req, res, next) {
  if (req.session && req.session.adminAuthenticated === true) { return next(); }
  return res.status(401).json({ success: false, error: "UNAUTHORIZED" });
}

/* =========================================================
PASSWORD COMPARISON
========================================================= */
async function verifyPassword(password) {
  if (ADMIN_PASSWORD_HASH) { return bcrypt.compare(password, ADMIN_PASSWORD_HASH); }
  if (!ADMIN_PASSWORD) { return false; }
  
  const inputBuffer = Buffer.from(password);
  const storedBuffer = Buffer.from(ADMIN_PASSWORD);
  
  /* timingSafeEqual throws if lengths differ. */
  if (inputBuffer.length !== storedBuffer.length) { return false; }
  return crypto.timingSafeEqual(inputBuffer, storedBuffer);
}

/* =========================================================
SESSION CLEANUP
========================================================= */
let cleanupRunning = false;
async function markStaleSessionsOffline() {
  if (cleanupRunning) { return; }
  cleanupRunning = true;
  try {
    const cutoff = Date.now() - ONLINE_TIMEOUT_MS;
    await UsageSession.updateMany(
      { status: "online", lastSeenTimestamp: { $lt: cutoff } },
      { $set: { status: "offline" } }
    );
  } catch (err) {
    console.error("Session cleanup error:", err.message);
  } finally {
    cleanupRunning = false;
  }
}
const cleanupInterval = setInterval(markStaleSessionsOffline, 15000);
cleanupInterval.unref();

/* =========================================================
LOGIN PAGE
========================================================= */
app.get("/login", csrfProtection, (req, res) => {
  if (req.session && req.session.adminAuthenticated) { return res.redirect("/"); }
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login</title>
  <style>
    * { box-sizing:border-box; font-family:system-ui,sans-serif; } 
    body{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:#0f172a; color:#e2e8f0; padding:20px; } 
    .card{ width:100%; max-width:400px; background:#1e293b; padding:28px; border-radius:14px; box-shadow:0 20px 60px rgba(0,0,0,.4); } 
    h1{ text-align:center; margin-top:0; color:#38bdf8; } 
    input{ width:100%; padding:12px; margin:8px 0; border-radius:7px; border:1px solid #475569; background:#0f172a; color:white; } 
    button{ width:100%; padding:12px; border:0; border-radius:7px; background:#3b82f6; color:white; font-weight:bold; cursor:pointer; margin-top:10px; } 
    .error{ background:#7f1d1d; padding:10px; border-radius:6px; text-align:center; margin-bottom:10px; color:#fecaca; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Secure Admin Login</h1>
    ${req.query.error ? '<div class="error">Invalid credentials</div>' : ""}
    <form method="POST" action="/login">
      <input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}">
      <input type="text" name="username" placeholder="Username" autocomplete="username" required>
      <input type="password" name="password" placeholder="Password" autocomplete="current-password" required>
      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>
  `);
});

/* =========================================================
LOGIN POST
========================================================= */
app.post("/login", loginLimiter, csrfProtection, async (req, res) => {
  try {
    const username = safeString(req.body.username, 100);
    const password = String(req.body.password || "");
    
    if (username !== ADMIN_USERNAME) { return res.redirect("/login?error=1"); }
    const valid = await verifyPassword(password);
    if (!valid) { return res.redirect("/login?error=1"); }
    
    req.session.regenerate((err) => {
      if (err) {
        console.error("Session regenerate error:", err.message);
        return res.redirect("/login?error=1");
      }
      req.session.adminAuthenticated = true;
      req.session.adminUsername = ADMIN_USERNAME;
      req.session.csrfToken = crypto.randomBytes(24).toString("hex");
      req.session.save((saveErr) => {
        if (saveErr) {
          console.error("Session save error:", saveErr.message);
          return res.redirect("/login?error=1");
        }
        return res.redirect("/");
      });
    });
  } catch (err) {
    console.error("Login error:", err.message);
    return res.redirect("/login?error=1");
  }
});

/* =========================================================
LOGOUT
========================================================= */
app.post("/logout", requireLogin, csrfProtection, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("admin.sid");
    res.redirect("/login");
  });
});

/* =========================================================
HEALTH CHECK
========================================================= */
app.get("/health", (req, res) => {
  const connected = mongoose.connection.readyState === 1;
  res.status(connected ? 200 : 503).json({
    server: "online",
    database: connected ? "connected" : "disconnected",
    timestamp: new Date()
  });
});

/* =========================================================
PUBLIC APP TRACKING
========================================================= */
async function handleTracking(req, res) {
  const deviceId = safeString(req.query.id || req.body?.id, MAX_DEVICE_ID_LENGTH);
  const rawAction = String(req.query.action || req.body?.action || req.query.status || req.body?.status || "start").trim().toLowerCase();
  const action = rawAction === "offline" ? "stop" : rawAction;

  if (!deviceId) {
    return res.status(400).json({ status: "ERROR", message: "DEVICE_ID_MISSING" });
  }

  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ status: "ERROR", message: "DATABASE_OFFLINE" });
  }

  try {
    let device = await Device.findOne({ deviceId });
    if (!device) {
      try {
        device = await Device.create({ deviceId, status: "pending", registeredAt: new Date() });
      } catch (createError) {
        if (createError && createError.code === 11000) {
          device = await Device.findOne({ deviceId });
        } else { throw createError; }
      }
    }
    
    /* Newly created devices and non-approved devices are denied. */
    if (!device || device.status !== "approved") {
      await UsageSession.updateMany(
        { deviceId, status: "online" },
        { $set: { status: "offline", lastSeenTimestamp: Date.now(), lastSeenTime: new Date() } }
      );
      return res.status(200).json({ status: "BLOCKED", redirectUrl: REDIRECT_URL });
    }

    const now = Date.now();
    const nowDate = new Date(now);

    /* Explicit stop. */
    if (action === "stop") {
      await UsageSession.findOneAndUpdate(
        { deviceId, status: "online" },
        { $set: { lastSeenTimestamp: now, lastSeenTime: nowDate, status: "offline" } },
        { sort: { startTimestamp: -1 } }
      );
      return res.status(200).json({ status: "ALLOWED", action: "STOPPED" });
    }

    /* Update active session heartbeat. */
    let activeSession = await UsageSession.findOneAndUpdate(
      { deviceId, status: "online" },
      { $set: { lastSeenTimestamp: now, lastSeenTime: nowDate } },
      { sort: { startTimestamp: -1 }, new: true }
    );

    /* No active session: create one. Duplicate-key race is handled. */
    if (!activeSession) {
      try {
        activeSession = await UsageSession.create({
          deviceId,
          startTime: nowDate,
          lastSeenTime: nowDate,
          startTimestamp: now,
          lastSeenTimestamp: now,
          status: "online"
        });
      } catch (createError) {
        if (createError && createError.code === 11000) {
          activeSession = await UsageSession.findOneAndUpdate(
            { deviceId, status: "online" },
            { $set: { lastSeenTimestamp: now, lastSeenTime: nowDate } },
            { sort: { startTimestamp: -1 }, new: true }
          );
        } else { throw createError; }
      }
    }

    return res.status(200).json({
      status: "ALLOWED",
      action: activeSession && activeSession.startTimestamp === now ? "STARTED" : "HEARTBEAT"
    });

  } catch (err) {
    console.error("Tracking error:", err.message);
    return res.status(500).json({ status: "ERROR" });
  }
}

app.get(["/track", "/index.php"], trackingLimiter, handleTracking);
app.post(["/track", "/index.php"], trackingLimiter, handleTracking);

/* =========================================================
ADMIN ACTIONS
========================================================= */
app.post("/action/:type", requireLogin, csrfProtection, async (req, res) => {
  const type = String(req.params.type || "");
  const deviceId = safeString(req.body.deviceId, MAX_DEVICE_ID_LENGTH);
  
  if (!deviceId) { return res.redirect(req.get("referer") || "/"); }
  
  try {
    if (type === "nickname") {
      const nickname = safeString(req.body.nickname, 50);
      await Device.updateOne({ deviceId }, { $set: { nickname } });
    }
    if (type === "approve") {
      await Device.updateOne({ deviceId }, { $set: { status: "approved" } });
    }
    if (type === "pending") {
      await Device.updateOne({ deviceId }, { $set: { status: "pending" } });
      await UsageSession.updateMany(
        { deviceId, status: "online" },
        { $set: { status: "offline", lastSeenTimestamp: Date.now(), lastSeenTime: new Date() } }
      );
    }
    if (type === "block") {
      await Device.updateOne({ deviceId }, { $set: { status: "blocked" } });
      await UsageSession.updateMany(
        { deviceId, status: "online" },
        { $set: { status: "offline", lastSeenTimestamp: Date.now(), lastSeenTime: new Date() } }
      );
    }
    if (type === "delete") {
      await Promise.all([
        Device.deleteOne({ deviceId }),
        UsageSession.deleteMany({ deviceId })
      ]);
    }
  } catch (err) {
    console.error("Admin action error:", err.message);
  }
  return res.redirect(req.get("referer") || "/");
});

/* =========================================================
SESSION HISTORY API
========================================================= */
app.get("/api/sessions/:deviceId", requireApiLogin, async (req, res) => {
  try {
    const deviceId = safeString(req.params.deviceId, MAX_DEVICE_ID_LENGTH);
    if (!deviceId) {
      return res.status(400).json({ success: false, error: "DEVICE_ID_REQUIRED" });
    }
    await markStaleSessionsOffline();
    
    const sessions = await UsageSession.find({ deviceId })
      .sort({ startTimestamp: -1 })
      .limit(100)
      .lean();
      
    const now = Date.now();
    const formattedSessions = sessions.map((item) => {
      const start = Number(item.startTimestamp || new Date(item.startTime).getTime());
      let end = Number(item.lastSeenTimestamp || new Date(item.lastSeenTime).getTime());
      if (item.status === "online") { end = now; }
      const durationMs = Math.max(0, end - start);
      
      return {
        startTime: safeDate(item.startTime),
        lastSeenTime: safeDate(item.lastSeenTime),
        duration: formatDuration(durationMs),
        status: item.status
      };
    });
    
    return res.json({ success: true, sessions: formattedSessions });
  } catch (err) {
    console.error("History API error:", err.message);
    return res.status(500).json({ success: false, error: "FETCH_FAILED" });
  }
});

/* =========================================================
DASHBOARD DATA API
========================================================= */
app.get("/api/dashboard", requireApiLogin, async (req, res) => {
  try {
    await markStaleSessionsOffline();

    const search = safeString(req.query.search, MAX_SEARCH_LENGTH);
    const filter = String(req.query.filter || "all");
    const customFrom = String(req.query.from || "");
    const customTo = String(req.query.to || "");
    const requestedPage = Math.max(1, parseInt(req.query.page || "1", 10) || 1);
    
    const range = getRange(filter, customFrom, customTo);
    const now = Date.now();

    /* A session overlaps a selected range if: sessionStart <= rangeEnd AND sessionEnd >= rangeStart */
    const sessionMatch = {};
    if (range.from !== null) {
      sessionMatch.startTimestamp = { $lte: range.to };
      sessionMatch.lastSeenTimestamp = { $gte: range.from };
    }

    const usagePipeline = [
      { $match: sessionMatch },
      { $project: {
          deviceId: 1,
          durationStart: range.from !== null ? { $max: ["$startTimestamp", range.from] } : "$startTimestamp",
          durationEnd: range.from !== null ? { $min: ["$lastSeenTimestamp", range.to] } : { $cond: [{ $eq: ["$status", "online"] }, now, "$lastSeenTimestamp"] }
      }},
      { $project: { deviceId: 1, duration: { $max: [0, { $subtract: ["$durationEnd", "$durationStart"] }] } } },
      { $group: { _id: "$deviceId", totalUsage: { $sum: "$duration" }, sessionCount: { $sum: 1 } } }
    ];

    const chartPipeline = [
      { $match: sessionMatch },
      { $project: {
          day: { $dateToString: { format: "%Y-%m-%d", date: "$startTime", timezone: "Asia/Kolkata" } },
          durationStart: range.from !== null ? { $max: ["$startTimestamp", range.from] } : "$startTimestamp",
          durationEnd: range.from !== null ? { $min: ["$lastSeenTimestamp", range.to] } : { $cond: [{ $eq: ["$status", "online"] }, now, "$lastSeenTimestamp"] }
      }},
      { $project: { day: 1, duration: { $max: [0, { $subtract: ["$durationEnd", "$durationStart"] }] } } },
      { $group: { _id: "$day", usage: { $sum: "$duration" } } },
      { $sort: { _id: 1 } }
    ];

    const deviceMatch = {};
    if (search) {
      const escapedSearch = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      deviceMatch.$or = [
        { deviceId: { $regex: escapedSearch, $options: "i" } },
        { nickname: { $regex: escapedSearch, $options: "i" } },
        { status: { $regex: escapedSearch, $options: "i" } }
      ];
    }

    const onlineCutoff = now - ONLINE_TIMEOUT_MS;
    
    const [deviceStatusStats, totalSearchDevices, devices, usageStats, chartStats, onlineSessions] = await Promise.all([
      Device.aggregate([{ $group: { _id: "$status", count: { $sum: 1 } } }]),
      Device.countDocuments(deviceMatch),
      Device.find(deviceMatch).sort({ registeredAt: -1 }).skip((requestedPage - 1) * DEVICES_PER_PAGE).limit(DEVICES_PER_PAGE).lean(),
      UsageSession.aggregate(usagePipeline),
      UsageSession.aggregate(chartPipeline),
      UsageSession.find({ status: "online", lastSeenTimestamp: { $gte: onlineCutoff } }).select({ deviceId: 1 }).lean()
    ]);

    let totalDevices = 0, approved = 0, pending = 0, blocked = 0;
    deviceStatusStats.forEach((item) => {
      const count = Number(item.count || 0);
      totalDevices += count;
      if (item._id === "approved") { approved = count; }
      if (item._id === "pending") { pending = count; }
      if (item._id === "blocked") { blocked = count; }
    });

    const usageMap = {};
    let totalUsage = 0;
    usageStats.forEach((item) => {
      const usage = Number(item.totalUsage || 0);
      usageMap[item._id] = { totalUsage: usage, sessionCount: Number(item.sessionCount || 0) };
      totalUsage += usage;
    });

    const onlineSet = new Set(onlineSessions.map((item) => String(item.deviceId)));
    const totalPages = Math.max(1, Math.ceil(totalSearchDevices / DEVICES_PER_PAGE));
    const currentPage = Math.min(requestedPage, totalPages);

    let finalDevices = devices;
    if (currentPage !== requestedPage) {
      finalDevices = await Device.find(deviceMatch).sort({ registeredAt: -1 }).skip((currentPage - 1) * DEVICES_PER_PAGE).limit(DEVICES_PER_PAGE).lean();
    }

    const deviceData = finalDevices.map((device) => {
      const stat = usageMap[device.deviceId] || { totalUsage: 0, sessionCount: 0 };
      return {
        deviceId: device.deviceId,
        nickname: device.nickname || "",
        status: device.status,
        registeredAt: safeDate(device.registeredAt),
        usage: formatDuration(stat.totalUsage),
        sessions: stat.sessionCount,
        online: onlineSet.has(String(device.deviceId))
      };
    });

    const chartLabels = chartStats.map((item) => item._id);
    const chartData = chartStats.map((item) => Math.round(Number(item.usage || 0) / 60000));

    return res.json({
      success: true,
      stats: { totalDevices, approved, pending, blocked, online: onlineSet.size, totalUsage: formatDuration(totalUsage) },
      devices: deviceData,
      pagination: { page: currentPage, totalPages, totalDevices: totalSearchDevices },
      chart: { labels: chartLabels, data: chartData }
    });
  } catch (err) {
    console.error("Dashboard API error:", err.message);
    return res.status(500).json({ success: false, error: "DASHBOARD_ERROR" });
  }
});

/* =========================================================
MAIN DASHBOARD (HTML FIXED)
========================================================= */
app.get("/", requireLogin, csrfProtection, (req, res) => {
  const search = String(req.query.search || "");
  const filter = String(req.query.filter || "all");
  const customFrom = String(req.query.from || "");
  const customTo = String(req.query.to || "");
  const page = Math.max(1, parseInt(req.query.page || "1", 10) || 1);

  res.send(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ultimate Admin Dashboard V5</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    * { box-sizing:border-box; font-family:system-ui,sans-serif; } 
    body{ margin:0; padding:15px; background:#0f172a; color:#e2e8f0; } 
    .container{ max-width:1450px; margin:auto; } 
    .header{ display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; margin-bottom:20px; } 
    h1{ margin:0; font-size:24px; color:#38bdf8; } 
    h2{ color:#38bdf8; font-size:17px; } 
    .card{ background:#1e293b; padding:15px; border-radius:12px; margin-bottom:15px; overflow-x:auto; } 
    .stats{ display:grid; grid-template-columns: repeat(auto-fit,minmax(150px,1fr)); gap:10px; margin-bottom:15px; } 
    .stat{ background:#1e293b; padding:15px; border-radius:10px; border:1px solid #334155; } 
    .stat-title{ font-size:11px; color:#94a3b8; text-transform:uppercase; } 
    .stat-value{ font-size:22px; font-weight:bold; margin-top:5px; } 
    .filters{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; } 
    .search, select, input[type=date], .nickname-input{ padding:9px; border-radius:6px; border:1px solid #475569; background:#0f172a; color:white; } 
    .search{ width:240px; } 
    .nickname-input{ width:120px; padding:7px; } 
    .btn{ border:0; border-radius:6px; padding:8px 11px; color:white; font-weight:bold; cursor:pointer; font-size:11px; text-decoration:none; display:inline-block; } 
    .refresh-btn{ background:#3b82f6; } 
    .logout-btn{ background:#475569; } 
    .approve{ background:#16a34a; } 
    .block{ background:#ea580c; } 
    .pending-btn{ background:#ca8a04; } 
    .delete-btn{ background:#dc2626; } 
    .history-btn{ background:#8b5cf6; } 
    .badge{ display:inline-block; padding:5px 8px; border-radius:5px; font-size:10px; font-weight:bold; } 
    .approved, .online{ background:#14532d; color:#4ade80; } 
    .pending{ background:#78350f; color:#fbbf24; } 
    .blocked{ background:#7f1d1d; color:#f87171; } 
    .offline{ background:#334155; color:#cbd5e1; } 
    table{ width:100%; border-collapse:collapse; min-width:950px; } 
    th, td{ padding:12px 10px; border-bottom:1px solid #334155; text-align:left; font-size:13px; } 
    th{ background:#0f172a; white-space:nowrap; } 
    .action-cell{ display:flex; gap:6px; flex-wrap:wrap; min-width:270px; align-items:center; } 
    code{ background:#0f172a; padding:4px 7px; border-radius:4px; color:#94a3b8; font-size:11px; word-break:break-all; } 
    small{ color:#94a3b8; } 
    .chart-card{ height:370px; } 
    .pagination{ display:flex; gap:10px; justify-content:center; align-items:center; margin-top:15px; } 
    .pagination button{ padding:8px 12px; border:0; border-radius:6px; background:#334155; color:white; cursor:pointer; } 
    .pagination button:disabled{ opacity:.4; cursor:not-allowed; } 
    /* MODAL */ 
    .modal-overlay{ display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,.7); z-index:9999; justify-content:center; align-items:center; padding:15px; } 
    .modal{ background:#1e293b; width:100%; max-width:700px; border-radius:14px; border:1px solid #334155; box-shadow: 0 20px 50px rgba(0,0,0,.5); overflow:hidden; } 
    .modal-header{ display:flex; justify-content:space-between; align-items:center; padding:16px 20px; background:#0f172a; border-bottom:1px solid #334155; } 
    .modal-header h3{ margin:0; color:#38bdf8; font-size:16px; } 
    .modal-close{ background:transparent; border:0; color:#94a3b8; font-size:20px; cursor:pointer; font-weight:bold; } 
    .modal-body{ padding:20px; max-height:400px; overflow-y:auto; } 
    @media(max-width:600px){ body{ padding:8px; } .search{ width:100%; } }
  </style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>Ultimate Admin Dashboard V5</h1>
      <small id="refreshStatus">Loading dashboard...</small>
    </div>
    <div style="display:flex; gap:8px; align-items:center;">
      <button onclick="manualRefresh()" class="btn refresh-btn">Refresh</button>
      <form method="POST" action="/logout" style="margin:0;">
        <input type="hidden" name="_csrf" value="${escapeHtml(res.locals.csrfToken)}">
        <button class="btn logout-btn" type="submit">Logout</button>
      </form>
    </div>
  </div>

  <div class="card">
    <form class="filters" id="filterForm">
      <input class="search" id="search" name="search" value="${escapeHtml(search)}" placeholder="Search nickname or device ID...">
      <select id="filter" name="filter">
        <option value="all" ${filter === "all" ? "selected" : ""}>All Time</option>
        <option value="today" ${filter === "today" ? "selected" : ""}>Today (IST)</option>
        <option value="7d" ${filter === "7d" ? "selected" : ""}>Last 7 Days</option>
        <option value="30d" ${filter === "30d" ? "selected" : ""}>Last 30 Days</option>
        <option value="custom" ${filter === "custom" ? "selected" : ""}>Custom Range</option>
      </select>
      <input type="date" id="from" name="from" value="${escapeHtml(customFrom)}">
      <input type="date" id="to" name="to" value="${escapeHtml(customTo)}">
      <button class="btn refresh-btn" type="submit">Apply</button>
    </form>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-title">Total Devices</div><div class="stat-value" id="totalDevices">-</div></div>
    <div class="stat"><div class="stat-title">Approved</div><div class="stat-value" id="approved">-</div></div>
    <div class="stat"><div class="stat-title">Pending</div><div class="stat-value" id="pending">-</div></div>
    <div class="stat"><div class="stat-title">Blocked</div><div class="stat-value" id="blocked">-</div></div>
    <div class="stat"><div class="stat-title">Online Now</div><div class="stat-value" id="online">-</div></div>
    <div class="stat"><div class="stat-title">Usage</div><div class="stat-value" id="totalUsage">-</div></div>
  </div>

  <div class="card chart-card">
    <h2>Daily Usage Trend</h2>
    <div style="height:290px;"><canvas id="usageChart"></canvas></div>
  </div>

  <div class="card">
    <h2>Device Permission Manager</h2>
    <table>
      <thead>
        <tr>
          <th>Nickname</th>
          <th>Device ID</th>
          <th>Permission</th>
          <th>Live</th>
          <th>Usage</th>
          <th>Registered</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="deviceTable">
        <tr><td colspan="7" style="text-align:center;">Loading...</td></tr>
      </tbody>
    </table>

    <div class="pagination">
      <button id="prevPage">Previous</button>
      <span id="pageInfo">Page -</span>
      <button id="nextPage">Next</button>
    </div>
  </div>
</div>

<!-- HISTORY MODAL -->
<div class="modal-overlay" id="historyModal">
  <div class="modal">
    <div class="modal-header">
      <h3 id="modalTitle">Session History</h3>
      <button class="modal-close" onclick="closeModal()">✕</button>
    </div>
    <div class="modal-body">
      <table>
        <thead>
          <tr>
            <th>Started (IST)</th>
            <th>Last Seen / Stopped</th>
            <th>Duration</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody id="historyTableBody">
          <tr><td colspan="4" style="text-align:center;">Loading history...</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<script>
const csrfToken = "${escapeHtml(res.locals.csrfToken)}";
let currentPage = ${page};
let chartInstance = null;
let refreshTimer = null;
let isEditing = false;
let refreshInProgress = false;
const refreshStatus = document.getElementById("refreshStatus");

/* ===================================================== ESCAPE HTML ===================================================== */
function escapeHTML(value){ 
  return String(value ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;"); 
}

/* ===================================================== DASHBOARD REFRESH ===================================================== */
async function refreshDashboard(){
  if(refreshInProgress){ return; }
  if(isEditing){ refreshStatus.innerText = "Refresh paused while editing"; refreshStatus.style.color = "#fbbf24"; return; }
  refreshInProgress = true;
  clearTimeout(refreshTimer);
  try{
    refreshStatus.innerText = "Refreshing..."; refreshStatus.style.color = "#38bdf8";
    const params = new URLSearchParams();
    params.set("search", document.getElementById("search").value);
    params.set("filter", document.getElementById("filter").value);
    params.set("from", document.getElementById("from").value);
    params.set("to", document.getElementById("to").value);
    params.set("page", currentPage);
    
    const response = await fetch("/api/dashboard?" + params.toString(), { credentials:"same-origin", cache:"no-store" });
    if(response.status === 401){ window.location.href = "/login"; return; }
    if(!response.ok){ throw new Error("Dashboard request failed"); }
    
    const data = await response.json();
    if(!data.success){ throw new Error("Dashboard API error"); }
    
    updateStats(data.stats);
    updateChart(data.chart);
    updateTable(data.devices);
    updatePagination(data.pagination);
    
    refreshStatus.innerText = "Auto-refresh active"; refreshStatus.style.color = "#4ade80";
  } catch(error) {
    console.error(error); refreshStatus.innerText = "Refresh failed"; refreshStatus.style.color = "#f87171";
  } finally {
    refreshInProgress = false; scheduleRefresh();
  }
}

/* ===================================================== MANUAL REFRESH ===================================================== */
function manualRefresh(){ isEditing = false; refreshDashboard(); }

/* ===================================================== STATS ===================================================== */
function updateStats(stats){
  document.getElementById("totalDevices").innerText = stats.totalDevices;
  document.getElementById("approved").innerText = stats.approved;
  document.getElementById("pending").innerText = stats.pending;
  document.getElementById("blocked").innerText = stats.blocked;
  document.getElementById("online").innerText = stats.online;
  document.getElementById("totalUsage").innerText = stats.totalUsage;
}

/* ===================================================== CHART ===================================================== */
function updateChart(chart){
  const canvas = document.getElementById("usageChart");
  if(chartInstance){ chartInstance.destroy(); }
  chartInstance = new Chart(canvas, {
    type:"line",
    data:{
      labels: chart.labels,
      datasets:[{ label:"Usage Minutes", data: chart.data, borderWidth:2, tension:.3, fill:true, borderColor:"#38bdf8", backgroundColor: "rgba(56,189,248,.12)" }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{ labels:{ color:"#e2e8f0" } } },
      scales:{
        x:{ ticks:{ color:"#94a3b8" }, grid:{ color:"#334155" } },
        y:{ beginAtZero:true, ticks:{ color:"#94a3b8" }, grid:{ color:"#334155" } }
      }
    }
  });
}

/* ===================================================== DEVICE TABLE ===================================================== */
function updateTable(devices){
  const tbody = document.getElementById("deviceTable");
  if(!devices.length){ tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:20px;">No devices found.</td></tr>'; return; }
  
  tbody.innerHTML = devices.map(function(device){
    const permission = escapeHTML(device.status);
    const liveClass = device.online ? "online" : "offline";
    const liveText = device.online ? "ONLINE" : "OFFLINE";
    const deviceId = escapeHTML(device.deviceId);
    const nickname = escapeHTML(device.nickname);
    
    let actionButtons = '<button class="btn history-btn" type="button" data-history="' + deviceId + '" data-nickname="' + nickname + '">History</button>';
    
    if(device.status !== "approved"){
      actionButtons += '<form method="POST" action="/action/approve"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><button class="btn approve" type="submit">Approve</button></form>';
    } else {
      actionButtons += '<form method="POST" action="/action/block"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><button class="btn block" type="submit">Block</button></form>';
    }
    
    if(device.status !== "pending"){
      actionButtons += '<form method="POST" action="/action/pending"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><button class="btn pending-btn" type="submit">Pending</button></form>';
    }
    
    actionButtons += '<form method="POST" action="/action/delete" onsubmit="return confirm(\\'Delete this device permanently?\\');"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><button class="btn delete-btn" type="submit">Delete</button></form>';
    
    return '<tr><td><form method="POST" action="/action/nickname" style="display:flex;gap:5px;"><input type="hidden" name="_csrf" value="' + csrfToken + '"><input type="hidden" name="deviceId" value="' + deviceId + '"><input class="nickname-input" name="nickname" value="' + nickname + '" placeholder="Nickname" maxlength="50"><button class="btn refresh-btn" type="submit">Save</button></form></td><td><code>' + deviceId + '</code></td><td><span class="badge ' + permission + '">' + permission.toUpperCase() + '</span></td><td><span class="badge ' + liveClass + '">' + liveText + '</span></td><td><strong>' + escapeHTML(device.usage) + '</strong><br><small>' + Number(device.sessions) + ' sessions</small></td><td>' + escapeHTML(device.registeredAt) + '</td><td class="action-cell">' + actionButtons + '</td></tr>';
  }).join("");
  
  document.querySelectorAll("[data-history]").forEach(function(button){
    button.addEventListener("click", function(){ openHistory(button.getAttribute("data-history"), button.getAttribute("data-nickname")); });
  });
}

/* ===================================================== HISTORY ===================================================== */
async function openHistory(deviceId, nickname){
  const modal = document.getElementById("historyModal");
  const modalTitle = document.getElementById("modalTitle");
  const tableBody = document.getElementById("historyTableBody");
  
  modalTitle.innerText = "History: " + (nickname || deviceId);
  tableBody.innerHTML = '<tr><td colspan="4" style="text-align:center;">Fetching records...</td></tr>';
  modal.style.display = "flex";
  
  try{
    const response = await fetch("/api/sessions/" + encodeURIComponent(deviceId), { credentials:"same-origin", cache:"no-store" });
    if(response.status === 401){ window.location.href = "/login"; return; }
    const data = await response.json();
    if(!data.success || !data.sessions.length){ tableBody.innerHTML = '<tr><td colspan="4" style="text-align:center;">No sessions recorded yet.</td></tr>'; return; }
    
    tableBody.innerHTML = data.sessions.map(function(item){
      const statusClass = item.status === "online" ? "online" : "offline";
      return '<tr><td>' + escapeHTML(item.startTime) + '</td><td>' + escapeHTML(item.lastSeenTime) + '</td><td><strong>' + escapeHTML(item.duration) + '</strong></td><td><span class="badge ' + statusClass + '">' + escapeHTML(String(item.status).toUpperCase()) + '</span></td></tr>';
    }).join("");
  } catch(error) {
    console.error(error); tableBody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#f87171;">Failed to load history.</td></tr>';
  }
}

function closeModal(){ document.getElementById("historyModal").style.display = "none"; }
window.addEventListener("click", function(event){ const modal = document.getElementById("historyModal"); if(event.target === modal){ closeModal(); } });

/* ===================================================== PAGINATION ===================================================== */
function updatePagination(pagination){
  currentPage = pagination.page;
  document.getElementById("pageInfo").innerText = "Page " + pagination.page + " of " + pagination.totalPages;
  document.getElementById("prevPage").disabled = pagination.page <= 1;
  document.getElementById("nextPage").disabled = pagination.page >= pagination.totalPages;
}

/* ===================================================== AUTO REFRESH ===================================================== */
function scheduleRefresh(){
  clearTimeout(refreshTimer);
  if(isEditing){ refreshStatus.innerText = "Refresh paused while editing"; refreshStatus.style.color = "#fbbf24"; return; }
  refreshTimer = setTimeout(function(){ refreshDashboard(); }, ${DASHBOARD_REFRESH_SECONDS * 1000});
}

/* Only search/filter controls pause refresh. */
document.querySelectorAll("#filterForm input, #filterForm select").forEach(function(element){
  element.addEventListener("focus", function(){ isEditing = true; clearTimeout(refreshTimer); refreshStatus.innerText = "Refresh paused while editing"; refreshStatus.style.color = "#fbbf24"; });
  element.addEventListener("blur", function(){ setTimeout(function(){ const active = document.activeElement; const stillEditing = active && active.closest && active.closest("#filterForm"); isEditing = Boolean(stillEditing); if(!isEditing){ scheduleRefresh(); } }, 100); });
});

document.getElementById("filterForm").addEventListener("submit", function(event){ event.preventDefault(); currentPage = 1; isEditing = false; refreshDashboard(); });
document.getElementById("filter").addEventListener("change", function(){ currentPage = 1; });
document.getElementById("prevPage").addEventListener("click", function(){ if(currentPage > 1){ currentPage--; refreshDashboard(); } });
document.getElementById("nextPage").addEventListener("click", function(){ currentPage++; refreshDashboard(); });

document.addEventListener("visibilitychange", function(){ if(document.hidden){ clearTimeout(refreshTimer); } else { scheduleRefresh(); } });

/* Initial load. */
refreshDashboard();
</script>
</body>
</html>
  `);
});

/* =========================================================
START SERVER
========================================================= */
async function startServer() {
  try {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 10000 });
    console.log("MongoDB CONNECTED");
    
    /* Ensure indexes exist. */
    await Promise.all([Device.init(), UsageSession.init()]);
    console.log("MongoDB indexes ready");
    
    app.listen(PORT, () => {
      console.log("Ultimate Admin Dashboard V5 running on port " + PORT);
    });
  } catch (err) {
    console.error("FATAL MongoDB startup error:", err.message);
    process.exit(1);
  }
}

startServer();
