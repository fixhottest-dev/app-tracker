"use strict";

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();

/* =========================================================
   ULTIMATE ADMIN DASHBOARD V6
   SINGLE-FILE PRODUCTION SERVER
========================================================= */

/* =========================================================
   CONFIGURATION
========================================================= */

const PORT = Number(process.env.PORT || 3000);
const MONGO_URI = process.env.MONGO_URI;

const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || "admin");
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";

const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PRODUCTION = NODE_ENV === "production";

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  (!IS_PRODUCTION ? crypto.randomBytes(48).toString("hex") : "");

const REDIRECT_URL =
  process.env.REDIRECT_URL ||
  "https://wa.me/918099188409?text=Hello%20Developer,%20please%20activate%20my%20app";

/*
Heartbeat architecture:

Client:
START
  ↓
PING every 15 seconds
  ↓
STOP when lifecycle stops

Server:
Last heartbeat < timeout = ONLINE

Last heartbeat >= timeout = OFFLINE
Session closes automatically.
*/

const ONLINE_TIMEOUT_MS = Number(
  process.env.ONLINE_TIMEOUT_MS || 45000
);

const CLEANUP_INTERVAL_MS = Number(
  process.env.CLEANUP_INTERVAL_MS || 15000
);

const DASHBOARD_REFRESH_SECONDS = 15;

const DEVICES_PER_PAGE = 20;

const MAX_DEVICE_ID_LENGTH = 200;
const MAX_NICKNAME_LENGTH = 50;
const MAX_SEARCH_LENGTH = 100;

const ADMIN_SESSION_MAX_AGE = 24 * 60 * 60 * 1000;

/* =========================================================
   HARD FAIL CONFIG CHECKS
========================================================= */

if (!MONGO_URI) {
  console.error("FATAL: MONGO_URI is missing.");
  process.exit(1);
}

if (!ADMIN_PASSWORD && !ADMIN_PASSWORD_HASH) {
  console.error(
    "FATAL: ADMIN_PASSWORD or ADMIN_PASSWORD_HASH is required."
  );
  process.exit(1);
}

if (IS_PRODUCTION && !SESSION_SECRET) {
  console.error(
    "FATAL: SESSION_SECRET is required in production."
  );
  process.exit(1);
}

/* =========================================================
   EXPRESS
========================================================= */

app.set("trust proxy", 1);

app.disable("x-powered-by");

app.use(
  express.urlencoded({
    extended: true,
    limit: "100kb"
  })
);

app.use(
  express.json({
    limit: "100kb"
  })
);

/* =========================================================
   SECURITY HEADERS
========================================================= */

app.use((req, res, next) => {
  res.setHeader(
    "X-Content-Type-Options",
    "nosniff"
  );

  res.setHeader(
    "X-Frame-Options",
    "DENY"
  );

  res.setHeader(
    "Referrer-Policy",
    "same-origin"
  );

  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, private"
  );

  res.setHeader(
    "Pragma",
    "no-cache"
  );

  res.setHeader(
    "Expires",
    "0"
  );

  next();
});

/* =========================================================
   SESSION
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

      ttl: ADMIN_SESSION_MAX_AGE / 1000,

      autoRemove: "native"
    }),

    cookie: {
      httpOnly: true,

      secure: IS_PRODUCTION,

      sameSite: "lax",

      maxAge: ADMIN_SESSION_MAX_AGE
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

  message: "Too many login attempts. Try again later."
});

const trackingLimiter = rateLimit({
  windowMs: 60 * 1000,

  max: 300,

  standardHeaders: true,

  legacyHeaders: false,

  message: {
    status: "ERROR",
    message: "RATE_LIMITED"
  }
});

/* =========================================================
   DATABASE SCHEMAS
========================================================= */

const DeviceSchema = new mongoose.Schema(
  {
    deviceId: {
      type: String,
      required: true,
      unique: true,
      index: true,
      trim: true,
      maxlength: MAX_DEVICE_ID_LENGTH
    },

    nickname: {
      type: String,
      default: "",
      trim: true,
      maxlength: MAX_NICKNAME_LENGTH
    },

    status: {
      type: String,

      enum: [
        "pending",
        "approved",
        "blocked"
      ],

      default: "pending",

      index: true
    },

    registeredAt: {
      type: Date,

      default: Date.now,

      index: true
    }
  },

  {
    versionKey: false
  }
);

/*
SESSION MODEL

Server owns all timestamps.

startTime:
when session started

lastSeenTime:
latest heartbeat

endTime:
final session end

status:
online/offline

endReason:
stop
timeout
blocked
pending
deleted
*/

const SessionSchema = new mongoose.Schema(
  {
    deviceId: {
      type: String,
      required: true,
      index: true,
      maxlength: MAX_DEVICE_ID_LENGTH
    },

    startTime: {
      type: Date,
      required: true,
      index: true
    },

    lastSeenTime: {
      type: Date,
      required: true,
      index: true
    },

    endTime: {
      type: Date,
      default: null
    },

    startTimestamp: {
      type: Number,
      required: true,
      index: true
    },

    lastSeenTimestamp: {
      type: Number,
      required: true,
      index: true
    },

    endTimestamp: {
      type: Number,
      default: null,
      index: true
    },

    durationMs: {
      type: Number,
      default: 0
    },

    status: {
      type: String,

      enum: [
        "online",
        "offline"
      ],

      default: "online",

      index: true
    },

    endReason: {
      type: String,

      enum: [
        "stop",
        "timeout",
        "blocked",
        "pending",
        "deleted",
        null
      ],

      default: null
    }
  },

  {
    versionKey: false
  }
);

/*
FAST HISTORY
*/

SessionSchema.index({
  deviceId: 1,
  startTimestamp: -1
});

/*
STALE CLEANUP
*/

SessionSchema.index({
  status: 1,
  lastSeenTimestamp: 1
});

/*
ONLY ONE ONLINE SESSION PER DEVICE
*/

SessionSchema.index(
  {
    deviceId: 1
  },

  {
    unique: true,

    partialFilterExpression: {
      status: "online"
    },

    name: "unique_online_session_per_device"
  }
);

const Device = mongoose.model(
  "Device",
  DeviceSchema
);

const UsageSession = mongoose.model(
  "UsageSession",
  SessionSchema
);

/* =========================================================
   DATABASE EVENTS
========================================================= */

mongoose.connection.on(
  "error",
  (err) => {
    console.error(
      "MongoDB Error:",
      err.message
    );
  }
);

mongoose.connection.on(
  "disconnected",
  () => {
    console.warn(
      "MongoDB DISCONNECTED"
    );
  }
);

mongoose.connection.on(
  "connected",
  () => {
    console.log(
      "MongoDB CONNECTED"
    );
  }
);

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

function safeString(value, maxLength) {
  return String(value || "")
    .trim()
    .substring(0, maxLength);
}

function formatDuration(ms) {
  const safeMs = Number(ms);

  if (
    !Number.isFinite(safeMs) ||
    safeMs <= 0
  ) {
    return "0s";
  }

  const totalSeconds = Math.floor(
    safeMs / 1000
  );

  const days = Math.floor(
    totalSeconds / 86400
  );

  const hours = Math.floor(
    (totalSeconds % 86400) / 3600
  );

  const minutes = Math.floor(
    (totalSeconds % 3600) / 60
  );

  const seconds =
    totalSeconds % 60;

  const parts = [];

  if (days > 0) {
    parts.push(days + "d");
  }

  if (hours > 0) {
    parts.push(hours + "h");
  }

  if (minutes > 0) {
    parts.push(minutes + "m");
  }

  if (
    seconds > 0 ||
    parts.length === 0
  ) {
    parts.push(seconds + "s");
  }

  return parts.join(" ");
}

function safeDate(value) {
  if (!value) {
    return "N/A";
  }

  const date = new Date(value);

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return String(value);
  }

  return date.toLocaleString(
    "en-IN",
    {
      timeZone: "Asia/Kolkata",

      dateStyle: "medium",

      timeStyle: "medium",

      hour12: true
    }
  );
}

function getISTStartOfDay() {
  const now = new Date();

  const formatter =
    new Intl.DateTimeFormat(
      "en-CA",
      {
        timeZone: "Asia/Kolkata",

        year: "numeric",

        month: "2-digit",

        day: "2-digit"
      }
    );

  const parts =
    formatter.formatToParts(now);

  const values = {};

  parts.forEach((part) => {
    if (
      part.type !== "literal"
    ) {
      values[part.type] =
        part.value;
    }
  });

  return Date.UTC(
    Number(values.year),

    Number(values.month) - 1,

    Number(values.day),

    0,

    0,

    0
  ) - (5.5 * 60 * 60 * 1000);
}

function getRange(
  filter,
  customFrom,
  customTo
) {
  const now = Date.now();

  let from = null;

  let to = now;

  if (filter === "today") {
    from = getISTStartOfDay();
  }

  if (filter === "7d") {
    from =
      now -
      7 * 24 * 60 * 60 * 1000;
  }

  if (filter === "30d") {
    from =
      now -
      30 * 24 * 60 * 60 * 1000;
  }

  if (filter === "custom") {
    if (customFrom) {
      const parsed =
        new Date(
          customFrom +
          "T00:00:00+05:30"
        );

      if (
        !Number.isNaN(
          parsed.getTime()
        )
      ) {
        from =
          parsed.getTime();
      }
    }

    if (customTo) {
      const parsed =
        new Date(
          customTo +
          "T23:59:59.999+05:30"
        );

      if (
        !Number.isNaN(
          parsed.getTime()
        )
      ) {
        to =
          parsed.getTime();
      }
    }
  }

  if (
    from !== null &&
    from > to
  ) {
    const temp = from;

    from = to;

    to = temp;
  }

  return {
    from,
    to
  };
}

/* =========================================================
   CSRF
========================================================= */

function csrfProtection(
  req,
  res,
  next
) {
  if (!req.session) {
    return res
      .status(500)
      .send(
        "Session unavailable."
      );
  }

  const method =
    req.method.toUpperCase();

  const protectedMethod =
    method === "POST" ||
    method === "PUT" ||
    method === "PATCH" ||
    method === "DELETE";

  if (!req.session.csrfToken) {
    req.session.csrfToken =
      crypto
        .randomBytes(32)
        .toString("hex");
  }

  res.locals.csrfToken =
    req.session.csrfToken;

  if (protectedMethod) {
    const token =
      req.body?._csrf ||
      req.get("x-csrf-token");

    if (
      !token ||
      token !==
      req.session.csrfToken
    ) {
      return res
        .status(403)
        .send(
          "CSRF validation failed."
        );
    }
  }

  next();
}

/* =========================================================
   AUTH
========================================================= */

function requireLogin(
  req,
  res,
  next
) {
  if (
    req.session &&
    req.session.adminAuthenticated === true
  ) {
    return next();
  }

  return res.redirect(
    "/login"
  );
}

function requireApiLogin(
  req,
  res,
  next
) {
  if (
    req.session &&
    req.session.adminAuthenticated === true
  ) {
    return next();
  }

  return res.status(401).json({
    success: false,

    error: "UNAUTHORIZED"
  });
}

/* =========================================================
   PASSWORD
========================================================= */

async function verifyPassword(
  password
) {
  if (ADMIN_PASSWORD_HASH) {
    return bcrypt.compare(
      password,
      ADMIN_PASSWORD_HASH
    );
  }

  if (!ADMIN_PASSWORD) {
    return false;
  }

  const input =
    Buffer.from(
      String(password)
    );

  const stored =
    Buffer.from(
      ADMIN_PASSWORD
    );

  if (
    input.length !==
    stored.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    input,
    stored
  );
}

/* =========================================================
   SESSION CLOSE HELPER
========================================================= */

async function closeOnlineSession(
  deviceId,
  reason,
  timestamp
) {
  const now =
    Number(timestamp) ||
    Date.now();

  const nowDate =
    new Date(now);

  return UsageSession.findOneAndUpdate(
    {
      deviceId,
      status: "online"
    },

    {
      $set: {
        status: "offline",

        endReason: reason,

        endTime: nowDate,

        endTimestamp: now,

        lastSeenTime: nowDate,

        lastSeenTimestamp: now
      }
    },

    {
      new: true,

      sort: {
        startTimestamp: -1
      }
    }
  ).then(async (sessionDoc) => {
    if (!sessionDoc) {
      return null;
    }

    const duration =
      Math.max(
        0,
        now -
        Number(
          sessionDoc.startTimestamp
        )
      );

    await UsageSession.updateOne(
      {
        _id:
          sessionDoc._id
      },

      {
        $set: {
          durationMs:
            duration
        }
      }
    );

    return sessionDoc;
  });
}

/* =========================================================
   STALE SESSION CLEANUP
========================================================= */

let cleanupRunning = false;

async function markStaleSessionsOffline() {
  if (cleanupRunning) {
    return;
  }

  cleanupRunning = true;

  try {
    const now =
      Date.now();

    const cutoff =
      now -
      ONLINE_TIMEOUT_MS;

    const staleSessions =
      await UsageSession.find({
        status: "online",

        lastSeenTimestamp: {
          $lt: cutoff
        }
      })
        .select({
          _id: 1,

          startTimestamp: 1,

          lastSeenTimestamp: 1
        })
        .lean();

    if (
      !staleSessions.length
    ) {
      return;
    }

    const operations =
      staleSessions.map(
        (item) => {
          /*
          Session ends at last heartbeat,
          not cleanup time.

          This prevents artificial extra
          duration from cleanup delay.
          */

          const endTimestamp =
            Number(
              item.lastSeenTimestamp
            );

          const duration =
            Math.max(
              0,
              endTimestamp -
              Number(
                item.startTimestamp
              )
            );

          return {
            updateOne: {
              filter: {
                _id: item._id,

                status: "online"
              },

              update: {
                $set: {
                  status:
                    "offline",

                  endReason:
                    "timeout",

                  endTime:
                    new Date(
                      endTimestamp
                    ),

                  endTimestamp,

                  durationMs:
                    duration
                }
              }
            }
          };
        }
      );

    if (
      operations.length
    ) {
      await UsageSession.bulkWrite(
        operations,
        {
          ordered: false
        }
      );
    }
  } catch (err) {
    console.error(
      "Stale cleanup error:",
      err.message
    );
  } finally {
    cleanupRunning = false;
  }
}

const cleanupInterval =
  setInterval(
    markStaleSessionsOffline,
    CLEANUP_INTERVAL_MS
  );

cleanupInterval.unref();

/* =========================================================
   LOGIN PAGE
========================================================= */

app.get(
  "/login",
  csrfProtection,
  (
    req,
    res
  ) => {
    if (
      req.session &&
      req.session.adminAuthenticated
    ) {
      return res.redirect("/");
    }

    res.send(`
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>Administrator Login</title>

<style>

*{
box-sizing:border-box;
font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}

body{
margin:0;
min-height:100vh;
display:flex;
align-items:center;
justify-content:center;
background:#f3f4f6;
color:#111827;
padding:20px;
}

.login-card{
width:100%;
max-width:420px;
background:#ffffff;
border:1px solid #e5e7eb;
border-radius:12px;
padding:32px;
box-shadow:
0 10px 30px
rgba(0,0,0,.08);
}

.logo{
width:44px;
height:44px;
border-radius:10px;
background:#111827;
color:white;
display:flex;
align-items:center;
justify-content:center;
font-weight:800;
margin-bottom:20px;
}

h1{
font-size:24px;
margin:0 0 8px;
}

p{
color:#6b7280;
font-size:14px;
margin:0 0 24px;
}

label{
display:block;
font-size:13px;
font-weight:600;
margin:14px 0 6px;
}

input{
width:100%;
padding:12px;
border:1px solid #d1d5db;
border-radius:8px;
font-size:14px;
outline:none;
}

input:focus{
border-color:#374151;
box-shadow:
0 0 0 3px
rgba(55,65,81,.1);
}

button{
width:100%;
margin-top:20px;
padding:12px;
border:0;
border-radius:8px;
background:#111827;
color:white;
font-weight:600;
cursor:pointer;
}

button:hover{
background:#000;
}

.error{
background:#fef2f2;
color:#b91c1c;
border:1px solid #fecaca;
padding:10px;
border-radius:7px;
font-size:13px;
margin-bottom:15px;
}

.footer{
margin-top:22px;
font-size:11px;
color:#9ca3af;
text-align:center;
}

</style>

</head>

<body>

<div class="login-card">

<div class="logo">
A
</div>

<h1>
Administrator Login
</h1>

<p>
Sign in to access the device management console.
</p>

${
req.query.error
? `
<div class="error">
Invalid username or password.
</div>
`
: ""
}

<form
method="POST"
action="/login"
>

<input
type="hidden"
name="_csrf"
value="${escapeHtml(res.locals.csrfToken)}"
>

<label>
Username
</label>

<input
type="text"
name="username"
autocomplete="username"
required
>

<label>
Password
</label>

<input
type="password"
name="password"
autocomplete="current-password"
required
>

<button type="submit">
Sign In
</button>

</form>

<div class="footer">
Secure administrator console
</div>

</div>

</body>
</html>
`);
  }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/login",

  loginLimiter,

  csrfProtection,

  async (
    req,
    res
  ) => {
    try {
      const username =
        safeString(
          req.body.username,
          100
        );

      const password =
        String(
          req.body.password || ""
        );

      if (
        username !==
        ADMIN_USERNAME
      ) {
        return res.redirect(
          "/login?error=1"
        );
      }

      const valid =
        await verifyPassword(
          password
        );

      if (!valid) {
        return res.redirect(
          "/login?error=1"
        );
      }

      req.session.regenerate(
        (err) => {
          if (err) {
            console.error(
              "Session regenerate error:",
              err.message
            );

            return res.redirect(
              "/login?error=1"
            );
          }

          req.session.adminAuthenticated =
            true;

          req.session.adminUsername =
            ADMIN_USERNAME;

          req.session.csrfToken =
            crypto
              .randomBytes(32)
              .toString("hex");

          req.session.save(
            (saveErr) => {
              if (saveErr) {
                console.error(
                  "Session save error:",
                  saveErr.message
                );

                return res.redirect(
                  "/login?error=1"
                );
              }

              return res.redirect(
                "/"
              );
            }
          );
        }
      );
    } catch (err) {
      console.error(
        "Login error:",
        err.message
      );

      return res.redirect(
        "/login?error=1"
      );
    }
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/logout",

  requireLogin,

  csrfProtection,

  (
    req,
    res
  ) => {
    req.session.destroy(
      () => {
        res.clearCookie(
          "admin.sid"
        );

        res.redirect(
          "/login"
        );
      }
    );
  }
);

/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/health",
  (
    req,
    res
  ) => {
    const connected =
      mongoose.connection.readyState === 1;

    res
      .status(
        connected
          ? 200
          : 503
      )
      .json({
        server:
          "online",

        database:
          connected
            ? "connected"
            : "disconnected",

        timestamp:
          new Date().toISOString()
      });
  }
);

/* =========================================================
   PUBLIC DEVICE TRACKING
========================================================= */

async function handleTracking(
  req,
  res
) {
  const deviceId =
    safeString(
      req.query.id ||
      req.body?.id,

      MAX_DEVICE_ID_LENGTH
    );

  let rawAction =
    String(
      req.query.action ||
      req.body?.action ||
      req.query.status ||
      req.body?.status ||
      "start"
    )
      .trim()
      .toLowerCase();

  if (
    rawAction === "offline"
  ) {
    rawAction =
      "stop";
  }

  const action =
    [
      "start",
      "ping",
      "stop"
    ].includes(rawAction)
      ? rawAction
      : "start";

  if (!deviceId) {
    return res
      .status(400)
      .json({
        status:
          "ERROR",

        message:
          "DEVICE_ID_MISSING"
      });
  }

  if (
    mongoose.connection.readyState !== 1
  ) {
    return res
      .status(503)
      .json({
        status:
          "ERROR",

        message:
          "DATABASE_OFFLINE"
      });
  }

  try {

    /*
    Find/create device.
    */

    let device =
      await Device.findOne({
        deviceId
      });

    if (!device) {
      try {
        device =
          await Device.create({
            deviceId,

            status:
              "pending",

            registeredAt:
              new Date()
          });
      } catch (err) {
        if (
          err &&
          err.code === 11000
        ) {
          device =
            await Device.findOne({
              deviceId
            });
        } else {
          throw err;
        }
      }
    }

    /*
    Not approved = close any active
    session and block app.
    */

    if (
      !device ||
      device.status !==
      "approved"
    ) {
      await closeOnlineSession(
        deviceId,

        device &&
        device.status ===
        "blocked"
          ? "blocked"
          : "pending",

        Date.now()
      );

      return res.json({
        status:
          "BLOCKED",

        redirectUrl:
          REDIRECT_URL
      });
    }

    const now =
      Date.now();

    const nowDate =
      new Date(now);

    /*
    STOP
    */

    if (
      action === "stop"
    ) {
      const stopped =
        await closeOnlineSession(
          deviceId,

          "stop",

          now
        );

      return res.json({
        status:
          "ALLOWED",

        action:
          stopped
            ? "STOPPED"
            : "NO_ACTIVE_SESSION"
      });
    }

    /*
    START/PING:

    First check if online session exists.
    */

    let activeSession =
      await UsageSession.findOne({
        deviceId,

        status:
          "online"
      });

    if (activeSession) {

      /*
      Update heartbeat.
      */

      activeSession.lastSeenTime =
        nowDate;

      activeSession.lastSeenTimestamp =
        now;

      await activeSession.save();

      return res.json({
        status:
          "ALLOWED",

        action:
          "HEARTBEAT"
      });
    }

    /*
    No active session.

    Create new session.

    Race condition handled by
    unique partial index.
    */

    try {

      activeSession =
        await UsageSession.create({
          deviceId,

          startTime:
            nowDate,

          lastSeenTime:
            nowDate,

          startTimestamp:
            now,

          lastSeenTimestamp:
            now,

          status:
            "online"
        });

    } catch (err) {

      if (
        err &&
        err.code === 11000
      ) {

        activeSession =
          await UsageSession.findOneAndUpdate(
            {
              deviceId,

              status:
                "online"
            },

            {
              $set: {
                lastSeenTime:
                  nowDate,

                lastSeenTimestamp:
                  now
              }
            },

            {
              new: true
            }
          );

      } else {
        throw err;
      }
    }

    return res.json({
      status:
        "ALLOWED",

      action:
        "STARTED",

      sessionId:
        activeSession
          ? String(
              activeSession._id
            )
          : null
    });

  } catch (err) {

    console.error(
      "Tracking error:",
      err.message
    );

    return res
      .status(500)
      .json({
        status:
          "ERROR",

        message:
          "TRACKING_FAILED"
      });
  }
}

app.get(
  [
    "/track",
    "/index.php"
  ],

  trackingLimiter,

  handleTracking
);

app.post(
  [
    "/track",
    "/index.php"
  ],

  trackingLimiter,

  handleTracking
);

/* =========================================================
   ADMIN ACTIONS
========================================================= */

app.post(
  "/action/:type",

  requireLogin,

  csrfProtection,

  async (
    req,
    res
  ) => {

    const type =
      String(
        req.params.type || ""
      );

    const deviceId =
      safeString(
        req.body.deviceId,
        MAX_DEVICE_ID_LENGTH
      );

    if (!deviceId) {
      return res.redirect(
        req.get("referer") ||
        "/"
      );
    }

    try {

      if (
        type === "nickname"
      ) {

        const nickname =
          safeString(
            req.body.nickname,
            MAX_NICKNAME_LENGTH
          );

        await Device.updateOne(
          {
            deviceId
          },

          {
            $set: {
              nickname
            }
          }
        );
      }

      if (
        type === "approve"
      ) {

        await Device.updateOne(
          {
            deviceId
          },

          {
            $set: {
              status:
                "approved"
            }
          }
        );
      }

      if (
        type === "pending"
      ) {

        await Device.updateOne(
          {
            deviceId
          },

          {
            $set: {
              status:
                "pending"
            }
          }
        );

        await closeOnlineSession(
          deviceId,

          "pending",

          Date.now()
        );
      }

      if (
        type === "block"
      ) {

        await Device.updateOne(
          {
            deviceId
          },

          {
            $set: {
              status:
                "blocked"
            }
          }
        );

        await closeOnlineSession(
          deviceId,

          "blocked",

          Date.now()
        );
      }

      if (
        type === "delete"
      ) {

        await Promise.all([
          Device.deleteOne({
            deviceId
          }),

          UsageSession.deleteMany({
            deviceId
          })
        ]);
      }

    } catch (err) {

      console.error(
        "Admin action error:",
        err.message
      );
    }

    return res.redirect(
      req.get("referer") ||
      "/"
    );
  }
);

/* =========================================================
   SESSION HISTORY API
========================================================= */

app.get(
  "/api/sessions/:deviceId",

  requireApiLogin,

  async (
    req,
    res
  ) => {

    try {

      const deviceId =
        safeString(
          req.params.deviceId,
          MAX_DEVICE_ID_LENGTH
        );

      if (!deviceId) {
        return res
          .status(400)
          .json({
            success:
              false,

            error:
              "DEVICE_ID_REQUIRED"
          });
      }

      await markStaleSessionsOffline();

      const sessions =
        await UsageSession.find({
          deviceId
        })
          .sort({
            startTimestamp:
              -1
          })
          .limit(200)
          .lean();

      const now =
        Date.now();

      const formatted =
        sessions.map(
          (item) => {

            const start =
              Number(
                item.startTimestamp
              );

            let end =
              Number(
                item.endTimestamp ||
                item.lastSeenTimestamp
              );

            if (
              item.status ===
              "online"
            ) {
              end =
                now;
            }

            const duration =
              item.status ===
              "offline" &&
              Number.isFinite(
                Number(
                  item.durationMs
                )
              ) &&
              Number(
                item.durationMs
              ) > 0
                ? Number(
                    item.durationMs
                  )
                : Math.max(
                    0,
                    end - start
                  );

            return {
              startTime:
                safeDate(
                  item.startTime
                ),

              lastSeenTime:
                safeDate(
                  item.lastSeenTime
                ),

              endTime:
                item.endTime
                  ? safeDate(
                      item.endTime
                    )
                  : item.status ===
                    "online"
                    ? "Currently active"
                    : safeDate(
                        item.lastSeenTime
                      ),

              duration:
                formatDuration(
                  duration
                ),

              durationMs:
                duration,

              status:
                item.status,

              endReason:
                item.endReason ||
                (
                  item.status ===
                  "online"
                    ? "active"
                    : "unknown"
                )
            };
          }
        );

      return res.json({
        success:
          true,

        sessions:
          formatted
      });

    } catch (err) {

      console.error(
        "History API error:",
        err.message
      );

      return res
        .status(500)
        .json({
          success:
            false,

          error:
            "FETCH_FAILED"
        });
    }
  }
);

/* =========================================================
   DASHBOARD API
========================================================= */

app.get(
  "/api/dashboard",

  requireApiLogin,

  async (
    req,
    res
  ) => {

    try {

      await markStaleSessionsOffline();

      const search =
        safeString(
          req.query.search,
          MAX_SEARCH_LENGTH
        );

      const filter =
        String(
          req.query.filter ||
          "all"
        );

      const customFrom =
        String(
          req.query.from ||
          ""
        );

      const customTo =
        String(
          req.query.to ||
          ""
        );

      const requestedPage =
        Math.max(
          1,

          parseInt(
            req.query.page ||
            "1",
            10
          ) || 1
        );

      const range =
        getRange(
          filter,
          customFrom,
          customTo
        );

      const now =
        Date.now();

      /*
      Device search.
      */

      const deviceMatch = {};

      if (search) {

        const escaped =
          search.replace(
            /[.*+?^${}()|[\]\\]/g,
            "\\$&"
          );

        deviceMatch.$or = [
          {
            deviceId: {
              $regex:
                escaped,

              $options:
                "i"
            }
          },

          {
            nickname: {
              $regex:
                escaped,

              $options:
                "i"
            }
          },

          {
            status: {
              $regex:
                escaped,

              $options:
                "i"
            }
          }
        ];
      }

      /*
      Session overlap.

      A session counts if:

      session.start <= range.end
      AND
      session.end >= range.start
      */

      const effectiveEndExpression =
        {
          $cond: [
            {
              $eq: [
                "$status",
                "online"
              ]
            },

            now,

            {
              $ifNull: [
                "$endTimestamp",

                "$lastSeenTimestamp"
              ]
            }
          ]
        };

      const sessionMatch =
        range.from !== null
          ? {
              startTimestamp: {
                $lte:
                  range.to
              },

              $or: [
                {
                  endTimestamp: {
                    $gte:
                      range.from
                  }
                },

                {
                  endTimestamp:
                    null,

                  lastSeenTimestamp: {
                    $gte:
                      range.from
                  }
                },

                {
                  status:
                    "online"
                }
              ]
            }
          : {};

      const durationStartExpression =
        range.from !== null
          ? {
              $max: [
                "$startTimestamp",

                range.from
              ]
            }
          : "$startTimestamp";

      const durationEndExpression =
        range.from !== null
          ? {
              $min: [
                effectiveEndExpression,

                range.to
              ]
            }
          : effectiveEndExpression;

      const usagePipeline = [
        {
          $match:
            sessionMatch
        },

        {
          $project: {
            deviceId:
              1,

            durationStart:
              durationStartExpression,

            durationEnd:
              durationEndExpression
          }
        },

        {
          $project: {
            deviceId:
              1,

            duration: {
              $max: [
                0,

                {
                  $subtract: [
                    "$durationEnd",

                    "$durationStart"
                  ]
                }
              ]
            }
          }
        },

        {
          $group: {
            _id:
              "$deviceId",

            totalUsage: {
              $sum:
                "$duration"
            },

            sessionCount: {
              $sum:
                1
            }
          }
        }
      ];

      const chartPipeline = [
        {
          $match:
            sessionMatch
        },

        {
          $project: {
            day: {
              $dateToString: {
                format:
                  "%Y-%m-%d",

                date:
                  "$startTime",

                timezone:
                  "Asia/Kolkata"
              }
            },

            durationStart:
              durationStartExpression,

            durationEnd:
              durationEndExpression
          }
        },

        {
          $project: {
            day:
              1,

            duration: {
              $max: [
                0,

                {
                  $subtract: [
                    "$durationEnd",

                    "$durationStart"
                  ]
                }
              ]
            }
          }
        },

        {
          $group: {
            _id:
              "$day",

            usage: {
              $sum:
                "$duration"
            }
          }
        },

        {
          $sort: {
            _id:
              1
          }
        }
      ];

      const onlineCutoff =
        now -
        ONLINE_TIMEOUT_MS;

      const skip =
        (
          requestedPage -
          1
        ) *
        DEVICES_PER_PAGE;

      const results =
        await Promise.all([

          Device.aggregate([
            {
              $group: {
                _id:
                  "$status",

                count: {
                  $sum:
                    1
                }
              }
            }
          ]),

          Device.countDocuments(
            deviceMatch
          ),

          Device.find(
            deviceMatch
          )
            .sort({
              registeredAt:
                -1
            })
            .skip(skip)
            .limit(
              DEVICES_PER_PAGE
            )
            .lean(),

          UsageSession.aggregate(
            usagePipeline
          ),

          UsageSession.aggregate(
            chartPipeline
          ),

          UsageSession.find({
            status:
              "online",

            lastSeenTimestamp: {
              $gte:
                onlineCutoff
            }
          })
            .select({
              deviceId:
                1
            })
            .lean()

        ]);

      const deviceStatusStats =
        results[0];

      const totalSearchDevices =
        results[1];

      let devices =
        results[2];

      const usageStats =
        results[3];

      const chartStats =
        results[4];

      const onlineSessions =
        results[5];

      let totalDevices =
        0;

      let approved =
        0;

      let pending =
        0;

      let blocked =
        0;

      deviceStatusStats.forEach(
        (item) => {

          const count =
            Number(
              item.count ||
              0
            );

          totalDevices +=
            count;

          if (
            item._id ===
            "approved"
          ) {
            approved =
              count;
          }

          if (
            item._id ===
            "pending"
          ) {
            pending =
              count;
          }

          if (
            item._id ===
            "blocked"
          ) {
            blocked =
              count;
          }
        }
      );

      const usageMap = {};

      let totalUsage =
        0;

      usageStats.forEach(
        (item) => {

          const usage =
            Number(
              item.totalUsage ||
              0
            );

          usageMap[
            String(item._id)
          ] = {
            totalUsage:
              usage,

            sessionCount:
              Number(
                item.sessionCount ||
                0
              )
          };

          totalUsage +=
            usage;
        }
      );

      const onlineSet =
        new Set(
          onlineSessions.map(
            (item) =>
              String(
                item.deviceId
              )
          )
        );

      const totalPages =
        Math.max(
          1,

          Math.ceil(
            totalSearchDevices /
            DEVICES_PER_PAGE
          )
        );

      const currentPage =
        Math.min(
          requestedPage,
          totalPages
        );

      /*
      Fix invalid page.
      */

      if (
        currentPage !==
        requestedPage
      ) {

        devices =
          await Device.find(
            deviceMatch
          )
            .sort({
              registeredAt:
                -1
            })
            .skip(
              (
                currentPage -
                1
              ) *
              DEVICES_PER_PAGE
            )
            .limit(
              DEVICES_PER_PAGE
            )
            .lean();
      }

      const deviceData =
        devices.map(
          (device) => {

            const stat =
              usageMap[
                String(
                  device.deviceId
                )
              ] || {
                totalUsage:
                  0,

                sessionCount:
                  0
              };

            return {

              deviceId:
                device.deviceId,

              nickname:
                device.nickname ||
                "",

              status:
                device.status,

              registeredAt:
                safeDate(
                  device.registeredAt
                ),

              usage:
                formatDuration(
                  stat.totalUsage
                ),

              sessions:
                stat.sessionCount,

              online:
                onlineSet.has(
                  String(
                    device.deviceId
                  )
                )
            };
          }
        );

      return res.json({

        success:
          true,

        stats: {

          totalDevices,

          approved,

          pending,

          blocked,

          online:
            onlineSet.size,

          totalUsage:
            formatDuration(
              totalUsage
            )
        },

        devices:
          deviceData,

        pagination: {

          page:
            currentPage,

          totalPages,

          totalDevices:
            totalSearchDevices
        },

        chart: {

          labels:
            chartStats.map(
              (item) =>
                item._id
            ),

          data:
            chartStats.map(
              (item) =>
                Math.round(
                  Number(
                    item.usage ||
                    0
                  ) / 60000
                )
            )
        }
      });

    } catch (err) {

      console.error(
        "Dashboard API error:",
        err.message
      );

      return res
        .status(500)
        .json({
          success:
            false,

          error:
            "DASHBOARD_ERROR"
        });
    }
  }
);

/* =========================================================
   MAIN DASHBOARD
========================================================= */

app.get(
  "/",

  requireLogin,

  csrfProtection,

  (
    req,
    res
  ) => {

    res.send(`
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>
Device Management Console
</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

:root{
--bg:#f5f6f8;
--panel:#ffffff;
--border:#e5e7eb;
--text:#111827;
--muted:#6b7280;
--dark:#111827;
--blue:#2563eb;
--green:#15803d;
--orange:#c2410c;
--red:#b91c1c;
--yellow:#a16207;
}

*{
box-sizing:border-box;
font-family:
Inter,
system-ui,
-apple-system,
BlinkMacSystemFont,
"Segoe UI",
sans-serif;
}

body{
margin:0;
background:var(--bg);
color:var(--text);
}

.topbar{
height:64px;
background:#111827;
color:white;
display:flex;
align-items:center;
justify-content:space-between;
padding:0 24px;
}

.brand{
font-size:17px;
font-weight:700;
}

.brand span{
color:#9ca3af;
font-weight:400;
margin-left:8px;
font-size:13px;
}

.top-actions{
display:flex;
gap:8px;
align-items:center;
}

.container{
max-width:1500px;
margin:auto;
padding:24px;
}

.page-title{
margin-bottom:20px;
}

.page-title h1{
font-size:24px;
margin:0 0 4px;
}

.page-title p{
margin:0;
color:var(--muted);
font-size:13px;
}

.card{
background:var(--panel);
border:1px solid var(--border);
border-radius:10px;
margin-bottom:18px;
}

.card-header{
padding:16px 18px;
border-bottom:1px solid var(--border);
font-weight:650;
font-size:14px;
}

.card-body{
padding:18px;
}

.stats{
display:grid;
grid-template-columns:
repeat(
auto-fit,
minmax(180px,1fr)
);
gap:14px;
margin-bottom:18px;
}

.stat{
background:white;
border:1px solid var(--border);
border-radius:10px;
padding:18px;
}

.stat-label{
font-size:12px;
color:var(--muted);
margin-bottom:8px;
}

.stat-value{
font-size:25px;
font-weight:700;
}

.filters{
display:flex;
flex-wrap:wrap;
gap:10px;
align-items:center;
}

input,
select{
padding:9px 11px;
border:1px solid #d1d5db;
border-radius:7px;
background:white;
font-size:13px;
outline:none;
}

input:focus,
select:focus{
border-color:#2563eb;
box-shadow:
0 0 0 3px
rgba(37,99,235,.08);
}

.search{
min-width:260px;
}

.btn{
border:0;
border-radius:7px;
padding:9px 12px;
font-size:12px;
font-weight:600;
cursor:pointer;
text-decoration:none;
display:inline-flex;
align-items:center;
justify-content:center;
gap:5px;
}

.btn-dark{
background:#111827;
color:white;
}

.btn-blue{
background:#2563eb;
color:white;
}

.btn-green{
background:#15803d;
color:white;
}

.btn-orange{
background:#c2410c;
color:white;
}

.btn-yellow{
background:#a16207;
color:white;
}

.btn-red{
background:#b91c1c;
color:white;
}

.btn-purple{
background:#6d28d9;
color:white;
}

.btn-gray{
background:#e5e7eb;
color:#111827;
}

.btn:hover{
opacity:.92;
}

.table-wrap{
overflow-x:auto;
}

table{
width:100%;
border-collapse:collapse;
min-width:1050px;
}

th{
background:#f9fafb;
color:#6b7280;
font-size:11px;
text-transform:uppercase;
letter-spacing:.04em;
font-weight:700;
white-space:nowrap;
}

th,
td{
padding:13px;
border-bottom:1px solid var(--border);
text-align:left;
font-size:13px;
}

td{
vertical-align:middle;
}

code{
font-size:11px;
background:#f3f4f6;
padding:4px 6px;
border-radius:4px;
word-break:break-all;
}

.badge{
display:inline-block;
padding:5px 8px;
border-radius:20px;
font-size:10px;
font-weight:700;
}

.approved{
background:#dcfce7;
color:#166534;
}

.pending{
background:#fef3c7;
color:#92400e;
}

.blocked{
background:#fee2e2;
color:#991b1b;
}

.online{
background:#dcfce7;
color:#166534;
}

.offline{
background:#f3f4f6;
color:#4b5563;
}

.action-cell{
display:flex;
gap:5px;
flex-wrap:wrap;
min-width:300px;
}

.inline-form{
margin:0;
display:inline-flex;
gap:5px;
}

.nickname-input{
width:125px;
padding:7px;
font-size:12px;
}

.chart-wrap{
height:310px;
}

.pagination{
display:flex;
justify-content:center;
align-items:center;
gap:12px;
padding:18px;
}

.pagination button{
border:1px solid #d1d5db;
background:white;
padding:8px 12px;
border-radius:7px;
cursor:pointer;
}

.pagination button:disabled{
opacity:.4;
cursor:not-allowed;
}

.status-line{
font-size:12px;
color:#6b7280;
}

/* MODAL */

.modal-overlay{
display:none;
position:fixed;
inset:0;
background:
rgba(17,24,39,.55);
z-index:9999;
padding:20px;
align-items:center;
justify-content:center;
}

.modal{
width:100%;
max-width:900px;
background:white;
border-radius:12px;
box-shadow:
0 25px 60px
rgba(0,0,0,.25);
overflow:hidden;
}

.modal-header{
display:flex;
justify-content:space-between;
align-items:center;
padding:16px 20px;
border-bottom:1px solid var(--border);
}

.modal-title{
font-size:16px;
font-weight:700;
}

.modal-close{
border:0;
background:transparent;
font-size:24px;
cursor:pointer;
color:#6b7280;
}

.modal-body{
padding:18px;
max-height:65vh;
overflow:auto;
}

@media(max-width:700px){

.topbar{
padding:0 14px;
}

.container{
padding:14px;
}

.brand span{
display:none;
}

.search{
width:100%;
min-width:0;
}

}

</style>

</head>

<body>

<div class="topbar">

<div class="brand">
Device Console
<span>
Administrator Panel
</span>
</div>

<div class="top-actions">

<button
class="btn btn-gray"
onclick="manualRefresh()"
>
Refresh
</button>

<form
method="POST"
action="/logout"
style="margin:0"
>

<input
type="hidden"
name="_csrf"
value="${escapeHtml(res.locals.csrfToken)}"
>

<button
class="btn btn-gray"
type="submit"
>
Logout
</button>

</form>

</div>

</div>

<div class="container">

<div class="page-title">

<h1>
Device Management
</h1>

<p
id="refreshStatus"
class="status-line"
>
Loading dashboard...
</p>

</div>

<div class="card">

<div class="card-body">

<form
id="filterForm"
class="filters"
>

<input
id="search"
class="search"
placeholder="Search device ID, nickname or status"
>

<select
id="filter"
>

<option value="all">
All Time
</option>

<option value="today">
Today (IST)
</option>

<option value="7d">
Last 7 Days
</option>

<option value="30d">
Last 30 Days
</option>

<option value="custom">
Custom Range
</option>

</select>

<input
type="date"
id="from"
>

<input
type="date"
id="to"
>

<button
class="btn btn-blue"
type="submit"
>
Apply Filter
</button>

</form>

</div>

</div>

<div class="stats">

<div class="stat">
<div class="stat-label">
TOTAL DEVICES
</div>
<div
class="stat-value"
id="totalDevices"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
APPROVED
</div>
<div
class="stat-value"
id="approved"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
PENDING
</div>
<div
class="stat-value"
id="pending"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
BLOCKED
</div>
<div
class="stat-value"
id="blocked"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
ONLINE NOW
</div>
<div
class="stat-value"
id="online"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
TOTAL USAGE
</div>
<div
class="stat-value"
id="totalUsage"
>
-
</div>
</div>

</div>

<div class="card">

<div class="card-header">
Usage Trend
</div>

<div class="card-body">

<div class="chart-wrap">
<canvas
id="usageChart"
></canvas>
</div>

</div>

</div>

<div class="card">

<div class="card-header">
Device Permission Manager
</div>

<div class="table-wrap">

<table>

<thead>

<tr>

<th>
Nickname
</th>

<th>
Device ID
</th>

<th>
Permission
</th>

<th>
Live Status
</th>

<th>
Usage
</th>

<th>
Registered
</th>

<th>
Actions
</th>

</tr>

</thead>

<tbody
id="deviceTable"
>

<tr>

<td
colspan="7"
style="text-align:center;padding:25px"
>
Loading devices...
</td>

</tr>

</tbody>

</table>

</div>

<div class="pagination">

<button
id="prevPage"
>
Previous
</button>

<span
id="pageInfo"
>
Page -
</span>

<button
id="nextPage"
>
Next
</button>

</div>

</div>

</div>

<!-- SESSION MODAL -->

<div
class="modal-overlay"
id="historyModal"
>

<div class="modal">

<div class="modal-header">

<div>

<div
class="modal-title"
id="modalTitle"
>
Session History
</div>

</div>

<button
class="modal-close"
onclick="closeModal()"
>
×
</button>

</div>

<div class="modal-body">

<div class="table-wrap">

<table>

<thead>

<tr>

<th>
Started
</th>

<th>
Last Seen
</th>

<th>
Ended
</th>

<th>
Duration
</th>

<th>
Status
</th>

<th>
End Reason
</th>

</tr>

</thead>

<tbody
id="historyTableBody"
>

<tr>

<td
colspan="6"
style="text-align:center"
>
Loading...
</td>

</tr>

</tbody>

</table>

</div>

</div>

</div>

</div>

<script>

const csrfToken =
"${escapeHtml(res.locals.csrfToken)}";

const REFRESH_SECONDS =
${DASHBOARD_REFRESH_SECONDS};

let currentPage = 1;

let chartInstance = null;

let refreshTimer = null;

let refreshInProgress = false;

const refreshStatus =
document.getElementById(
"refreshStatus"
);

function escapeHTML(value){

return String(
value ?? ""
)

.replace(
/&/g,
"&amp;"
)

.replace(
/</g,
"&lt;"
)

.replace(
/>/g,
"&gt;"
)

.replace(
/"/g,
"&quot;"
)

.replace(
/'/g,
"&#039;"
);

}

async function refreshDashboard(){

if(
refreshInProgress
){
return;
}

refreshInProgress =
true;

clearTimeout(
refreshTimer
);

try{

refreshStatus.textContent =
"Refreshing data...";

const params =
new URLSearchParams();

params.set(
"search",
document
.getElementById(
"search"
)
.value
);

params.set(
"filter",
document
.getElementById(
"filter"
)
.value
);

params.set(
"from",
document
.getElementById(
"from"
)
.value
);

params.set(
"to",
document
.getElementById(
"to"
)
.value
);

params.set(
"page",
currentPage
);

const response =
await fetch(
"/api/dashboard?" +
params.toString(),
{
credentials:
"same-origin",

cache:
"no-store"
}
);

if(
response.status === 401
){

window.location.href =
"/login";

return;

}

if(
!response.ok
){

throw new Error(
"Dashboard request failed"
);

}

const data =
await response.json();

if(
!data.success
){

throw new Error(
"Dashboard API error"
);

}

updateStats(
data.stats
);

updateChart(
data.chart
);

updateTable(
data.devices
);

updatePagination(
data.pagination
);

refreshStatus.textContent =
"Last refreshed: " +
new Date()
.toLocaleTimeString(
"en-IN"
);

}catch(error){

console.error(
error
);

refreshStatus.textContent =
"Unable to refresh dashboard.";

}finally{

refreshInProgress =
false;

scheduleRefresh();

}

}

function manualRefresh(){

refreshDashboard();

}

function updateStats(stats){

document
.getElementById(
"totalDevices"
)
.textContent =
stats.totalDevices;

document
.getElementById(
"approved"
)
.textContent =
stats.approved;

document
.getElementById(
"pending"
)
.textContent =
stats.pending;

document
.getElementById(
"blocked"
)
.textContent =
stats.blocked;

document
.getElementById(
"online"
)
.textContent =
stats.online;

document
.getElementById(
"totalUsage"
)
.textContent =
stats.totalUsage;

}

function updateChart(chart){

const canvas =
document.getElementById(
"usageChart"
);

if(
chartInstance
){

chartInstance.destroy();

}

chartInstance =
new Chart(
canvas,
{

type:
"line",

data:{
labels:
chart.labels,

datasets:[
{
label:
"Usage (minutes)",

data:
chart.data,

borderColor:
"#2563eb",

backgroundColor:
"rgba(37,99,235,.08)",

borderWidth:
2,

fill:
true,

tension:
.25
}
]
},

options:{

responsive:
true,

maintainAspectRatio:
false,

plugins:{

legend:{

labels:{

color:
"#374151"

}

}

},

scales:{

x:{

ticks:{

color:
"#6b7280"

},

grid:{

color:
"#f3f4f6"

}

},

y:{

beginAtZero:
true,

ticks:{

color:
"#6b7280"

},

grid:{

color:
"#f3f4f6"

}

}

}

}

}
);

}

function updateTable(devices){

const tbody =
document.getElementById(
"deviceTable"
);

if(
!devices.length
){

tbody.innerHTML =
'<tr><td colspan="7" style="text-align:center;padding:25px">No devices found.</td></tr>';

return;

}

tbody.innerHTML =
devices.map(
function(device){

const deviceId =
escapeHTML(
device.deviceId
);

const nickname =
escapeHTML(
device.nickname
);

const status =
escapeHTML(
device.status
);

const liveClass =
device.online
? "online"
: "offline";

const liveText =
device.online
? "ONLINE"
: "OFFLINE";

let actions =
'<button type="button" class="btn btn-purple" data-history="' +
deviceId +
'" data-nickname="' +
nickname +
'">History</button>';

if(
device.status !==
"approved"
){

actions +=
'<form class="inline-form" method="POST" action="/action/approve">' +

'<input type="hidden" name="_csrf" value="' +
csrfToken +
'">' +

'<input type="hidden" name="deviceId" value="' +
deviceId +
'">' +

'<button class="btn btn-green" type="submit">Approve</button>' +

'</form>';

}

if(
device.status !==
"blocked"
){

actions +=
'<form class="inline-form" method="POST" action="/action/block">' +

'<input type="hidden" name="_csrf" value="' +
csrfToken +
'">' +

'<input type="hidden" name="deviceId" value="' +
deviceId +
'">' +

'<button class="btn btn-orange" type="submit">Block</button>' +

'</form>';

}

if(
device.status !==
"pending"
){

actions +=
'<form class="inline-form" method="POST" action="/action/pending">' +

'<input type="hidden" name="_csrf" value="' +
csrfToken +
'">' +

'<input type="hidden" name="deviceId" value="' +
deviceId +
'">' +

'<button class="btn btn-yellow" type="submit">Pending</button>' +

'</form>';

}

actions +=
'<form class="inline-form" method="POST" action="/action/delete" onsubmit="return confirm(\\'Delete this device and all session history permanently?\\')">' +

'<input type="hidden" name="_csrf" value="' +
csrfToken +
'">' +

'<input type="hidden" name="deviceId" value="' +
deviceId +
'">' +

'<button class="btn btn-red" type="submit">Delete</button>' +

'</form>';

return (

'<tr>' +

'<td>' +

'<form class="inline-form" method="POST" action="/action/nickname">' +

'<input type="hidden" name="_csrf" value="' +
csrfToken +
'">' +

'<input type="hidden" name="deviceId" value="' +
deviceId +
'">' +

'<input class="nickname-input" name="nickname" maxlength="50" placeholder="Nickname" value="' +
nickname +
'">' +

'<button class="btn btn-blue" type="submit">Save</button>' +

'</form>' +

'</td>' +

'<td><code>' +
deviceId +
'</code></td>' +

'<td><span class="badge ' +
status +
'">' +
status.toUpperCase() +
'</span></td>' +

'<td><span class="badge ' +
liveClass +
'">' +
liveText +
'</span></td>' +

'<td><strong>' +
escapeHTML(
device.usage
) +
'</strong><br><span style="font-size:11px;color:#6b7280">' +
Number(
device.sessions
) +
' sessions</span></td>' +

'<td>' +
escapeHTML(
device.registeredAt
) +
'</td>' +

'<td class="action-cell">' +
actions +
'</td>' +

'</tr>'

);

}
).join("");

document
.querySelectorAll(
"[data-history]"
)
.forEach(
function(button){

button.addEventListener(
"click",
function(){

openHistory(
button.getAttribute(
"data-history"
),

button.getAttribute(
"data-nickname"
)

);

}
);

}
);

}

async function openHistory(
deviceId,
nickname
){

const modal =
document.getElementById(
"historyModal"
);

const title =
document.getElementById(
"modalTitle"
);

const body =
document.getElementById(
"historyTableBody"
);

title.textContent =
"Session History — " +
(
nickname ||
deviceId
);

body.innerHTML =
'<tr><td colspan="6" style="text-align:center">Loading session history...</td></tr>';

modal.style.display =
"flex";

try{

const response =
await fetch(
"/api/sessions/" +
encodeURIComponent(
deviceId
),
{
credentials:
"same-origin",

cache:
"no-store"
}
);

if(
response.status ===
401
){

window.location.href =
"/login";

return;

}

const data =
await response.json();

if(
!data.success ||
!data.sessions.length
){

body.innerHTML =
'<tr><td colspan="6" style="text-align:center">No session history available.</td></tr>';

return;

}

body.innerHTML =
data.sessions.map(
function(item){

const statusClass =
item.status ===
"online"
? "online"
: "offline";

return (

'<tr>' +

'<td>' +
escapeHTML(
item.startTime
) +
'</td>' +

'<td>' +
escapeHTML(
item.lastSeenTime
) +
'</td>' +

'<td>' +
escapeHTML(
item.endTime
) +
'</td>' +

'<td><strong>' +
escapeHTML(
item.duration
) +
'</strong></td>' +

'<td><span class="badge ' +
statusClass +
'">' +
escapeHTML(
String(
item.status
).toUpperCase()
) +
'</span></td>' +

'<td>' +
escapeHTML(
item.endReason
) +
'</td>' +

'</tr>'

);

}
).join("");

}catch(error){

console.error(
error
);

body.innerHTML =
'<tr><td colspan="6" style="text-align:center;color:#b91c1c">Failed to load session history.</td></tr>';

}

}

function closeModal(){

document
.getElementById(
"historyModal"
)
.style.display =
"none";

}

window.addEventListener(
"click",
function(event){

const modal =
document.getElementById(
"historyModal"
);

if(
event.target ===
modal
){

closeModal();

}

}
);

function updatePagination(
pagination
){

currentPage =
pagination.page;

document
.getElementById(
"pageInfo"
)
.textContent =
"Page " +
pagination.page +
" of " +
pagination.totalPages;

document
.getElementById(
"prevPage"
)
.disabled =
pagination.page <=
1;

document
.getElementById(
"nextPage"
)
.disabled =
pagination.page >=
pagination.totalPages;

}

function scheduleRefresh(){

clearTimeout(
refreshTimer
);

if(
document.hidden
){
return;
}

refreshTimer =
setTimeout(
refreshDashboard,
REFRESH_SECONDS *
1000
);

}

document
.getElementById(
"filterForm"
)
.addEventListener(
"submit",
function(event){

event.preventDefault();

currentPage =
1;

refreshDashboard();

}
);

document
.getElementById(
"prevPage"
)
.addEventListener(
"click",
function(){

if(
currentPage >
1
){

currentPage--;

refreshDashboard();

}

}
);

document
.getElementById(
"nextPage"
)
.addEventListener(
"click",
function(){

currentPage++;

refreshDashboard();

}
);

document.addEventListener(
"visibilitychange",
function(){

if(
document.hidden
){

clearTimeout(
refreshTimer
);

}else{

scheduleRefresh();

}

}
);

refreshDashboard();

</script>

</body>

</html>
`);
  }
);

/* =========================================================
   404
========================================================= */

app.use(
  (
    req,
    res
  ) => {
    res
      .status(404)
      .send(
        "404 Not Found"
      );
  }
);

/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

let server = null;

async function shutdown(
  signal
) {

  console.log(
    signal +
    " received. Shutting down..."
  );

  clearInterval(
    cleanupInterval
  );

  try {

    if (server) {

      await new Promise(
        (resolve) => {
          server.close(
            resolve
          );
        }
      );

    }

    await mongoose.disconnect();

    console.log(
      "Shutdown complete."
    );

    process.exit(0);

  } catch (err) {

    console.error(
      "Shutdown error:",
      err.message
    );

    process.exit(1);

  }
}

process.on(
  "SIGTERM",
  () => shutdown("SIGTERM")
);

process.on(
  "SIGINT",
  () => shutdown("SIGINT")
);

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {

  try {

    await mongoose.connect(
      MONGO_URI,
      {

        serverSelectionTimeoutMS:
          10000,

        socketTimeoutMS:
          45000
      }
    );

    await Promise.all([

      Device.init(),

      UsageSession.init()

    ]);

    console.log(
      "MongoDB indexes ready"
    );

    server =
      app.listen(
        PORT,
        () => {

          console.log(
            "V6 Device Console running on port " +
            PORT
          );

          console.log(
            "Online timeout: " +
            ONLINE_TIMEOUT_MS +
            "ms"
          );

        }
      );

  } catch (err) {

    console.error(
      "FATAL STARTUP ERROR:",
      err.message
    );

    process.exit(1);

  }
}

startServer();