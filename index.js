const express = require("express");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 3000;

const REDIRECT_URL = "https://wa.me/918099188409?text=Hello%20Developer,%20please%20activate%20my%20app";
const MONGO_URI = process.env.MONGO_URI;

// 🔒 ADMIN CREDENTIALS (Ise apne hisaab se change kar lein)
const ADMIN_USER = "admin";
const ADMIN_PASS = "12345";

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
});

/* =========================
   SECURITY MIDDLEWARE (Lock Dashboard)
========================= */
app.use((req, res, next) => {
    // App tracking ko password free rakhein
    if (req.path === "/index.php" || req.path === "/track") return next();

    // Baaki sab (Dashboard & Actions) ke liye password mangein
    const b64auth = (req.headers.authorization || '').split(' ')[1] || '';
    const [login, password] = Buffer.from(b64auth, 'base64').toString().split(':');

    if (login === ADMIN_USER && password === ADMIN_PASS) {
        return next();
    }

    res.set('WWW-Authenticate', 'Basic realm="Admin Panel"');
    res.status(401).send('Authentication required. Enter Username and Password.');
});

/* =========================
   DATABASE SCHEMAS
========================= */
const DeviceSchema = new mongoose.Schema({
    deviceId: { type: String, required: true, unique: true, index: true },
    status: { type: String, enum: ["pending", "approved", "blocked"], default: "pending" },
    registeredAt: { type: Date, default: Date.now }
});

const SessionSchema = new mongoose.Schema({
    deviceId: { type: String, required: true, index: true },
    startTime: Date,
    lastSeenTime: Date,
    startTimestamp: Number,
    lastSeenTimestamp: Number,
    status: { type: String, enum: ["online", "offline"], default: "online" }
});

const Device = mongoose.model("Device", DeviceSchema);
const Session = mongoose.model("Session", SessionSchema);

if (!MONGO_URI) {
    console.error("MONGO_URI IS MISSING");
} else {
    mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 10000 })
        .then(() => console.log("MongoDB CONNECTED"))
        .catch(err => console.error("MongoDB CONNECTION FAILED:", err.message));
}

/* =========================
   HELPERS
========================= */
function formatDuration(ms) {
    if (!Number.isFinite(ms) || ms < 0) return "0s";
    const totalSeconds = Math.floor(ms / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    let result = "";
    if (hours > 0) result += `${hours}h `;
    if (minutes > 0) result += `${minutes}m `;
    result += `${seconds}s`;
    return result;
}

function safeDate(val) {
    if (!val) return "N/A";
    const d = new Date(val);
    if (isNaN(d.getTime())) return String(val);
    return d.toLocaleString("en-IN", { timeZone: "Asia/Kolkata" });
}

function escapeHtml(value) {
    return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

/* =========================
   TRACKING ENDPOINT (Public for App)
========================= */
app.get(["/index.php", "/track"], async (req, res) => {
    const deviceId = String(req.query.id || "").trim();
    const action = String(req.query.action || "start").trim();

    if (!deviceId) return res.status(400).json({ status: "ERROR" });

    try {
        let device = await Device.findOne({ deviceId });

        if (!device) {
            device = await Device.create({ deviceId, status: "pending", registeredAt: new Date() });
            return res.status(200).json({ status: "BLOCKED", redirectUrl: REDIRECT_URL });
        }

        if (device.status !== "approved") {
            await Session.updateMany({ deviceId, status: "online" }, { $set: { status: "offline" } });
            return res.status(200).json({ status: "BLOCKED", redirectUrl: REDIRECT_URL });
        }

        const now = Date.now();
        let session = await Session.findOne({ deviceId, status: "online" }).sort({ startTimestamp: -1 });

        if (action === "start" || !session) {
            if (session) {
                session.status = "offline";
                await session.save();
            }
            await Session.create({
                deviceId, startTime: new Date(now), lastSeenTime: new Date(now),
                startTimestamp: now, lastSeenTimestamp: now, status: "online"
            });
        } else {
            session.lastSeenTimestamp = now;
            session.lastSeenTime = new Date(now);
            await session.save();
        }

        return res.status(200).json({ status: "ALLOWED" });
    } catch (err) {
        return res.status(500).json({ status: "ERROR" });
    }
});

/* =========================
   ADMIN ACTIONS (Protected)
========================= */
app.post("/toggle-device", async (req, res) => {
    const deviceId = String(req.body.deviceId || "").trim();
    if (deviceId) {
        try {
            const device = await Device.findOne({ deviceId });
            if (device) {
                device.status = device.status === "approved" ? "blocked" : "approved";
                await device.save();
                if (device.status === "blocked") {
                    await Session.updateMany({ deviceId, status: "online" }, { $set: { status: "offline" } });
                }
            }
        } catch (err) { console.error(err); }
    }
    res.redirect("/");
});

app.post("/delete-session", async (req, res) => {
    const id = String(req.body.id || "").trim();
    if (id) {
        try { await Session.findByIdAndDelete(id); } catch (err) {}
    }
    res.redirect("/");
});

app.post("/clear-all", async (req, res) => {
    try { await Session.deleteMany({}); } catch (err) {}
    res.redirect("/");
});

/* =========================
   DASHBOARD UI (Protected)
========================= */
app.get("/", async (req, res) => {
    try {
        const cutoff = Date.now() - 25000;
        await Session.updateMany({ status: "online", lastSeenTimestamp: { $lt: cutoff } }, { $set: { status: "offline" } });

        const devices = await Device.find().sort({ registeredAt: -1 }).lean();
        const sessions = await Session.find().sort({ startTimestamp: -1 }).lean();

        const deviceRows = devices.map(d => {
            const approved = d.status === "approved";
            return `
                <tr>
                    <td><code>${escapeHtml(d.deviceId)}</code></td>
                    <td><span class="badge ${approved ? "approved" : "blocked"}">${escapeHtml(d.status.toUpperCase())}</span></td>
                    <td>${safeDate(d.registeredAt)}</td>
                    <td>
                        <form method="POST" action="/toggle-device" style="margin:0;">
                            <input type="hidden" name="deviceId" value="${escapeHtml(d.deviceId)}">
                            <button type="submit" class="btn ${approved ? "block" : "approve"}">
                                ${approved ? "🛑 Block" : "✅ Approve"}
                            </button>
                        </form>
                    </td>
                </tr>`;
        }).join("");

        const sessionRows = sessions.map(s => {
            const duration = formatDuration((s.lastSeenTimestamp || s.startTimestamp) - s.startTimestamp);
            return `
                <tr>
                    <td><code>${escapeHtml(s.deviceId)}</code></td>
                    <td><span class="badge ${s.status}">${escapeHtml(s.status.toUpperCase())}</span></td>
                    <td>${safeDate(s.startTime)}</td>
                    <td>${safeDate(s.lastSeenTime)}</td>
                    <td><strong>${duration}</strong></td>
                    <td>
                        <form method="POST" action="/delete-session" style="margin:0;">
                            <input type="hidden" name="id" value="${escapeHtml(String(s._id))}">
                            <button type="submit" class="delete" onclick="return confirm('Delete this record?')">🗑️ Delete</button>
                        </form>
                    </td>
                </tr>`;
        }).join("");

        res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>Admin Dashboard</title>
<style>
* { box-sizing: border-box; font-family: system-ui, sans-serif; }
body { margin: 0; padding: 15px; background: #0f172a; color: #e2e8f0; }
.container { max-width: 1000px; margin: auto; }
.header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
h1 { color: #38bdf8; font-size: 20px; margin: 0; }
h2 { color: #38bdf8; font-size: 15px; margin: 25px 0 10px 0; }
.card { background: #1e293b; padding: 10px; border-radius: 8px; overflow-x: auto; margin-bottom: 15px; }
table { width: 100%; border-collapse: collapse; white-space: nowrap; }
th, td { padding: 10px 12px; border-bottom: 1px solid #334155; text-align: left; font-size: 13px; }
th { background: #0f172a; font-weight: bold; }
.badge { display: inline-block; padding: 4px 6px; border-radius: 4px; font-size: 10px; font-weight: bold; }
.approved, .online { background: #14532d; color: #4ade80; }
.blocked, .pending, .offline { background: #7f1d1d; color: #f87171; }
.btn { border: 0; border-radius: 4px; padding: 8px 12px; color: white; font-weight: bold; cursor: pointer; font-size: 12px; }
.approve { background: #16a34a; }
.block { background: #ea580c; }
.delete { border: 0; background: transparent; color: #f87171; cursor: pointer; font-weight: bold; font-size: 12px; }
.clear-btn { background: #b91c1c; }
.refresh-btn { background: #3b82f6; }
code { background: #0f172a; padding: 3px 6px; border-radius: 4px; color: #94a3b8; font-size: 12px; }
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Admin Control Panel</h1>
        <button class="btn refresh-btn" onclick="window.location.reload()">🔄 Refresh</button>
    </div>
    
    <h2>Device Permission Manager</h2>
    <div class="card">
        <table>
            <thead><tr><th>Device ID</th><th>Status</th><th>Registered</th><th>Action</th></tr></thead>
            <tbody>${deviceRows || `<tr><td colspan="4">No devices.</td></tr>`}</tbody>
        </table>
    </div>

    <h2>Session History</h2>
    <div class="card">
        <table>
            <thead><tr><th>Device ID</th><th>Status</th><th>Start</th><th>Last Seen</th><th>Duration</th><th>Action</th></tr></thead>
            <tbody>${sessionRows || `<tr><td colspan="6">No sessions.</td></tr>`}</tbody>
        </table>
    </div>
    
    <div style="margin-top:20px;">
        <form method="POST" action="/clear-all">
            <button type="submit" class="btn clear-btn" onclick="return confirm('Clear ALL?')">🗑️ Clear All History</button>
        </form>
    </div>
</div>
</body>
</html>`);
    } catch (err) { res.status(500).send("Error"); }
});

app.listen(PORT, () => console.log(`Server live on port ${PORT}`));
