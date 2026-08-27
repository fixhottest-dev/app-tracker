const express = require("express");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 3000;

const REDIRECT_URL = "https://wa.me/918099188409?text=Hello%20Developer,%20please%20activate%20my%20app";
const MONGO_URI = process.env.MONGO_URI;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

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
   UTILITY HELPERS
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

async function markInactiveSessions() {
    const cutoff = Date.now() - 25000;
    await Session.updateMany(
        { status: "online", lastSeenTimestamp: { $lt: cutoff } },
        { $set: { status: "offline" } }
    );
}

/* =========================
   APP AUTH / TRACKING API
========================= */
app.get(["/index.php", "/track"], async (req, res) => {
    const deviceId = String(req.query.id || "").trim();
    const action = String(req.query.action || "start").trim();

    if (!deviceId) return res.status(400).json({ status: "ERROR", message: "Missing device ID" });

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
            session = await Session.create({
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
        console.error("TRACKING ERROR:", err);
        return res.status(500).json({ status: "ERROR" });
    }
});

/* =========================
   AJAX ACTION ENDPOINTS
========================= */
app.post("/api/toggle-device", async (req, res) => {
    const deviceId = String(req.body.deviceId || "").trim();
    try {
        const device = await Device.findOne({ deviceId });
        if (device) {
            device.status = device.status === "approved" ? "blocked" : "approved";
            await device.save();
            if (device.status === "blocked") {
                await Session.updateMany({ deviceId, status: "online" }, { $set: { status: "offline" } });
            }
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.post("/api/delete-session", async (req, res) => {
    try {
        await Session.findByIdAndDelete(req.body.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.post("/api/clear-all", async (req, res) => {
    try {
        await Session.deleteMany({});
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

/* =========================
   ULTIMATE DASHBOARD UI
========================= */
app.get("/", async (req, res) => {
    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).send(`<h1 style="color:white;font-family:sans-serif;text-align:center;margin-top:50px;">Database Connecting... Please Refresh.</h1>`);
        }

        await markInactiveSessions();

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
                        <button class="btn ${approved ? "block" : "approve"}" onclick="toggleDevice('${escapeHtml(d.deviceId)}', this)">
                            ${approved ? "Block Device" : "Approve Device"}
                        </button>
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
                        <button class="delete" onclick="deleteSession('${escapeHtml(String(s._id))}', this)">Delete</button>
                    </td>
                </tr>`;
        }).join("");

        res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Control Panel</title>
<style>
* { box-sizing: border-box; font-family: 'Segoe UI', system-ui, sans-serif; }
body { margin: 0; padding: 20px; background: #0f172a; color: #e2e8f0; }
.container { max-width: 1100px; margin: auto; }
h1, h2 { color: #38bdf8; letter-spacing: 0.5px; }
.card { background: #1e293b; padding: 15px; border-radius: 12px; overflow-x: auto; margin-bottom: 25px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 14px 12px; border-bottom: 1px solid #334155; text-align: left; font-size: 14px; }
th { color: #38bdf8; background: #0f172a; font-weight: 600; }
.badge { display: inline-block; padding: 5px 10px; border-radius: 6px; font-size: 11px; font-weight: bold; letter-spacing: 0.5px; }
.approved, .online { background: #14532d; color: #4ade80; border: 1px solid #166534; }
.blocked, .pending, .offline { background: #7f1d1d; color: #f87171; border: 1px solid #991b1b; }
.btn { border: 0; border-radius: 6px; padding: 8px 14px; color: white; font-weight: bold; cursor: pointer; transition: 0.2s; font-size: 13px; }
.btn:active { transform: scale(0.95); }
.approve { background: #16a34a; }
.approve:hover { background: #15803d; }
.block { background: #ea580c; }
.block:hover { background: #c2410c; }
.delete { border: 0; background: transparent; color: #f87171; cursor: pointer; font-weight: bold; font-size: 13px; transition: 0.2s; }
.delete:hover { color: #ef4444; text-decoration: underline; }
.clear-btn { background: #b91c1c; margin-top: 10px; }
.clear-btn:hover { background: #991b1b; }
code { background: #0f172a; padding: 4px 8px; border-radius: 4px; color: #94a3b8; }
</style>
<script>
// SPA Data Fetcher - Ultimate Cache Buster
function refreshTables() {
    fetch(location.pathname + '?_t=' + Date.now(), { cache: "no-store" })
        .then(r => r.text())
        .then(html => {
            const doc = new DOMParser().parseFromString(html, 'text/html');
            const newTbody = doc.querySelectorAll('tbody');
            const oldTbody = document.querySelectorAll('tbody');
            if(newTbody.length === oldTbody.length) {
                oldTbody[0].innerHTML = newTbody[0].innerHTML;
                oldTbody[1].innerHTML = newTbody[1].innerHTML;
            }
        }).catch(console.error);
}

// Action Handler with UI Feedback
function doAction(url, data, btn) {
    if(btn) { btn.innerText = "Wait..."; btn.style.opacity = "0.5"; btn.disabled = true; }
    fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    }).then(res => res.json())
      .then(() => refreshTables())
      .catch(() => alert("Network Error! Try again."));
}

function toggleDevice(id, btn) { doAction('/api/toggle-device', { deviceId: id }, btn); }
function deleteSession(id, btn) { if(confirm('Delete this session record?')) doAction('/api/delete-session', { id: id }, btn); }
function clearAll(btn) { if(confirm('Are you sure you want to delete ALL history?')) doAction('/api/clear-all', {}, btn); }

// Auto-Sync every 4 seconds without page jump
setInterval(refreshTables, 4000);
</script>
</head>
<body>
<div class="container">
    <h1>Admin Control Panel</h1>
    
    <h2>Device Permission Manager</h2>
    <div class="card">
        <table>
            <thead><tr><th>Device ID</th><th>Status</th><th>Registered</th><th>Action</th></tr></thead>
            <tbody>${deviceRows || `<tr><td colspan="4" style="text-align:center;color:#64748b;">No devices registered yet.</td></tr>`}</tbody>
        </table>
    </div>

    <h2>Session History Logs</h2>
    <div class="card">
        <table>
            <thead><tr><th>Device ID</th><th>Status</th><th>Session Start</th><th>Last Seen</th><th>Duration</th><th>Action</th></tr></thead>
            <tbody>${sessionRows || `<tr><td colspan="6" style="text-align:center;color:#64748b;">No active or past sessions.</td></tr>`}</tbody>
        </table>
    </div>
    
    <div style="text-align: right;">
        <button class="btn clear-btn" onclick="clearAll(this)">🗑️ Clear All History</button>
    </div>
</div>
</body>
</html>`);
    } catch (err) {
        console.error("DASHBOARD ERROR:", err);
        res.status(500).send("Dashboard Rendering Error");
    }
});

app.listen(PORT, () => console.log(`Server live on port ${PORT}`));
