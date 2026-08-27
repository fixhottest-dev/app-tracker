const express = require("express");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 3000;

const REDIRECT_URL =
  "https://wa.me/918099188409?text=Hello%20Developer,%20please%20activate%20my%20app";

const MONGO_URI = process.env.MONGO_URI;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

/* =========================
   DATABASE
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

// Ye function purane "Invalid Date" issue ko theek karega
function safeDate(val) {
    if (!val) return "N/A";
    const d = new Date(val);
    if (isNaN(d.getTime())) return String(val); // Agar purana string format hai toh waise hi dikha do
    return d.toLocaleString("en-IN", { timeZone: "Asia/Kolkata" });
}

async function markInactiveSessions() {
    const cutoff = Date.now() - 25000;
    await Session.updateMany(
        { status: "online", lastSeenTimestamp: { $lt: cutoff } },
        { $set: { status: "offline" } }
    );
}

/* =========================
   APP AUTH / TRACKING
========================= */

app.get(["/index.php", "/track"], async (req, res) => {
    const deviceId = String(req.query.id || "").trim();
    const action = String(req.query.action || "start").trim();

    if (!deviceId) return res.status(400).json({ status: "ERROR", message: "Missing device ID" });

    try {
        let device = await Device.findOne({ deviceId });

        if (!device) {
            device = await Device.create({
                deviceId, status: "pending", registeredAt: new Date()
            });
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
   DASHBOARD
========================= */

app.get("/", async (req, res) => {
    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).send(`<h1>Server OK</h1><p>MongoDB is not connected.</p>`);
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
                        <form method="POST" action="/toggle-device" style="margin:0;">
                            <input type="hidden" name="deviceId" value="${escapeHtml(d.deviceId)}">
                            <button class="btn ${approved ? "block" : "approve"}" type="submit">
                                ${approved ? "Block Device" : "Approve Device"}
                            </button>
                        </form>
                    </td>
                </tr>
            `;
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
                        <form method="POST" action="/delete" style="margin:0;">
                            <input type="hidden" name="id" value="${escapeHtml(String(s._id))}">
                            <button class="delete" type="submit">Delete</button>
                        </form>
                    </td>
                </tr>
            `;
        }).join("");

        res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Control Panel</title>
<style>
* { box-sizing: border-box; font-family: system-ui, sans-serif; }
body { margin: 0; padding: 20px; background: #0f172a; color: #e2e8f0; }
.container { max-width: 1100px; margin: auto; }
h1, h2 { color: #38bdf8; }
.card { background: #1e293b; padding: 15px; border-radius: 10px; overflow-x: auto; margin-bottom: 25px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 12px; border-bottom: 1px solid #334155; text-align: left; font-size: 13px; }
th { color: #38bdf8; background: #0f172a; }
.badge { display: inline-block; padding: 4px 8px; border-radius: 6px; font-size: 10px; font-weight: bold; }
.approved, .online { background: #14532d; color: #4ade80; }
.blocked, .pending, .offline { background: #7f1d1d; color: #f87171; }
.btn { border: 0; border-radius: 6px; padding: 7px 12px; color: white; font-weight: bold; cursor: pointer; }
.approve { background: #16a34a; }
.block { background: #ea580c; }
.delete { border: 0; background: transparent; color: #f87171; cursor: pointer; font-weight: bold; }
</style>
<script>
// Smart refresh: Sirf table update hogi, poora page load nahi hoga, jisse button work karega!
setInterval(() => {
    fetch(location.href)
        .then(r => r.text())
        .then(html => {
            const doc = new DOMParser().parseFromString(html, 'text/html');
            const newBodies = doc.querySelectorAll('tbody');
            const oldBodies = document.querySelectorAll('tbody');
            if(newBodies.length === oldBodies.length) {
                oldBodies[0].innerHTML = newBodies[0].innerHTML;
                oldBodies[1].innerHTML = newBodies[1].innerHTML;
            }
        }).catch(() => {});
}, 4000);
</script>
</head>
<body>
<div class="container">
<h1>Admin Control Panel</h1>
<h2>Device Permission Manager</h2>
<div class="card">
<table>
<thead><tr><th>Device ID</th><th>Status</th><th>Registered</th><th>Action</th></tr></thead>
<tbody>${deviceRows || `<tr><td colspan="4">No devices registered.</td></tr>`}</tbody>
</table>
</div>
<h2>Session History</h2>
<div class="card">
<table>
<thead><tr><th>Device ID</th><th>Status</th><th>Start</th><th>Last Seen</th><th>Duration</th><th>Action</th></tr></thead>
<tbody>${sessionRows || `<tr><td colspan="6">No sessions.</td></tr>`}</tbody>
</table>
</div>
<form method="POST" action="/clear-all" style="margin-top:20px;">
<button class="btn block" type="submit" onclick="return confirm('Delete all history?')">Clear All History</button>
</form>
</div>
</body>
</html>
        `);
    } catch (err) {
        console.error("DASHBOARD ERROR:", err);
        res.status(500).send("Dashboard Error");
    }
});

/* =========================
   ACTIONS
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
        } catch (err) {}
    }
    res.redirect("/");
});

app.post("/delete", async (req, res) => {
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

function escapeHtml(value) {
    return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
