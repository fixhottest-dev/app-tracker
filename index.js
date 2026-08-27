const express = require('express');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;

const REDIRECT_URL =
    'https://wa.me/918099188409?text=Hello%20Developer,%20please%20activate%20my%20app';

const MONGO_URI = process.env.MONGO_URI;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

/* =========================
   DATABASE
========================= */

if (!MONGO_URI) {
    console.error('CRITICAL: MONGO_URI is not configured');
} else {
    mongoose.connect(MONGO_URI)
        .then(() => console.log('MongoDB connected'))
        .catch(err => console.error('MongoDB connection error:', err));
}

/* =========================
   DEVICE
========================= */

const DeviceSchema = new mongoose.Schema({
    deviceId: {
        type: String,
        required: true,
        unique: true,
        index: true
    },

    status: {
        type: String,
        enum: ['pending', 'approved', 'blocked'],
        default: 'pending'
    },

    registeredAt: {
        type: String
    }
});

const Device = mongoose.model('Device', DeviceSchema);

/* =========================
   SESSION
========================= */

const SessionSchema = new mongoose.Schema({
    deviceId: {
        type: String,
        required: true,
        index: true
    },

    startTime: String,
    lastSeenTime: String,
    endTime: String,

    startTimestamp: Number,
    lastSeenTimestamp: Number,
    endTimestamp: Number,

    status: {
        type: String,
        enum: ['online', 'offline'],
        default: 'online'
    }
});

const Session = mongoose.model('Session', SessionSchema);

/* =========================
   HELPERS
========================= */

function getIndiaTime(timestamp = Date.now()) {
    return new Date(timestamp).toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata'
    });
}

function formatDuration(ms) {
    if (!ms || ms < 0) return '0s';

    const totalSeconds = Math.floor(ms / 1000);

    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;

    let result = '';

    if (hours) result += `${hours}h `;
    if (minutes) result += `${minutes}m `;

    result += `${seconds}s`;

    return result;
}

/* =========================
   DEVICE / SESSION API
========================= */

app.get(['/','/index.php','/track'], async (req, res) => {

    const deviceId = String(req.query.id || '').trim();
    const action = String(req.query.action || 'start').trim();

    if (!deviceId) {
        return res.status(400).json({
            status: 'ERROR',
            message: 'Missing device ID'
        });
    }

    const now = Date.now();
    const time = getIndiaTime(now);

    try {

        /* -------------------------
           FIND / REGISTER DEVICE
        ------------------------- */

        let device = await Device.findOne({ deviceId });

        if (!device) {
            device = await Device.create({
                deviceId,
                status: 'pending',
                registeredAt: time
            });
        }

        /* -------------------------
           BLOCK UNAPPROVED DEVICE
        ------------------------- */

        if (device.status !== 'approved') {

            return res.status(200).json({
                status: 'BLOCKED',
                redirectUrl: REDIRECT_URL
            });
        }

        /* -------------------------
           APPROVED DEVICE
        ------------------------- */

        let session = await Session.findOne({
            deviceId,
            status: 'online'
        }).sort({
            startTimestamp: -1
        });

        /* START */

        if (action === 'start') {

            // Close an old online session if one exists
            if (session) {
                session.status = 'offline';
                session.endTimestamp = now;
                session.endTime = time;

                await session.save();
            }

            session = await Session.create({
                deviceId,
                startTime: time,
                lastSeenTime: time,
                startTimestamp: now,
                lastSeenTimestamp: now,
                status: 'online'
            });

            return res.status(200).json({
                status: 'ALLOWED',
                action: 'start'
            });
        }

        /* PING */

        if (action === 'ping') {

            if (!session) {

                session = await Session.create({
                    deviceId,
                    startTime: time,
                    lastSeenTime: time,
                    startTimestamp: now,
                    lastSeenTimestamp: now,
                    status: 'online'
                });

            } else {

                session.lastSeenTimestamp = now;
                session.lastSeenTime = time;

                await session.save();
            }

            return res.status(200).json({
                status: 'ALLOWED',
                action: 'ping'
            });
        }

        /* STOP */

        if (action === 'stop') {

            if (session) {

                session.status = 'offline';
                session.endTimestamp = now;
                session.endTime = time;
                session.lastSeenTimestamp = now;
                session.lastSeenTime = time;

                await session.save();
            }

            return res.status(200).json({
                status: 'ALLOWED',
                action: 'stop'
            });
        }

        /* UNKNOWN ACTION */

        return res.status(400).json({
            status: 'ERROR',
            message: 'Unknown action'
        });

    } catch (error) {

        console.error('Tracking error:', error);

        return res.status(500).json({
            status: 'ERROR',
            message: 'Server error'
        });
    }
});

/* =========================
   AUTOMATIC OFFLINE CHECK
========================= */

setInterval(async () => {

    try {

        const now = Date.now();
        const timeout = 25000;

        const sessions = await Session.find({
            status: 'online'
        });

        for (const session of sessions) {

            if (
                session.lastSeenTimestamp &&
                now - session.lastSeenTimestamp > timeout
            ) {

                session.status = 'offline';
                session.endTimestamp = session.lastSeenTimestamp;
                session.endTime = session.lastSeenTime;

                await session.save();

                console.log(
                    `Device offline: ${session.deviceId}`
                );
            }
        }

    } catch (error) {

        console.error('Offline checker error:', error);
    }

}, 10000);

/* =========================
   APPROVE / BLOCK DEVICE
========================= */

app.post('/toggle-device', async (req, res) => {

    const deviceId = String(req.body.deviceId || '').trim();

    if (!deviceId) {
        return res.redirect('/');
    }

    try {

        const device = await Device.findOne({ deviceId });

        if (device) {

            device.status =
                device.status === 'approved'
                    ? 'blocked'
                    : 'approved';

            await device.save();

            /* If blocked while online,
               close active sessions */

            if (device.status === 'blocked') {

                const now = Date.now();
                const time = getIndiaTime(now);

                await Session.updateMany(
                    {
                        deviceId,
                        status: 'online'
                    },
                    {
                        $set: {
                            status: 'offline',
                            endTimestamp: now,
                            endTime: time
                        }
                    }
                );
            }
        }

    } catch (error) {

        console.error('Toggle error:', error);
    }

    res.redirect('/');
});

/* =========================
   DELETE SESSION
========================= */

app.post('/delete', async (req, res) => {

    const id = req.body.id;

    if (id) {

        try {
            await Session.findByIdAndDelete(id);
        } catch (error) {
            console.error('Delete error:', error);
        }
    }

    res.redirect('/');
});

/* =========================
   CLEAR HISTORY
========================= */

app.post('/clear-all', async (req, res) => {

    try {

        await Session.deleteMany({});

    } catch (error) {

        console.error('Clear error:', error);
    }

    res.redirect('/');
});

/* =========================
   DASHBOARD
========================= */

app.get('/dashboard', async (req, res) => {

    try {

        const devices = await Device
            .find()
            .sort({ _id: -1 });

        const sessions = await Session
            .find()
            .sort({ startTimestamp: -1 });

        const deviceRows = devices.map(device => {

            const approved = device.status === 'approved';

            return `
                <tr>
                    <td><code>${device.deviceId}</code></td>

                    <td>
                        <span class="badge ${approved ? 'online' : 'offline'}">
                            ${device.status.toUpperCase()}
                        </span>
                    </td>

                    <td>${device.registeredAt || '-'}</td>

                    <td>
                        <form method="POST" action="/toggle-device">
                            <input
                                type="hidden"
                                name="deviceId"
                                value="${device.deviceId}"
                            >

                            <button class="action-btn ${approved ? 'block-btn' : 'approve-btn'}">
                                ${approved ? 'Block Access' : 'Approve Device'}
                            </button>
                        </form>
                    </td>
                </tr>
            `;
        }).join('');

        const sessionRows = sessions.map(session => {

            const end =
                session.endTimestamp ||
                session.lastSeenTimestamp ||
                session.startTimestamp;

            const duration =
                formatDuration(end - session.startTimestamp);

            return `
                <tr>

                    <td>
                        <code>${session.deviceId}</code>
                    </td>

                    <td>
                        <span class="badge ${session.status}">
                            ${session.status.toUpperCase()}
                        </span>
                    </td>

                    <td>${session.startTime || '-'}</td>

                    <td>${session.lastSeenTime || '-'}</td>

                    <td>${session.endTime || '-'}</td>

                    <td>
                        <strong>${duration}</strong>
                    </td>

                    <td>
                        <form method="POST" action="/delete">
                            <input
                                type="hidden"
                                name="id"
                                value="${session._id}"
                            >

                            <button class="del-btn">
                                Delete
                            </button>
                        </form>
                    </td>

                </tr>
            `;
        }).join('');

        res.send(`
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>Device Control</title>

<style>

body {
    background:#0f172a;
    color:#e2e8f0;
    font-family:system-ui;
    padding:20px;
}

.container {
    max-width:1200px;
    margin:auto;
}

.card {
    background:#1e293b;
    padding:15px;
    border-radius:10px;
    margin-bottom:25px;
    overflow:auto;
}

h1,h2 {
    color:#38bdf8;
}

h2 {
    margin:20px 0 10px;
}

table {
    width:100%;
    border-collapse:collapse;
}

th,td {
    padding:10px;
    border-bottom:1px solid #334155;
    text-align:left;
    white-space:nowrap;
}

th {
    color:#38bdf8;
}

.badge {
    padding:4px 8px;
    border-radius:5px;
    font-size:10px;
    font-weight:bold;
}

.online {
    background:#166534;
    color:#4ade80;
}

.offline {
    background:#991b1b;
    color:#f87171;
}

.action-btn {
    border:0;
    padding:6px 12px;
    border-radius:5px;
    font-weight:bold;
    cursor:pointer;
}

.approve-btn {
    background:#16a34a;
    color:white;
}

.block-btn {
    background:#ea580c;
    color:white;
}

.del-btn {
    background:none;
    border:0;
    color:#f87171;
    cursor:pointer;
}

</style>

</head>

<body>

<div class="container">

<h1>Admin Control Panel</h1>

<h2>Device Permission Manager</h2>

<div class="card">

<table>

<thead>
<tr>
<th>Device ID</th>
<th>Status</th>
<th>Registered</th>
<th>Action</th>
</tr>
</thead>

<tbody>

${deviceRows ||
'<tr><td colspan="4">No devices</td></tr>'}

</tbody>

</table>

</div>

<h2>Session History</h2>

<div class="card">

<table>

<thead>
<tr>
<th>Device</th>
<th>Status</th>
<th>Start</th>
<th>Last Seen</th>
<th>End</th>
<th>Duration</th>
<th>Action</th>
</tr>
</thead>

<tbody>

${sessionRows ||
'<tr><td colspan="7">No sessions</td></tr>'}

</tbody>

</table>

</div>

</div>

<script>

setTimeout(() => {
    location.reload();
}, 5000);

</script>

</body>
</html>
        `);

    } catch (error) {

        console.error('Dashboard error:', error);

        res.status(500).send('Database Error');
    }
});

/* =========================
   SERVER
========================= */

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
