const express = require('express');
const mongoose = require('mongoose');
const app = express();
const PORT = process.env.PORT || 3000;

// 1. Apna MongoDB Connection String Yahan Lagayein
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://<username>:<password>@cluster0.mongodb.net/app_tracker?retryWrites=true&w=majority";

mongoose.connect(MONGO_URI)
    .then(() => console.log("MongoDB Connected Successfully"))
    .catch(err => console.error("Mongo DB Connection Error:", err));

// 2. Session Data Schema
const SessionSchema = new mongoose.Schema({
    deviceId: String,
    startTime: String,
    lastSeenTime: String,
    startTimestamp: Number,
    lastSeenTimestamp: Number,
    status: String
});

const Session = mongoose.model('Session', SessionSchema);

function formatDuration(ms) {
    const totalSecs = Math.floor(ms / 1000);
    const hrs = Math.floor(totalSecs / 3600);
    const mins = Math.floor((totalSecs % 3600) / 60);
    const secs = totalSecs % 60;
    let result = '';
    if (hrs > 0) result += `${hrs}h `;
    if (mins > 0) result += `${mins}m `;
    result += `${secs}s`;
    return result || '0s';
}

app.use(express.urlencoded({ extended: true }));

// Tracking API Route
app.get(['/', '/index.php', '/track'], async (req, res) => {
    const deviceId = req.query.id;
    const action = req.query.action;
    const now = Date.now();
    const timeFormatted = new Date(now).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

    // App se Hit Aane Par
    if (deviceId) {
        try {
            let currentSession = await Session.findOne({ deviceId: deviceId, status: 'online' });

            if (action === 'start' || !currentSession) {
                if (currentSession) {
                    currentSession.status = 'offline';
                    await currentSession.save();
                }

                await Session.create({
                    deviceId: deviceId,
                    startTime: timeFormatted,
                    lastSeenTime: timeFormatted,
                    startTimestamp: now,
                    lastSeenTimestamp: now,
                    status: 'online'
                });
            } else {
                currentSession.lastSeenTimestamp = now;
                currentSession.lastSeenTime = timeFormatted;
                await currentSession.save();
            }
        } catch (e) {
            console.error(e);
        }
        return res.status(200).send('OK');
    }

    // Dashboard Fetching
    try {
        let allSessions = await Session.find().sort({ startTimestamp: -1 });

        // Update inactive sessions to offline (>25 seconds)
        for (let s of allSessions) {
            if (s.status === 'online' && (now - s.lastSeenTimestamp > 25000)) {
                s.status = 'offline';
                await Session.updateOne({ _id: s._id }, { status: 'offline' });
            }
        }

        const rowsHtml = allSessions.map(s => {
            const duration = formatDuration(s.lastSeenTimestamp - s.startTimestamp);
            return `
                <tr>
                    <td><code>${s.deviceId}</code></td>
                    <td><span class="badge ${s.status}">${s.status.toUpperCase()}</span></td>
                    <td>${s.startTime}</td>
                    <td>${s.lastSeenTime}</td>
                    <td><strong>${duration}</strong></td>
                    <td><a href="/delete?id=${s._id}" class="del-btn" onclick="return confirm('Is history record ko delete karein?')">Delete</a></td>
                </tr>
            `;
        }).join('');

        res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Permanent Session Tracking</title>
            <style>
                * { box-sizing: border-box; font-family: system-ui, sans-serif; margin: 0; padding: 0; }
                body { background: #0f172a; color: #e2e8f0; padding: 20px; }
                .container { max-width: 1000px; margin: 0 auto; }
                .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
                h1 { color: #38bdf8; font-size: 20px; }
                .card { background: #1e293b; border-radius: 10px; padding: 15px; overflow-x: auto; }
                table { width: 100%; border-collapse: collapse; text-align: left; }
                th, td { padding: 12px; border-bottom: 1px solid #334155; font-size: 13px; }
                th { color: #38bdf8; background: #0f172a; }
                .badge { padding: 4px 8px; border-radius: 6px; font-size: 10px; font-weight: bold; }
                .online { background: #166534; color: #4ade80; }
                .offline { background: #991b1b; color: #f87171; }
                .clear-btn { background: #ef4444; color: #fff; padding: 8px 14px; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 12px; }
                .del-btn { color: #f87171; text-decoration: none; font-size: 12px; font-weight: bold; }
                .del-btn:hover { text-decoration: underline; }
            </style>
            <script>
                // Auto Refresh UI
                setInterval(() => {
                    fetch(location.href)
                        .then(r => r.text())
                        .then(html => {
                            const doc = new DOMParser().parseFromString(html, 'text/html');
                            const newTbody = doc.querySelector('tbody');
                            if (newTbody) document.querySelector('tbody').innerHTML = newTbody.innerHTML;
                        }).catch(() => {});
                }, 4000);
            </script>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Live Session History (Permanent Storage)</h1>
                    <a href="/clear-all" class="clear-btn" onclick="return confirm('Kya aap SARI HISTORY DELETE karna chahte hain?')">Clear All History</a>
                </div>
                <div class="card">
                    <table>
                        <thead>
                            <tr>
                                <th>Device ID</th>
                                <th>Status</th>
                                <th>Session Start</th>
                                <th>Last Seen</th>
                                <th>Duration</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rowsHtml || '<tr><td colspan="6" style="text-align:center; color:#94a3b8;">No history records found.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
        </body>
        </html>
        `);
    } catch (err) {
        res.status(500).send("Database Error");
    }
});

// Delete Single Record
app.get('/delete', async (req, res) => {
    const id = req.query.id;
    if (id) {
        await Session.findByIdAndDelete(id);
    }
    res.redirect('/');
});

// Delete All History
app.get('/clear-all', async (req, res) => {
    await Session.deleteMany({});
    res.redirect('/');
});

app.listen(PORT, () => console.log(`Server live on port ${PORT}`));
