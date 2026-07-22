const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const LOG_FILE = path.join(__dirname, 'sessions_log.json'); // Nayi file taaki purana glitch khatam ho

if (!fs.existsSync(LOG_FILE)) {
    fs.writeFileSync(LOG_FILE, JSON.stringify([]));
}

function formatDuration(seconds) {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    let result = '';
    if (hrs > 0) result += `${hrs}h `;
    if (mins > 0) result += `${mins}m `;
    result += `${secs}s`;
    return result;
}

app.get(['/', '/index.php'], (req, res) => {
    const deviceId = req.query.id;
    const action = req.query.action; // 'start' ya 'ping'

    let sessions = [];
    try {
        sessions = JSON.parse(fs.readFileSync(LOG_FILE, 'utf8'));
        if (!Array.isArray(sessions)) sessions = [];
    } catch (e) {
        sessions = [];
    }

    const nowTimestamp = Date.now();
    const nowReadable = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

    if (deviceId) {
        if (action === 'start') {
            // Naya session turant add karo jab bhi app khule
            sessions.unshift({
                session_id: nowTimestamp.toString(),
                device_id: deviceId,
                start_time: nowReadable,
                last_seen: nowReadable,
                last_timestamp: nowTimestamp,
                duration: 0,
                status: 'online'
            });
        } else {
            // Heartbeat ping jo chal raha hai
            let activeSession = sessions.find(s => s.device_id === deviceId && s.status === 'online');
            if (activeSession) {
                activeSession.last_seen = nowReadable;
                activeSession.last_timestamp = nowTimestamp;
                activeSession.duration += 10; // har 10 sec ping
            } else {
                // Agar session nahi mila toh naya bana do
                sessions.unshift({
                    session_id: nowTimestamp.toString(),
                    device_id: deviceId,
                    start_time: nowReadable,
                    last_seen: nowReadable,
                    last_timestamp: nowTimestamp,
                    duration: 10,
                    status: 'online'
                });
            }
        }

        fs.writeFileSync(LOG_FILE, JSON.stringify(sessions, null, 2));
        return res.send('SUCCESS');
    }

    // Dashboard check: Agar 25 seconds se ping nahi aaya toh OFFLINE mark karo
    sessions.forEach(s => {
        if (s.status === 'online' && (nowTimestamp - s.last_timestamp > 25000)) {
            s.status = 'offline';
        }
    });

    fs.writeFileSync(LOG_FILE, JSON.stringify(sessions, null, 2));

    const rows = sessions.map(s => `
        <tr>
            <td><code>${s.device_id}</code></td>
            <td><span class="badge ${s.status}">${s.status.toUpperCase()}</span></td>
            <td>${s.start_time}</td>
            <td>${s.last_seen}</td>
            <td><strong>${formatDuration(s.duration)}</strong></td>
        </tr>
    `).join('');

    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="refresh" content="5"> <!-- Har 5 second me auto refresh -->
        <title>Admin Session Dashboard</title>
        <style>
            * { box-sizing: border-box; font-family: system-ui, sans-serif; margin: 0; padding: 0; }
            body { background-color: #121212; color: #ffffff; padding: 20px; }
            .container { max-width: 1000px; margin: 0 auto; }
            .header { text-align: center; margin-bottom: 20px; }
            .header h1 { color: #00e676; font-size: 24px; }
            .card { background-color: #1e1e1e; border-radius: 12px; padding: 15px; overflow-x: auto; }
            table { width: 100%; border-collapse: collapse; text-align: left; }
            th, td { padding: 12px 15px; border-bottom: 1px solid #2c2c2c; }
            th { background-color: #272727; color: #00e676; font-size: 12px; text-transform: uppercase; }
            .badge { padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; }
            .online { background-color: rgba(0, 230, 118, 0.2); color: #00e676; border: 1px solid #00e676; }
            .offline { background-color: rgba(255, 82, 82, 0.2); color: #ff5252; border: 1px solid #ff5252; }
            .btn { background-color: #00e676; color: #121212; border: none; padding: 8px 16px; border-radius: 6px; font-weight: bold; cursor: pointer; float: right; margin-bottom: 15px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><h1>Multiple Sessions Log Dashboard</h1></div>
            <button class="btn" onclick="location.reload()">Refresh Data</button>
            <div class="card">
                <table>
                    <thead>
                        <tr>
                            <th>Device ID</th>
                            <th>Status</th>
                            <th>Session Start Time</th>
                            <th>Last Seen</th>
                            <th>Duration</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rows || '<tr><td colspan="5" style="text-align:center; color:#888;">No session records found.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    `;

    res.send(html);
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
