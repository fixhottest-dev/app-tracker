const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const LOG_FILE = path.join(__dirname, 'log_data.json');

if (!fs.existsSync(LOG_FILE)) {
    fs.writeFileSync(LOG_FILE, JSON.stringify({}));
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
    const status = req.query.status;
    const duration = parseInt(req.query.duration || '0', 10);

    let logs = {};
    try {
        logs = JSON.parse(fs.readFileSync(LOG_FILE, 'utf8'));
    } catch (e) {
        logs = {};
    }

    const nowTimestamp = Date.now();
    const nowReadable = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

    // Handle Tracking Hits
    if (deviceId && status) {
        const previousDuration = logs[deviceId]?.total_seconds || 0;

        logs[deviceId] = {
            device_id: deviceId,
            status: status, // online / offline from app
            last_seen: nowReadable,
            last_timestamp: nowTimestamp,
            total_seconds: previousDuration + duration
        };

        fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
        return res.send('SUCCESS');
    }

    // Render Dashboard & Auto-Detect Offline Status
    const rows = Object.values(logs).map(user => {
        // Agar 2 minutes (120000 ms) se zyada time ho gaya request aaye, toh automatic OFFLINE kar do
        const isExpired = user.last_timestamp && (nowTimestamp - user.last_timestamp > 120000);
        const displayStatus = isExpired ? 'offline' : user.status;

        return `
            <tr>
                <td><code>${user.device_id}</code></td>
                <td><span class="badge ${displayStatus}">${displayStatus.toUpperCase()}</span></td>
                <td>${user.last_seen}</td>
                <td><strong>${formatDuration(user.total_seconds)}</strong></td>
            </tr>
        `;
    }).join('');

    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Session Dashboard</title>
        <style>
            * { box-sizing: border-box; font-family: system-ui, sans-serif; margin: 0; padding: 0; }
            body { background-color: #121212; color: #ffffff; padding: 20px; }
            .container { max-width: 900px; margin: 0 auto; }
            .header { text-align: center; margin-bottom: 20px; }
            .header h1 { color: #00e676; font-size: 24px; }
            .card { background-color: #1e1e1e; border-radius: 12px; padding: 15px; overflow-x: auto; }
            table { width: 100%; border-collapse: collapse; text-align: left; }
            th, td { padding: 12px 15px; border-bottom: 1px solid #2c2c2c; }
            th { background-color: #272727; color: #00e676; font-size: 13px; text-transform: uppercase; }
            .badge { padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; }
            .online { background-color: rgba(0, 230, 118, 0.2); color: #00e676; border: 1px solid #00e676; }
            .offline { background-color: rgba(255, 82, 82, 0.2); color: #ff5252; border: 1px solid #ff5252; }
            .btn { background-color: #00e676; color: #121212; border: none; padding: 8px 16px; border-radius: 6px; font-weight: bold; cursor: pointer; float: right; margin-bottom: 15px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><h1>Admin Session Dashboard</h1></div>
            <button class="btn" onclick="location.reload()">Refresh Data</button>
            <div class="card">
                <table>
                    <thead>
                        <tr>
                            <th>Device ID</th>
                            <th>Status</th>
                            <th>Last Seen</th>
                            <th>Total Usage</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rows || '<tr><td colspan="4" style="text-align:center; color:#888;">No active records found.</td></tr>'}
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
