const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Memory storage for active sessions
const devices = new Map();

// Time formatter helper
function formatTime(ms) {
    const totalSecs = Math.floor(ms / 1000);
    const mins = Math.floor(totalSecs / 60);
    const secs = totalSecs % 60;
    return `${mins}m ${secs}s`;
}

// 1. Tracking Endpoint (App hit karegi)
app.get(['/', '/index.php', '/track'], (req, res) => {
    const deviceId = req.query.id;
    const now = Date.now();

    if (deviceId) {
        let device = devices.get(deviceId);
        if (!device) {
            // New Session
            device = {
                id: deviceId,
                startTime: now,
                lastSeen: now,
                status: 'online'
            };
        } else {
            // Update Existing Session
            device.lastSeen = now;
            device.status = 'online';
        }
        devices.set(deviceId, device);
        return res.status(200).send('OK');
    }

    // 2. Dashboard Rendering (Browser ke liye)
    let rowsHtml = '';
    const currentTime = Date.now();

    devices.forEach((dev) => {
        // Agar 25 seconds tak ping nahi aaya, toh OFFLINE mark karo
        if (currentTime - dev.lastSeen > 25000) {
            dev.status = 'offline';
        }

        const duration = formatTime(dev.lastSeen - dev.startTime);
        const startReadable = new Date(dev.startTime).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
        const lastSeenReadable = new Date(dev.lastSeen).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

        rowsHtml += `
            <tr>
                <td><code>${dev.id}</code></td>
                <td><span class="badge ${dev.status}">${dev.status.toUpperCase()}</span></td>
                <td>${startReadable}</td>
                <td>${lastSeenReadable}</td>
                <td><strong>${duration}</strong></td>
            </tr>
        `;
    });

    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>App Tracking Dashboard</title>
        <style>
            * { box-sizing: border-box; font-family: sans-serif; margin: 0; padding: 0; }
            body { background: #0f172a; color: #e2e8f0; padding: 20px; }
            .container { max-width: 900px; margin: 0 auto; }
            h1 { color: #38bdf8; text-align: center; margin-bottom: 20px; }
            .card { background: #1e293b; border-radius: 10px; padding: 15px; overflow-x: auto; }
            table { width: 100%; border-collapse: collapse; text-align: left; }
            th, td { padding: 12px; border-bottom: 1px solid #334155; font-size: 14px; }
            th { color: #38bdf8; background: #0f172a; }
            .badge { padding: 4px 8px; border-radius: 6px; font-size: 12px; font-weight: bold; }
            .online { background: #166534; color: #4ade80; }
            .offline { background: #991b1b; color: #f87171; }
        </style>
        <script>
            // Silent Live Auto Update (No Refresh Freeze)
            setInterval(() => {
                fetch(location.href)
                    .then(r => r.text())
                    .then(html => {
                        const doc = new DOMParser().parseFromString(html, 'text/html');
                        const newTbody = doc.querySelector('tbody');
                        if (newTbody) document.querySelector('tbody').innerHTML = newTbody.innerHTML;
                    }).catch(() => {});
            }, 3000);
        </script>
    </head>
    <body>
        <div class="container">
            <h1>Live App Telemetry Dashboard</h1>
            <div class="card">
                <table>
                    <thead>
                        <tr>
                            <th>Device ID</th>
                            <th>Status</th>
                            <th>Session Start</th>
                            <th>Last Seen</th>
                            <th>Active Duration</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rowsHtml || '<tr><td colspan="5" style="text-align:center; color:#94a3b8;">No devices online. Open the app to view logs.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    `);
});

app.listen(PORT, () => console.log(`Server live on port ${PORT}`));
