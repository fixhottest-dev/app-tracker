const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// In-Memory Storage (Fastest Response - No Disk Lag)
let sessions = [];

function formatDuration(seconds) {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    let res = '';
    if (hrs > 0) res += `${hrs}h `;
    if (mins > 0) res += `${mins}m `;
    res += `${secs}s`;
    return res;
}

// Tracking API
app.get(['/', '/index.php'], (req, res) => {
    const deviceId = req.query.id;
    const action = req.query.action;
    const nowTimestamp = Date.now();
    const nowReadable = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

    if (deviceId) {
        let activeSession = sessions.find(s => s.device_id === deviceId && s.status === 'online');

        if (action === 'start' || !activeSession) {
            if (activeSession) activeSession.status = 'offline';
            sessions.unshift({
                device_id: deviceId,
                start_time: nowReadable,
                last_seen: nowReadable,
                last_timestamp: nowTimestamp,
                duration: 10,
                status: 'online'
            });
        } else {
            activeSession.last_seen = nowReadable;
            activeSession.last_timestamp = nowTimestamp;
            activeSession.duration += 10;
        }

        return res.status(200).send('SUCCESS');
    }

    // Auto Offline Calculation (> 25 seconds)
    sessions.forEach(s => {
        if (s.status === 'online' && (nowTimestamp - s.last_timestamp > 25000)) {
            s.status = 'offline';
        }
    });

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
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>App Session Tracker</title>
        <style>
            * { box-sizing: border-box; font-family: system-ui, sans-serif; margin: 0; padding: 0; }
            body { background-color: #121212; color: #fff; padding: 20px; }
            .container { max-width: 950px; margin: 0 auto; }
            h1 { color: #00e676; text-align: center; margin-bottom: 20px; font-size: 22px; }
            .card { background-color: #1e1e1e; border-radius: 10px; padding: 15px; overflow-x: auto; }
            table { width: 100%; border-collapse: collapse; text-align: left; }
            th, td { padding: 12px; border-bottom: 1px solid #2d2d2d; font-size: 14px; }
            th { color: #00e676; background-color: #252525; }
            .badge { padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; }
            .online { background: rgba(0, 230, 118, 0.2); color: #00e676; border: 1px solid #00e676; }
            .offline { background: rgba(255, 82, 82, 0.2); color: #ff5252; border: 1px solid #ff5252; }
            .btn { background-color: #00e676; color: #121212; border: none; padding: 8px 16px; border-radius: 6px; font-weight: bold; cursor: pointer; float: right; margin-bottom: 15px; }
        </style>
        <script>
            // JavaScript Auto-Fetch without Freeze
            setInterval(() => {
                fetch(location.href)
                    .then(res => res.text())
                    .then(html => {
                        const parser = new DOMParser();
                        const doc = parser.parseFromString(html, 'text/html');
                        document.querySelector('tbody').innerHTML = doc.querySelector('tbody').innerHTML;
                    }).catch(() => {});
            }, 3000);
        </script>
    </head>
    <body>
        <div class="container">
            <h1>Live App Sessions Dashboard</h1>
            <div class="card">
                <table>
                    <thead>
                        <tr>
                            <th>Device ID</th>
                            <th>Status</th>
                            <th>Session Start</th>
                            <th>Last Seen</th>
                            <th>Duration</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rows || '<tr><td colspan="5" style="text-align:center; color:#888;">No tracking records yet. Open the app.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    `;

    res.send(html);
});

app.listen(PORT, () => console.log(`Server live on ${PORT}`));
