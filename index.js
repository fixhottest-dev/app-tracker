const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// In-Memory Storage (Zero Disk Latency - Server Freeze Fix)
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

// Session API Endpoint
app.get(['/', '/index.php'], (req, res) => {
    const deviceId = req.query.id;
    const action = req.query.action;
    const nowTimestamp = Date.now();
    const nowReadable = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

    // Handle App Hits
    if (deviceId) {
        let activeSession = sessions.find(s => s.device_id === deviceId && s.status === 'online');

        if (action === 'start' || !activeSession) {
            if (activeSession) activeSession.status = 'offline';
            sessions.unshift({
                session_id: nowTimestamp.toString(),
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

    // Mark Inactive Sessions as Offline (> 25s)
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

    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>App Live Tracking Dashboard</title>
        <style>
            * { box-sizing: border-box; font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 0; }
            body { background-color: #0f172a; color: #f8fafc; padding: 24px; }
            .container { max-width: 900px; margin: 0 auto; }
            h1 { color: #38bdf8; text-align: center; margin-bottom: 24px; font-size: 22px; }
            .card { background-color: #1e293b; border-radius: 12px; padding: 16px; overflow-x: auto; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }
            table { width: 100%; border-collapse: collapse; text-align: left; }
            th, td { padding: 12px 16px; border-bottom: 1px solid #334155; font-size: 14px; }
            th { color: #38bdf8; background-color: #0f172a; font-weight: 600; text-transform: uppercase; font-size: 12px; }
            .badge { padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; }
            .online { background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid #22c55e; }
            .offline { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
        </style>
        <script>
            // Silent Live DOM Refresh without Browser Freeze
            setInterval(() => {
                fetch(location.href)
                    .then(r => r.text())
                    .then(html => {
                        const doc = new DOMParser().parseFromString(html, 'text/html');
                        document.querySelector('tbody').innerHTML = doc.querySelector('tbody').innerHTML;
                    }).catch(() => {});
            }, 3000);
        </script>
    </head>
    <body>
        <div class="container">
            <h1>Live Session Tracking Dashboard</h1>
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
                        ${rows || '<tr><td colspan="5" style="text-align:center; color:#94a3b8;">No active or past sessions found. Open the app to view telemetry.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    `);
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
