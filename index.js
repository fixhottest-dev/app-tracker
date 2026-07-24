const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// All sessions history store karne ke liye array
let sessionHistory = [];

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

// Tracking API Route
app.get(['/', '/index.php', '/track'], (req, res) => {
    const deviceId = req.query.id;
    const action = req.query.action;
    const now = Date.now();
    const timeFormatted = new Date(now).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

    // App se Request aane par
    if (deviceId) {
        // Active session dhoondo jo 'online' ho
        let currentSession = sessionHistory.find(s => s.deviceId === deviceId && s.status === 'online');

        if (action === 'start' || !currentSession) {
            // Agar purana active session tha, toh use offline kar do
            if (currentSession) {
                currentSession.status = 'offline';
            }

            // NAYA Session History Entry create karo
            currentSession = {
                id: Date.now().toString(),
                deviceId: deviceId,
                startTime: timeFormatted,
                lastSeenTime: timeFormatted,
                startTimestamp: now,
                lastSeenTimestamp: now,
                status: 'online'
            };
            // List ke start me add karo (Naya session sabse upar dikhega)
            sessionHistory.unshift(currentSession);
        } else {
            // Existing running session ko update karo
            currentSession.lastSeenTimestamp = now;
            currentSession.lastSeenTime = timeFormatted;
        }

        return res.status(200).send('OK');
    }

    // Dashboard Load hone par: Inactive Sessions (25s timeout) ko OFFLINE mark karo
    sessionHistory.forEach(s => {
        if (s.status === 'online' && (now - s.lastSeenTimestamp > 25000)) {
            s.status = 'offline';
        }
    });

    // History Table Rows Generate Karo
    const rowsHtml = sessionHistory.map(s => {
        const duration = formatDuration(s.lastSeenTimestamp - s.startTimestamp);
        return `
            <tr>
                <td><code>${s.deviceId}</code></td>
                <td><span class="badge ${s.status}">${s.status.toUpperCase()}</span></td>
                <td>${s.startTime}</td>
                <td>${s.lastSeenTime}</td>
                <td><strong>${duration}</strong></td>
            </tr>
        `;
    }).join('');

    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>App History Tracking Dashboard</title>
        <style>
            * { box-sizing: border-box; font-family: system-ui, sans-serif; margin: 0; padding: 0; }
            body { background: #0f172a; color: #e2e8f0; padding: 20px; }
            .container { max-width: 950px; margin: 0 auto; }
            h1 { color: #38bdf8; text-align: center; margin-bottom: 20px; font-size: 22px; }
            .card { background: #1e293b; border-radius: 10px; padding: 15px; overflow-x: auto; }
            table { width: 100%; border-collapse: collapse; text-align: left; }
            th, td { padding: 12px; border-bottom: 1px solid #334155; font-size: 14px; }
            th { color: #38bdf8; background: #0f172a; }
            .badge { padding: 4px 8px; border-radius: 6px; font-size: 11px; font-weight: bold; }
            .online { background: #166534; color: #4ade80; }
            .offline { background: #991b1b; color: #f87171; }
        </style>
        <script>
            // Live Update without Refresh
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
            <h1>User Session History & Live Status</h1>
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
                        ${rowsHtml || '<tr><td colspan="5" style="text-align:center; color:#94a3b8;">No session records found.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    `);
});

app.listen(PORT, () => console.log(`Server live on port ${PORT}`));
