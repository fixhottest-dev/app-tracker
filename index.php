<?php
date_default_timezone_set('Asia/Kolkata');
$logFile = 'log_data.json';

if (!file_exists($logFile)) {
    file_put_contents($logFile, json_encode([]));
}

$deviceId = $_GET['id'] ?? '';
$status   = $_GET['status'] ?? '';
$duration = intval($_GET['duration'] ?? 0);

// API Execution
if (!empty($deviceId) && !empty($status)) {
    $currentLogs = json_decode(file_get_contents($logFile), true);
    if (!is_array($currentLogs)) { $currentLogs = []; }

    $lastSeen = date("Y-m-d h:i:s A");
    $previousDuration = isset($currentLogs[$deviceId]['total_seconds']) ? $currentLogs[$deviceId]['total_seconds'] : 0;

    $currentLogs[$deviceId] = [
        'device_id'     => $deviceId,
        'status'        => $status,
        'last_seen'     => $lastSeen,
        'total_seconds' => $previousDuration + $duration
    ];

    file_put_contents($logFile, json_encode($currentLogs, JSON_PRETTY_PRINT));
    echo "SUCCESS";
    exit;
}

// Admin UI Dashboard
$usersData = json_decode(file_get_contents($logFile), true);
if (!is_array($usersData)) { $usersData = []; }

function formatDuration($seconds) {
    $hours = floor($seconds / 3600);
    $minutes = floor(($seconds / 60) % 60);
    $sec = $seconds % 60;
    return ($hours > 0 ? "{$hours}h " : "") . ($minutes > 0 ? "{$minutes}m " : "") . "{$sec}s";
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Session Tracker</title>
    <style>
        body { background: #121212; color: #fff; font-family: sans-serif; padding: 15px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 10px; border-bottom: 1px solid #333; text-align: left; }
        th { color: #00e676; background: #222; }
        .online { color: #00e676; font-weight: bold; }
        .offline { color: #ff5252; font-weight: bold; }
    </style>
</head>
<body>
    <h2>User Activity Logs</h2>
    <button onclick="location.reload()" style="padding: 8px 15px; background: #00e676; border: none; font-weight: bold; cursor: pointer;">Refresh Data</button>
    <table>
        <tr><th>Device ID</th><th>Status</th><th>Last Seen</th><th>Usage Time</th></tr>
        <?php foreach ($usersData as $user): ?>
            <tr>
                <td><code><?= htmlspecialchars($user['device_id']) ?></code></td>
                <td class="<?= $user['status'] ?>"><?= strtoupper($user['status']) ?></td>
                <td><?= $user['last_seen'] ?></td>
                <td><?= formatDuration($user['total_seconds']) ?></td>
            </tr>
        <?php endforeach; ?>
    </table>
</body>
</html>
