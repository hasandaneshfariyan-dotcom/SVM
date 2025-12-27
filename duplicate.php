<?php
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

require "functions.php";

/**
 * Build a stable fingerprint for deduplication, ignoring the visible name.
 */
function fingerprint($raw) {
    $type = detect_type($raw);
    $p = configParse($raw);
    if (!$type || $p === null) return null;

    if ($type === 'vmess') {
        $add = $p['add'] ?? '';
        $port = $p['port'] ?? '';
        $id = $p['id'] ?? ($p['uuid'] ?? '');
        $tls = $p['tls'] ?? '';
        $sni = $p['sni'] ?? ($p['host'] ?? '');
        $net = $p['net'] ?? '';
        $path = $p['path'] ?? '';
        $host = $p['host'] ?? '';
        return "vmess|$add|$port|$id|$tls|$sni|$net|$path|$host";
    }

    if (in_array($type, ['vless','trojan','tuic','hy2'], true)) {
        // Expect configParse returns array with server/port/uuid + params
        $server = $p['server'] ?? ($p['host'] ?? '');
        $port = $p['port'] ?? '';
        $uuid = $p['uuid'] ?? ($p['id'] ?? '');
        $sni = $p['sni'] ?? ($p['host_param'] ?? ($p['params']['sni'] ?? ($p['params']['host'] ?? '')));
        $security = $p['security'] ?? ($p['params']['security'] ?? '');
        $flow = $p['flow'] ?? ($p['params']['flow'] ?? '');
        $pbk = $p['pbk'] ?? ($p['params']['pbk'] ?? '');
        $sid = $p['sid'] ?? ($p['params']['sid'] ?? '');
        return "$type|$server|$port|$uuid|$sni|$security|$pbk|$sid|$flow";
    }

    if ($type === 'ss') {
        // remove fragment for ss
        return "ss|" . explode('#', $raw, 2)[0];
    }

    return $type . "|" . $raw;
}

$inputFile = "config.txt";
if (!file_exists($inputFile)) {
    exit("config.txt not found\n");
}

$lines = file($inputFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

$seen = [];
$out = [];
$stats = ["in" => 0, "out" => 0, "dupes" => 0];

foreach ($lines as $line) {
    $stats["in"] += 1;
    $fp = fingerprint($line);
    if ($fp === null) continue;

    if (isset($seen[$fp])) {
        $stats["dupes"] += 1;
        continue;
    }
    $seen[$fp] = true;
    $out[] = $line;
}

$stats["out"] = count($out);
file_put_contents("reports/dedup_stats.json", json_encode($stats, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
file_put_contents($inputFile, implode("\n", $out));

echo "Dedup done. In={$stats['in']} Out={$stats['out']} Dupes={$stats['dupes']}\n";
