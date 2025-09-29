<?php
// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

// Include the functions file
require "functions.php"; // مطمئن شوید این فایل کامل و در مسیر درست است

function processWsPath($input)
{
    if (empty($input)) return ["path" => "/", "max_early_data" => 0];
    $input = ltrim($input, "/");
    $max_early_data = 0;
    if (strpos($input, "?ed=") !== false) {
        list($path, $ed) = explode("?ed=", $input);
        $input = $path;
        $max_early_data = intval($ed);
    }
    return ["path" => "/" . $input, "max_early_data" => $max_early_data];
}

function setTls($decodedConfig, $configType)
{
    $serverName = match($configType) {
        "vmess" => $decodedConfig["sni"] ?? $decodedConfig["add"] ?? "",
        default => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? "",
    };
    $tls = [
        "enabled" => true,
        "server_name" => $serverName,
        "insecure" => isset($decodedConfig["params"]["insecure"]) && $decodedConfig["params"]["insecure"] === "1",
        "alpn" => explode(",", $decodedConfig["params"]["alpn"] ?? ($configType === "tuic" ? "h3,spdy/3.1" : "h3")),
        "min_version" => "1.3",
        "max_version" => "1.3",
        "utls" => [
            "enabled" => true,
            "fingerprint" => $decodedConfig["params"]["fp"] ?? "chrome"
        ]
    ];
    if ($configType === "vless" && ($decodedConfig["params"]["security"] ?? "") === "reality") {
        $tls["reality"] = [
            "enabled" => true,
            "public_key" => $decodedConfig["params"]["pbk"] ?? "",
            "short_id" => $decodedConfig["params"]["sid"] ?? ""
        ];
    }
    if ($configType === "hy2" && !empty($decodedConfig["params"]["ech"])) {
        $tls["ech"] = [
            "enabled" => true,
            "config" => explode(",", $decodedConfig["params"]["ech"])
        ];
    }
    return $tls;
}

function setTransport($decodedConfig, $configType, $transportType)
{
    $serverName = match($configType) {
        "vmess" => $decodedConfig["sni"] ?? $decodedConfig["add"] ?? "",
        default => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? "",
    };
    $path = processWsPath($decodedConfig["path"] ?? $decodedConfig["params"]["path"] ?? "")['path'];
    $maxEarly = processWsPath($decodedConfig["path"] ?? $decodedConfig["params"]["path"] ?? "")['max_early_data'];
    $serviceName = $decodedConfig["params"]["serviceName"] ?? "";

    return match($transportType) {
        "ws" => [
            "type" => "ws",
            "path" => $path,
            "headers" => ["Host" => $serverName],
            "max_early_data" => $maxEarly,
            "early_data_header_name" => $maxEarly > 0 ? "Sec-WebSocket-Protocol" : ""
        ],
        "grpc" => [
            "type" => "grpc",
            "service_name" => $serviceName,
            "idle_timeout" => "15s",
            "ping_timeout" => "15s",
            "permit_without_stream" => false
        ],
        "http" => [
            "type" => "http",
            "host" => [$serverName],
            "path" => $path
        ],
        default => null
    };
}

function toSingbox($input)
{
    if (!is_valid($input)) return null;
    $type = detect_type($input);
    $funcMap = [
        "vmess" => "vmessToSingbox",
        "vless" => "vlessToSingbox",
        "trojan" => "trojanToSingbox",
        "tuic" => "tuicToSingbox",
        "hy2" => "hy2ToSingbox",
        "ss" => "ssToSingbox"
    ];
    return $funcMap[$type] ?? null ? $funcMap[$type]($input) : null;
}

function processConvertion($base64ConfigsList, $configsName = "Created By sinavm")
{
    $configsArray = array_filter(explode("\n", base64_decode($base64ConfigsList)), 'strlen');
    $structure = json_decode(file_get_contents('structure.json'), true);

    $newOutbounds = [$structure['outbounds'][0], $structure['outbounds'][1]];
    $index = 1;

    foreach ($configsArray as $config) {
        $toSingbox = toSingbox($config);
        if ($toSingbox) {
            if (!empty($toSingbox['tls']['reality']['short_id'])) {
                $toSingbox['tls']['reality']['short_id'] = preg_replace('/[^a-f0-9]/i', '', $toSingbox['tls']['reality']['short_id']);
            }
            $toSingbox['tag'] = "@SiNAVM-$index";
            $newOutbounds[] = $toSingbox;
            $newOutbounds[0]['outbounds'][] = $toSingbox['tag'];
            $newOutbounds[1]['outbounds'][] = $toSingbox['tag'];
            $index++;
        }
    }

    $newOutbounds[] = ["type" => "direct", "tag" => "direct"];
    $structure['outbounds'] = $newOutbounds;

    return hiddifyHeader($configsName) . json_encode($structure, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}

// ---------- مسیر فایل‌ها ----------
$directories = [
    "subscriptions/xray/base64/mix",
    "subscriptions/xray/base64/vmess",
    "subscriptions/xray/base64/vless",
    "subscriptions/xray/base64/reality",
    "subscriptions/xray/base64/tuic",
    "subscriptions/xray/base64/hy2",
    "subscriptions/xray/base64/ss",
    "subscriptions/xray/base64/trojan"
];

foreach ($directories as $dir) {
    if (!file_exists($dir)) continue;
    $parts = explode("/", $dir);
    $name = $parts[3] ?? 'unknown';
    $data = file_get_contents($dir);
    $result = processConvertion($data, "@SiNAVM | " . $name);
    file_put_contents("subscriptions/singbox/" . $name . ".json", $result);
}

echo "Conversion to Sing-box completed successfully!\n";
