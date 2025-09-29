<?php
// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

// Include the functions file
require "functions.php";

function processWsPath($input)
{
    if (empty($input)) {
        return ["path" => "/", "max_early_data" => 0];
    }
    if (strpos($input, "/") === 0) {
        $input = substr($input, 1);
    }
    $max_early_data = 0;
    $path = $input;
    if (strpos($input, "?ed=") !== false) {
        $parts = explode("?ed=", $input);
        $path = $parts[0];
        $max_early_data = intval($parts[1] ?? 0);
    }
    return [
        "path" => "/" . $path,
        "max_early_data" => $max_early_data
    ];
}

function setTls($decodedConfig, $configType)
{
    $serverNameTypes = [
        "vmess" => $decodedConfig["sni"] ?? $decodedConfig["add"] ?? "",
        "vless" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? "",
        "trojan" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? "",
        "tuic" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? "",
        "hy2" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? ""
    ];
    $tlsConfig = [
        "enabled" => true,
        "server_name" => $serverNameTypes[$configType],
        "insecure" => isset($decodedConfig["params"]["insecure"]) && $decodedConfig["params"]["insecure"] === "1",
        "alpn" => explode(",", $decodedConfig["params"]["alpn"] ?? ($configType === "tuic" ? "h3,spdy/3.1" : "h3")),
        "min_version" => "1.3",
        "max_version" => "1.3",
        "utls" => [
            "enabled" => true,
            "fingerprint" => $decodedConfig["params"]["fp"] ?? "chrome"
        ]
    ];
    if ($configType === "vless" && !empty($decodedConfig["params"]["security"]) && $decodedConfig["params"]["security"] === "reality") {
        $tlsConfig["reality"] = [
            "enabled" => true,
            "public_key" => $decodedConfig["params"]["pbk"] ?? "",
            "short_id" => $decodedConfig["params"]["sid"] ?? ""
        ];
    }
    if ($configType === "hy2" && !empty($decodedConfig["params"]["ech"])) {
        $tlsConfig["ech"] = [
            "enabled" => true,
            "config" => explode(",", $decodedConfig["params"]["ech"])
        ];
    }
    return $tlsConfig;
}

function setTransport($decodedConfig, $configType, $transportType)
{
    $serverNameTypes = [
        "vmess" => $decodedConfig["sni"] ?? $decodedConfig["add"] ?? "",
        "vless" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? "",
        "trojan" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? "",
        "tuic" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? "",
        "hy2" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? ""
    ];
    $pathTypes = [
        "vmess" => processWsPath($decodedConfig["path"] ?? "")['path'],
        "vless" => processWsPath($decodedConfig["params"]["path"] ?? "")["path"],
        "trojan" => processWsPath($decodedConfig["params"]["path"] ?? "")["path"],
        "tuic" => processWsPath($decodedConfig["params"]["path"] ?? "")["path"],
        "hy2" => processWsPath($decodedConfig["params"]["path"] ?? "")["path"]
    ];
    $earlyData = [
        "vmess" => processWsPath($decodedConfig["path"] ?? "")['max_early_data'],
        "vless" => processWsPath($decodedConfig["params"]["path"] ?? "")["max_early_data"],
        "trojan" => processWsPath($decodedConfig["params"]["path"] ?? "")["max_early_data"],
        "tuic" => processWsPath($decodedConfig["params"]["path"] ?? "")["max_early_data"],
        "hy2" => processWsPath($decodedConfig["params"]["path"] ?? "")["max_early_data"]
    ];
    $servicenameTypes = [
        "vmess" => $decodedConfig["path"] ?? "",
        "vless" => $decodedConfig["params"]["serviceName"] ?? "",
        "trojan" => $decodedConfig["params"]["serviceName"] ?? "",
        "tuic" => $decodedConfig["params"]["serviceName"] ?? "",
        "hy2" => $decodedConfig["params"]["serviceName"] ?? ""
    ];
    $transportTypes = [
        "ws" => [
            "type" => "ws",
            "path" => $pathTypes[$configType],
            "headers" => [
                "Host" => $serverNameTypes[$configType]
            ],
            "max_early_data" => $earlyData[$configType],
            "early_data_header_name" => $earlyData[$configType] > 0 ? "Sec-WebSocket-Protocol" : ""
        ],
        "grpc" => [
            "type" => "grpc",
            "service_name" => $servicenameTypes[$configType],
            "idle_timeout" => "15s",
            "ping_timeout" => "15s",
            "permit_without_stream" => false
        ],
        "http" => [
            "type" => "http",
            "host" => [$serverNameTypes[$configType]],
            "path" => $pathTypes[$configType]
        ]
    ];
    return $transportTypes[$transportType] ?? null;
}

// … (توابع vmessToSingbox، vlessToSingbox، trojanToSingbox، ssToSingbox، tuicToSingbox، hy2ToSingbox بدون تغییر)

function toSingbox($input)
{
    if (!is_valid($input)) {
        return null;
    }
    $configType = detect_type($input);
    $functionsArray = [
        "vmess" => "vmessToSingbox",
        "vless" => "vlessToSingbox",
        "trojan" => "trojanToSingbox",
        "tuic" => "tuicToSingbox",
        "hy2" => "hy2ToSingbox",
        "ss" => "ssToSingbox"
    ];
    return isset($functionsArray[$configType]) ? $functionsArray[$configType]($input) : null;
}

function processConvertion($base64ConfigsList, $configsName = "Created By sinavm")
{
    $configsArray = array_filter(explode("\n", base64_decode($base64ConfigsList)), 'strlen');
    $structure = json_decode(file_get_contents('structure.json'), true);
    $index = 1;
    $newOutbounds = [];
    $newOutbounds[] = $structure['outbounds'][0]; // Internet
    $newOutbounds[] = $structure['outbounds'][1]; // Best Latency
    foreach ($configsArray as $config) {
        // --------- پاکسازی HTML و فاصله‌ها ---------
        $config = preg_replace('/<[^>]+>/', '', $config);
        $config = trim($config);

        $toSingbox = toSingbox($config);
        if ($toSingbox) {
            // --------- پاکسازی short_id فقط با حروف هگزادسیمال ---------
            if (isset($toSingbox['tls']['reality']['short_id'])) {
                $toSingbox['tls']['reality']['short_id'] = preg_replace('/[^a-f0-9]/i', '', $toSingbox['tls']['reality']['short_id']);
            }

            $toSingbox['tag'] = "@SiNAVM-$index";
            $newOutbounds[] = $toSingbox;
            $newOutbounds[0]['outbounds'][] = $toSingbox['tag']; // Add to selector
            $newOutbounds[1]['outbounds'][] = $toSingbox['tag']; // Add to urltest
            $index++;
        }
    }
    $newOutbounds[] = [
        "type" => "direct",
        "tag" => "direct"
    ];
    $structure['outbounds'] = $newOutbounds;
    return hiddifyHeader($configsName) . json_encode($structure, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}

$directoryOfFiles = [
    "subscriptions/xray/base64/mix",
    "subscriptions/xray/base64/vmess",
    "subscriptions/xray/base64/vless",
    "subscriptions/xray/base64/reality",
    "subscriptions/xray/base64/tuic",
    "subscriptions/xray/base64/hy2",
    "subscriptions/xray/base64/ss",
    "subscriptions/xray/base64/trojan"
];

foreach ($directoryOfFiles as $directory) {
    $configsName = "@SiNAVM | " . explode("/", $directory)[3];
    $configsData = file_get_contents($directory);
    $convertionResult = processConvertion($configsData, $configsName);
    file_put_contents("subscriptions/singbox/" . explode("/", $directory)[3] . ".json", $convertionResult);
}

echo "Conversion to Sing-box completed successfully!\n";
