<?php
// functions.php - اصلاح‌شده برای جلوگیری از خطای short_id و اعتبارسنجی Reality

// --- Helper validators ---
function is_hex_string($s) {
    return is_string($s) && $s !== '' && preg_match('/^[0-9a-fA-F]+$/', $s);
}

function is_base64_string($s) {
    if (!is_string($s) || $s === '') return false;
    // حذف فضاها و بررسی پایه‌ای base64
    $s = trim($s);
    // base64 چاراکترهای A-Z a-z 0-9 + / = و - _ (در base64url) ممکنه باشند
    return preg_match('/^[A-Za-z0-9+\/=]+$|^[A-Za-z0-9\-_]+$/', $s);
}

// --- موجودی که شما قبلاً داشتید ---
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

    $insecureFlag = (isset($decodedConfig["params"]["insecure"]) && ($decodedConfig["params"]["insecure"] === "1" || $decodedConfig["params"]["insecure"] === 1 || $decodedConfig["params"]["insecure"] === "true"));

    $alpnRaw = $decodedConfig["params"]["alpn"] ?? ($configType === "tuic" ? "h3,spdy/3.1" : "h3");
    $alpnArr = array_filter(array_map('trim', explode(",", $alpnRaw)));

    $tlsConfig = [
        "enabled" => true,
        "server_name" => $serverNameTypes[$configType] ?? "",
        "insecure" => $insecureFlag,
        "alpn" => !empty($alpnArr) ? $alpnArr : ["h3"],
        "min_version" => "1.3",
        "max_version" => "1.3",
        "utls" => [
            "enabled" => true,
            "fingerprint" => $decodedConfig["params"]["fp"] ?? "chrome"
        ]
    ];

    // Reality validation: only add reality if pbk and sid look valid
    if ($configType === "vless" && !empty($decodedConfig["params"]["security"]) && $decodedConfig["params"]["security"] === "reality") {
        $pbk = $decodedConfig["params"]["pbk"] ?? "";
        $sid = $decodedConfig["params"]["sid"] ?? "";

        // pbk می‌تواند base64 یا hex باشد — حداقل بررسی ابتدایی
        $pbk_ok = is_base64_string($pbk) || is_hex_string($pbk);

        // sid باید هگز باشد (اجتناب از کاراکترهای نامعتبر مثل '<')
        $sid_ok = is_hex_string($sid);

        if ($pbk_ok && $sid_ok) {
            // مقداردهی امن
            $tlsConfig["reality"] = [
                "enabled" => true,
                "public_key" => $pbk,
                "short_id" => $sid
            ];
        } else {
            // اگر هرکدام نامعتبر است، بهتر است reality را فعال نکنیم — بالاترین ایمنی: رد کانفیگ بر عهده caller
            // این تابع فقط یک آرایه TLS می‌سازد؛ تصمیم‌گیری نهایی در caller انجام می‌شود.
            $tlsConfig["reality"] = [
                "enabled" => false
            ];
        }
    }

    // ECH support for hy2
    if ($configType === "hy2" && !empty($decodedConfig["params"]["ech"])) {
        $echListRaw = $decodedConfig["params"]["ech"];
        $echArr = array_filter(array_map('trim', explode(",", $echListRaw)));
        if (!empty($echArr)) {
            $tlsConfig["ech"] = [
                "enabled" => true,
                "config" => $echArr
            ];
        }
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
            "path" => $pathTypes[$configType] ?? "/",
            "headers" => [
                "Host" => $serverNameTypes[$configType] ?? ""
            ],
            "max_early_data" => intval($earlyData[$configType] ?? 0),
            "early_data_header_name" => (intval($earlyData[$configType] ?? 0) > 0 ? "Sec-WebSocket-Protocol" : "")
        ],
        "grpc" => [
            "type" => "grpc",
            "service_name" => $servicenameTypes[$configType] ?? "",
            "idle_timeout" => "15s",
            "ping_timeout" => "15s",
            "permit_without_stream" => false
        ],
        "http" => [
            "type" => "http",
            "host" => [$serverNameTypes[$configType] ?? ""],
            "path" => $pathTypes[$configType] ?? "/"
        ]
    ];

    // اگر transport از نوع grpc است اما service_name خالی است، بازگرداندن null تا caller حذفش کند
    if ($transportType === "grpc" && empty($transportTypes["grpc"]["service_name"])) {
        return null;
    }

    return $transportTypes[$transportType] ?? null;
}

// --- تبدیل vmess -> singbox ---
function vmessToSingbox($input)
{
    $decodedConfig = configParse($input);
    if (!$decodedConfig) {
        return null;
    }
    $configResult = [
        "type" => "vmess",
        "server" => $decodedConfig["add"] ?? "",
        "server_port" => intval($decodedConfig["port"] ?? 0),
        "uuid" => $decodedConfig["id"] ?? "",
        "security" => $decodedConfig["scy"] ?? "auto",
        "alter_id" => intval($decodedConfig["aid"] ?? 0),
        "domain_strategy" => "prefer_ipv4"
    ];

    // TLS check (port 443 or tls param)
    if ((($decodedConfig["port"] ?? "") === "443" || ($decodedConfig["tls"] ?? "") === "tls") && !empty($configResult["server"])) {
        $tls = setTls($decodedConfig, "vmess");
        if (!empty($tls["server_name"])) {
            $configResult["tls"] = $tls;
        }
    }

    // transport
    if (!empty($decodedConfig["net"]) && in_array($decodedConfig["net"], ["ws", "grpc", "http"])) {
        $transport = setTransport($decodedConfig, "vmess", $decodedConfig["net"]);
        if ($transport) {
            $configResult["transport"] = $transport;
        }
    }

    // grpc must have service_name
    if (isset($configResult["transport"]) && $configResult["transport"]["type"] === "grpc" && empty($configResult["transport"]["service_name"])) {
        return null;
    }

    return (!empty($configResult["server"]) && !empty($configResult["uuid"])) ? $configResult : null;
}

// --- تبدیل vless -> singbox (با اعتبارسنجی reality) ---
function vlessToSingbox($input)
{
    $decodedConfig = configParse($input);
    if (!$decodedConfig) {
        return null;
    }

    $isReality = !empty($decodedConfig["params"]["security"]) && $decodedConfig["params"]["security"] === "reality";

    $configResult = [
        "type" => "vless",
        "server" => $decodedConfig["hostname"] ?? "",
        "server_port" => intval($decodedConfig["port"] ?? 0),
        "uuid" => $decodedConfig["username"] ?? "",
        "packet_encoding" => "xudp",
        "domain_strategy" => $isReality ? "ipv6_only" : "prefer_ipv4"
    ];

    // TLS + Reality
    if ((($decodedConfig["port"] ?? "") === "443" || (!empty($decodedConfig["params"]["security"]) && in_array($decodedConfig["params"]["security"], ["tls", "reality"]))) && !empty($configResult["server"])) {
        $tls = setTls($decodedConfig, "vless");

        // اگر reality فعال و واقعاً valid است — باید pbk و sid معتبر باشند
        if (!empty($decodedConfig["params"]["security"]) && $decodedConfig["params"]["security"] === "reality") {
            $pbk = $decodedConfig["params"]["pbk"] ?? "";
            $sid = $decodedConfig["params"]["sid"] ?? "";

            $pbk_ok = is_base64_string($pbk) || is_hex_string($pbk);
            $sid_ok = is_hex_string($sid);

            if ($pbk_ok && $sid_ok) {
                // setTls قبلاً reality را به صورت enabled=false یا enabled=true اضافه کرده بود؛ برای اطمینان دوباره مقدار درست قرار می‌دهیم
                $tls["reality"] = [
                    "enabled" => true,
                    "public_key" => $pbk,
                    "short_id" => $sid
                ];
            } else {
                // اگر reality ناقص است => کانفیگ نامعتبر است (برای جلوگیری از خطای sing-box)
                return null;
            }
        }

        // اگر server_name خالی نبود یا reality فعال شده، tls را اعمال کن
        if ((!empty($tls["server_name"])) || (!empty($tls["reality"]["enabled"] ?? false))) {
            $configResult["tls"] = $tls;
        }
    }

    // transport
    if (!empty($decodedConfig["params"]["type"]) && in_array($decodedConfig["params"]["type"], ["ws", "grpc", "http"])) {
        $transport = setTransport($decodedConfig, "vless", $decodedConfig["params"]["type"]);
        if ($transport) {
            $configResult["transport"] = $transport;
        }
    }

    // grpc must have service_name
    if (isset($configResult["transport"]) && $configResult["transport"]["type"] === "grpc" && empty($configResult["transport"]["service_name"])) {
        return null;
    }

    // reality specific checks: pbk and short_id already بررسی شدند بالاتر
    return (!empty($configResult["server"]) && !empty($configResult["uuid"])) ? $configResult : null;
}

// --- تبدیل trojan -> singbox ---
function trojanToSingbox($input)
{
    $decodedConfig = configParse($input);
    if (!$decodedConfig) {
        return null;
    }
    $configResult = [
        "type" => "trojan",
        "server" => $decodedConfig["hostname"] ?? "",
        "server_port" => intval($decodedConfig["port"] ?? 0),
        "password" => $decodedConfig["username"] ?? "",
        "domain_strategy" => "prefer_ipv4"
    ];

    if ((($decodedConfig["port"] ?? "") === "443" || (!empty($decodedConfig["params"]["security"]) && $decodedConfig["params"]["security"] === "tls")) && !empty($configResult["server"])) {
        $tls = setTls($decodedConfig, "trojan");
        if (!empty($tls["server_name"])) {
            $configResult["tls"] = $tls;
        }
    }

    if (!empty($decodedConfig["params"]["type"]) && in_array($decodedConfig["params"]["type"], ["ws", "grpc", "http"])) {
        $transport = setTransport($decodedConfig, "trojan", $decodedConfig["params"]["type"]);
        if ($transport) {
            $configResult["transport"] = $transport;
        }
    }

    if (isset($configResult["transport"]) && $configResult["transport"]["type"] === "grpc" && empty($configResult["transport"]["service_name"])) {
        return null;
    }

    return (!empty($configResult["server"]) && !empty($configResult["password"])) ? $configResult : null;
}

// --- تبدیل shadowsocks -> singbox ---
function ssToSingbox($input)
{
    $decodedConfig = configParse($input);
    if (!$decodedConfig) {
        return null;
    }
    $encryptionMethods = [
        "chacha20-ietf-poly1305",
        "aes-256-gcm",
        "2022-blake3-aes-256-gcm"
    ];
    if (!in_array($decodedConfig["encryption_method"] ?? "", $encryptionMethods)) {
        return null;
    }
    $configResult = [
        "type" => "shadowsocks",
        "server" => $decodedConfig["server_address"] ?? "",
        "server_port" => intval($decodedConfig["server_port"] ?? 0),
        "method" => $decodedConfig["encryption_method"],
        "password" => $decodedConfig["password"] ?? "",
        "udp_over_tcp" => true,
        "domain_strategy" => "prefer_ipv4"
    ];
    return (!empty($configResult["server"]) && !empty($configResult["password"])) ? $configResult : null;
}

// --- تبدیل tuic -> singbox ---
function tuicToSingbox($input)
{
    $decodedConfig = configParse($input);
    if (!$decodedConfig) {
        return null;
    }
    $configResult = [
        "type" => "tuic",
        "server" => $decodedConfig["hostname"] ?? "",
        "server_port" => intval($decodedConfig["port"] ?? 0),
        "uuid" => $decodedConfig["username"] ?? "",
        "password" => $decodedConfig["pass"] ?? "",
        "congestion_control" => $decodedConfig["params"]["congestion_control"] ?? "bbr",
        "udp_relay_mode" => $decodedConfig["params"]["udp_relay_mode"] ?? "native",
        "zero_rtt_handshake" => false,
        "heartbeat" => "10s",
        "network" => "tcp",
        "domain_strategy" => "prefer_ipv4"
    ];
    $tls = setTls($decodedConfig, "tuic");
    if (!empty($tls["server_name"])) {
        $configResult["tls"] = $tls;
    }
    return (!empty($configResult["server"]) && !empty($configResult["uuid"]) && !empty($configResult["password"])) ? $configResult : null;
}

// --- تبدیل hysteria2 -> singbox ---
function hy2ToSingbox($input)
{
    $decodedConfig = configParse($input);
    if (!$decodedConfig) {
        return null;
    }
    $configResult = [
        "type" => "hysteria2",
        "server" => $decodedConfig["hostname"] ?? "",
        "server_port" => intval($decodedConfig["port"] ?? 0),
        "server_ports" => !empty($decodedConfig["params"]["ports"]) ? $decodedConfig["params"]["ports"] : null,
        "password" => $decodedConfig["username"] ?? "",
        "domain_strategy" => "ipv4_only",
        "hop_interval" => "10s"
    ];
    if (!empty($decodedConfig["params"]["obfs"])) {
        $configResult["obfs"] = [
            "type" => $decodedConfig["params"]["obfs"],
            "password" => $decodedConfig["params"]["obfs-password"] ?? ""
        ];
        if (empty($configResult["obfs"]["password"])) {
            return null;
        }
    }
    $tls = setTls($decodedConfig, "hy2");
    if (!empty($tls["server_name"]) || !empty($tls["ech"])) {
        $configResult["tls"] = $tls;
    }
    return (!empty($configResult["server"]) && !empty($configResult["password"])) ? $configResult : null;
}

// --- wrapper toSingbox (uses helper functions detect_type, is_valid, configParse which should exist) ---
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

// --- processConvertion unchanged (keeps original behaviour) ---
function processConvertion($base64ConfigsList, $configsName = "Created By sinavm")
{
    $configsArray = array_filter(explode("\n", base64_decode($base64ConfigsList)), 'strlen');
    $structure = json_decode(file_get_contents('structure.json'), true);
    $index = 1;
    $newOutbounds = [];
    $newOutbounds[] = $structure['outbounds'][0]; // Internet
    $newOutbounds[] = $structure['outbounds'][1]; // Best Latency
    foreach ($configsArray as $config) {
        $toSingbox = toSingbox($config);
        if ($toSingbox) {
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
