<?php

// --- Helper validators ---
function is_hex_string($s) {
    return is_string($s) && $s !== '' && preg_match('/^[0-9a-fA-F]+$/', $s);
}

function is_base64_string($s) {
    if (!is_string($s) || $s === '') return false;
    $s = trim($s);
    return preg_match('/^[A-Za-z0-9+\/=]+$|^[A-Za-z0-9\-_]+$/', $s);
}


function configParse($input) {
    // حذف تگ‌های HTML و رشته‌های اضافی
    $input = preg_replace('/<[^>]+>|\s*vmess:\/\/[^\s]*/', '', $input);
    $input = str_replace(["\r", "\n"], '', $input);


    $url = parse_url($input);
    if (!$url) return null;

    $result = [];
    $result['type'] = strtok($input, ':');
    $result['username'] = strtok('@');
    $result['hostname'] = strtok(':');
    $result['port'] = strtok('?');
    $result['params'] = [];
    parse_str(strtok(''), $params);


    foreach ($params as $key => $value) {
        $value = strip_tags($value);
        $value = preg_replace('/vmess:\/\/[^\s]*/', '', $value);
        $value = trim($value);
        if (!empty($value)) {
            $result['params'][$key] = $value;
        }
    }

    return $result;
}


function processWsPath($input) {
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


function setTls($decodedConfig, $configType) {
    $serverNameTypes = [
        "vmess" => $decodedConfig["sni"] ?? $decodedConfig["add"] ?? "",
        "vless" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? "",
        "trojan" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? "",
        "tuic" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? "",
        "hy2" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? ""
    ];

    $serverName = strip_tags($serverNameTypes[$configType] ?? "");
    $serverName = preg_replace('/[^A-Za-z0-9\.\-_]/', '', $serverName);

    $insecureFlag = (isset($decodedConfig["params"]["insecure"]) && ($decodedConfig["params"]["insecure"] === "1" || $decodedConfig["params"]["insecure"] === 1 || $decodedConfig["params"]["insecure"] === "true"));

    $alpnRaw = $decodedConfig["params"]["alpn"] ?? ($configType === "tuic" ? "h3,spdy/3.1" : "h3");
    $alpnArr = array_filter(array_map('trim', explode(",", $alpnRaw)));

    $tlsConfig = [
        "enabled" => true,
        "server_name" => $serverName,
        "insecure" => $insecureFlag,
        "alpn" => !empty($alpnArr) ? $alpnArr : ["h3"],
        "min_version" => "1.3",
        "max_version" => "1.3",
        "utls" => [
            "enabled" => true,
            "fingerprint" => $decodedConfig["params"]["fp"] ?? "chrome"
        ]
    ];

    if ($configType === "vless" && !empty($decodedConfig["params"]["security"]) && $decodedConfig["params"]["security"] === "reality") {
        $pbk = $decodedConfig["params"]["pbk"] ?? "";
        $sid = $decodedConfig["params"]["sid"] ?? "";

        $pbk = strip_tags($pbk);
        $sid = strip_tags($sid);
        $pbk = preg_replace('/[^A-Za-z0-9+\/=]/', '', $pbk);
        $sid = preg_replace('/[^0-9a-fA-F]/', '', $sid);

        $pbk_ok = is_base64_string($pbk) || is_hex_string($pbk);
        $sid_ok = is_hex_string($sid) && strlen($sid) <= 16;

        if ($pbk_ok && $sid_ok) {
            $tlsConfig["reality"] = [
                "enabled" => true,
                "public_key" => $pbk,
                "short_id" => $sid
            ];
        } else {
            $tlsConfig["reality"] = [
                "enabled" => false
            ];
        }
    }

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


function setTransport($decodedConfig, $configType, $transportType) {
    $serverNameTypes = [
        "vmess" => $decodedConfig["sni"] ?? $decodedConfig["add"] ?? "",
        "vless" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? "",
        "trojan" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? "",
        "tuic" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? "",
        "hy2" => $decodedConfig["params"]["sni"] ?? $decodedConfig["hostname"] ?? ""
    ];

    $serverName = strip_tags($serverNameTypes[$configType] ?? "");
    $serverName = preg_replace('/[^A-Za-z0-9\.\-_]/', '', $serverName);

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
                "Host" => $serverName
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
            "host" => [$serverName],
            "path" => $pathTypes[$configType] ?? "/"
        ]
    ];

    if ($transportType === "grpc" && empty($transportTypes["grpc"]["service_name"])) {
        return null;
    }

    return $transportTypes[$transportType] ?? null;
}


function vmessToSingbox($input) {
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

    if ((($decodedConfig["port"] ?? "") === "443" || ($decodedConfig["tls"] ?? "") === "tls") && !empty($configResult["server"])) {
        $tls = setTls($decodedConfig, "vmess");
        if (!empty($tls["server_name"])) {
            $configResult["tls"] = $tls;
        }
    }

    if (!empty($decodedConfig["net"]) && in_array($decodedConfig["net"], ["ws", "grpc", "http"])) {
        $transport = setTransport($decodedConfig, "vmess", $decodedConfig["net"]);
        if ($transport) {
            $configResult["transport"] = $transport;
        }
    }

    if (isset($configResult["transport"]) && $configResult["transport"]["type"] === "grpc" && empty($configResult["transport"]["service_name"])) {
        return null;
    }

    return (!empty($configResult["server"]) && !empty($configResult["uuid"])) ? $configResult : null;
}


function vlessToSingbox($input) {
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

    if ((($decodedConfig["port"] ?? "") === "443" || (!empty($decodedConfig["params"]["security"]) && in_array($decodedConfig["params"]["security"], ["tls", "reality"]))) && !empty($configResult["server"])) {
        $tls = setTls($decodedConfig, "vless");
        if ((!empty($tls["server_name"])) || (!empty($tls["reality"]["enabled"] ?? false))) {
            $configResult["tls"] = $tls;
        }
    }

    if (!empty($decodedConfig["params"]["type"]) && in_array($decodedConfig["params"]["type"], ["ws", "grpc", "http"])) {
        $transport = setTransport($decodedConfig, "vless", $decodedConfig["params"]["type"]);
        if ($transport) {
            $configResult["transport"] = $transport;
        }
    }

    if (isset($configResult["transport"]) && $configResult["transport"]["type"] === "grpc" && empty($configResult["transport"]["service_name"])) {
        return null;
    }

    return (!empty($configResult["server"]) && !empty($configResult["uuid"])) ? $configResult : null;
}


function trojanToSingbox($input) {
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


function ssToSingbox($input) {
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


function tuicToSingbox($input) {
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


function hy2ToSingbox($input) {
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


function toSingbox($input) {
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


function processConvertion($base64ConfigsList, $configsName = "Created By sinavm") {
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
            $newOutbounds[0]['outbounds'][] = $toSingbox['tag'];
            $newOutbounds[1]['outbounds'][] = $toSingbox['tag'];
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
