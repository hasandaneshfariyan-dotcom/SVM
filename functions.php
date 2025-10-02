<?php

function is_ip($string)
{
    $ip_pattern = '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/';
    return preg_match($ip_pattern, $string);
}

function convertToJson($input)
{
    $lines = explode("\n", $input);
    $data = [];
    foreach ($lines as $line) {
        $parts = explode("=", $line);
        if (count($parts) == 2 && !empty($parts[0]) && !empty($parts[1])) {
            $key = trim($parts[0]);
            $value = trim($parts[1]);
            $data[$key] = $value;
        }
    }
    return json_encode($data);
}

function ip_info($ip)
{
    if (is_cloudflare_ip($ip)) {
        $traceUrl = "http://$ip/cdn-cgi/trace";
        $traceData = json_decode(convertToJson(file_get_contents($traceUrl)), true);
        $country = $traceData['loc'] ?? "CF";
        return (object) [
            "country" => $country,
        ];
    }

    if (!is_ip($ip)) {
        $ip_address_array = dns_get_record($ip, DNS_A);
        if (empty($ip_address_array)) {
            return null;
        }
        $randomKey = array_rand($ip_address_array);
        $ip = $ip_address_array[$randomKey]["ip"];
    }

    $endpoints = [
        "https://ipapi.co/{ip}/json/",
        "https://ipwhois.app/json/{ip}",
        "http://www.geoplugin.net/json.gp?ip={ip}",
        "https://api.ipbase.com/v1/json/{ip}",
    ];

    $result = (object) [
        "country" => "XX",
    ];

    foreach ($endpoints as $endpoint) {
        $url = str_replace("{ip}", $ip, $endpoint);
        $options = [
            "http" => [
                "header" => "User-Agent: Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.102011-10-16 20:23:10\r\n",
            ],
        ];

        $context = stream_context_create($options);
        $response = @file_get_contents($url, false, $context);
        if ($response !== false) {
            $data = json_decode($response);
            if ($endpoint === $endpoints[0]) {
                $result->country = $data->country_code ?? "XX";
            } elseif ($endpoint === $endpoints[1]) {
                $result->country = $data->country_code ?? "XX";
            } elseif ($endpoint === $endpoints[2]) {
                $result->country = $data->geoplugin_countryCode ?? "XX";
            } elseif ($endpoint === $endpoints[3]) {
                $result->country = $data->country_code ?? "XX";
            }
            break;
        }
    }

    return $result;
}

function is_cloudflare_ip($ip)
{
    $cloudflare_ranges = file_get_contents('https://www.cloudflare.com/ips-v4');
    $cloudflare_ranges = explode("\n", $cloudflare_ranges);
    foreach ($cloudflare_ranges as $range) {
        if (cidr_match($ip, $range)) {
            return true;
        }
    }
    return false;
}

function cidr_match($ip, $range)
{
    list($subnet, $bits) = explode('/', $range);
    $bits = $bits ?? 32;
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = -1 << (32 - $bits);
    $subnet &= $mask;
    return ($ip & $mask) == $subnet;
}

function is_valid($input)
{
    if (empty($input) || stripos($input, "…") !== false || stripos($input, "...") !== false) {
        return false;
    }
    return preg_match('/^(vmess|vless|trojan|ss|hysteria2|tuic):\/\//', $input);
}

function isEncrypted($input)
{
    $decodedConfig = configParse($input);
    $configType = detect_type($input);

    if ($configType === "vmess" && !empty($decodedConfig['tls']) && $decodedConfig['scy'] !== "none") {
        return true;
    } elseif (in_array($configType, ["vless", "trojan"]) && !empty($decodedConfig['params']['security']) && $decodedConfig['params']['security'] !== "none") {
        return true;
    } elseif ($configType === "ss") {
        return true;
    } elseif ($configType === "tuic" && !empty($decodedConfig['params']['allow_insecure']) && $decodedConfig['params']['allow_insecure'] === "0") {
        return true;
    } elseif ($configType === "hy2" && !empty($decodedConfig['params']['insecure']) && $decodedConfig['params']['insecure'] === "0") {
        return true;
    }
    return false;
}

function getFlags($country_code)
{
    if (strlen($country_code) !== 2) {
        return "🏳️";
    }
    $flag = mb_convert_encoding(
        "&#" . (127397 + ord($country_code[0])) . ";",
        "UTF-8",
        "HTML-ENTITIES"
    );
    $flag .= mb_convert_encoding(
        "&#" . (127397 + ord($country_code[1])) . ";",
        "UTF-8",
        "HTML-ENTITIES"
    );
    return $flag;
}

function detect_type($input)
{
    if (substr($input, 0, 8) === "vmess://") {
        return "vmess";
    } elseif (substr($input, 0, 8) === "vless://") {
        return "vless";
    } elseif (substr($input, 0, 9) === "trojan://") {
        return "trojan";
    } elseif (substr($input, 0, 5) === "ss://") {
        return "ss";
    } elseif (substr($input, 0, 7) === "tuic://") {
        return "tuic";
    } elseif (
        substr($input, 0, 6) === "hy2://" ||
        substr($input, 0, 12) === "hysteria2://"
    ) {
        return "hy2";
    } elseif (substr($input, 0, 11) === "hysteria://") {
        return "hysteria";
    }
    return null;
}

function extractLinksByType($inputString, $configType)
{
    $pattern = "/(" . $configType . '):\/\/[^"\'\s]+/';
    preg_match_all($pattern, $inputString, $matches);
    return empty($matches[0]) ? null : $matches[0];
}

function parseQuery($query)
{
    $params = [];
    parse_str($query, $params);
    return $params;
}

function configParse($input)
{
    $configType = detect_type($input);
    if (!$configType) {
        return null;
    }

    if ($configType === "vmess") {
        $vmess_data = substr($input, 8);
        $decoded_data = json_decode(base64_decode($vmess_data), true);
        if (!$decoded_data) {
            return null;
        }
        // تمیزسازی فیلدهای vmess
        foreach ($decoded_data as $k => $v) {
            if (in_array($k, ['host', 'sni'])) {
                preg_match('/^[a-zA-Z0-9.-_*]+/', $v, $m);
                $decoded_data[$k] = $m[0] ?? '';
            } elseif ($k === 'path') {
                $decoded_data[$k] = strip_tags($v);
            } elseif ($k === 'ps') {
                $decoded_data[$k] = strip_tags($v);
            }
        }
        return $decoded_data;
    } elseif (
        $configType === "vless" ||
        $configType === "trojan" ||
        $configType === "tuic" ||
        $configType === "hy2"
    ) {
        $parsedUrl = parse_url($input);
        if (!$parsedUrl) {
            return null;
        }
        $params = [];
        if (isset($parsedUrl["query"])) {
            $params = parseQuery($parsedUrl["query"]);
        }
        // تمیزسازی params برای جلوگیری از محتوای اضافی (HTML و غیره)
        foreach ($params as $key => $val) {
            $val = trim(strip_tags($val)); // حذف تگ‌های HTML
            switch ($key) {
                case 'sid':
                    preg_match('/^[0-9a-fA-F]+/', $val, $m);
                    $params[$key] = $m[0] ?? '';
                    break;
                case 'pbk':
                    preg_match('/^[A-Za-z0-9+\/=]+/', $val, $m);
                    $params[$key] = $m[0] ?? '';
                    break;
                case 'sni':
                case 'host':
                case 'server_name':
                    preg_match('/^[a-zA-Z0-9.-_*]+/', $val, $m);
                    $params[$key] = $m[0] ?? '';
                    break;
                case 'path':
                case 'serviceName':
                    $params[$key] = preg_replace('/<[^>]*>/', '', $val); // حذف تگ‌های باقی‌مانده
                    break;
                default:
                    $params[$key] = $val;
            }
        }
        $output = [
            "protocol" => $configType,
            "username" => $parsedUrl["user"] ?? "",
            "hostname" => $parsedUrl["host"] ?? "",
            "port" => $parsedUrl["port"] ?? "",
            "params" => $params,
            "hash" => isset($parsedUrl["fragment"]) ? urldecode($parsedUrl["fragment"]) : "SiNAVM" . getRandomName(),
        ];
        if ($configType === "tuic") {
            $output["pass"] = $params["password"] ?? "";
            if (empty($output["username"]) || empty($output["pass"])) {
                return null;
            }
        }
        return $output;
    } elseif ($configType === "ss") {
        $url = parse_url($input);
        if (!$url) {
            return null;
        }
        $user = $url["user"] ?? "";
        if (isBase64($user)) {
            $user = base64_decode($user);
        }
        $userParts = explode(":", $user);
        if (count($userParts) < 2) {
            return null;
        }
        $output = [
            "encryption_method" => $userParts[0],
            "password" => $userParts[1],
            "server_address" => $url["host"] ?? "",
            "server_port" => $url["port"] ?? "",
            "name" => isset($url["fragment"]) ? strip_tags(urldecode($url["fragment"])) : "SiNAVM" . getRandomName(),
        ];
        if (empty($output["server_address"]) || empty($output["password"])) {
            return null;
        }
        return $output;
    }
    return null;
}

function reparseConfig($configArray, $configType)
{
    if ($configType === "vmess") {
        $encoded_data = base64_encode(json_encode($configArray));
        return "vmess://" . $encoded_data;
    } elseif (
        $configType === "vless" ||
        $configType === "trojan" ||
        $configType === "tuic" ||
        $configType === "hy2"
    ) {
        $url = $configType . "://";
        $url .= addUsernameAndPassword($configArray);
        $url .= $configArray["hostname"];
        $url .= addPort($configArray);
        $url .= addParams($configArray);
        $url .= addHash($configArray);
        return $url;
    } elseif ($configType === "ss") {
        $user = base64_encode(
            $configArray["encryption_method"] . ":" . $configArray["password"]
        );
        $url = "ss://$user@{$configArray["server_address"]}:{$configArray["server_port"]}";
        if (!empty($configArray["name"])) {
            $url .= "#" . str_replace(" ", "%20", $configArray["name"]);
        }
        return $url;
    }
    return null;
}

function addUsernameAndPassword($obj)
{
    $url = "";
    if (!empty($obj["username"])) {
        $url .= $obj["username"];
        if (isset($obj["pass"]) && !empty($obj["pass"])) {
            $url .= ":" . $obj["pass"];
        }
        $url .= "@";
    }
    return $url;
}

function addPort($obj)
{
    $url = "";
    if (!empty($obj["port"])) {
        $url .= ":" . $obj["port"];
    }
    return $url;
}

function addParams($obj)
{
    $url = "";
    if (!empty($obj["params"])) {
        $url .= "?" . http_build_query($obj["params"]);
    }
    return $url;
}

function addHash($obj)
{
    $url = "";
    if (!empty($obj["hash"])) {
        $url .= "#" . str_replace(" ", "%20", $obj["hash"]);
    }
    return $url;
}

function is_reality($input)
{
    $type = detect_type($input);
    return ($type === "vless" && stripos($input, "security=reality") !== false);
}

function isBase64($input)
{
    return (base64_encode(base64_decode($input, true)) === $input);
}

function getRandomName()
{
    return substr(md5(uniqid()), 0, 8);
}

function deleteFolder($folder)
{
    if (!is_dir($folder)) {
        return;
    }
    $files = glob($folder . '/*');
    foreach ($files as $file) {
        is_dir($file) ? deleteFolder($file) : unlink($file);
    }
    rmdir($folder);
}

function tehran_time()
{
    date_default_timezone_set("Asia/Tehran");
    return date("Y-m-d H:i:s", time());
}

function hiddifyHeader($subscriptionName)
{
    return "#profile-title: base64:" . base64_encode($subscriptionName) . "\n" .
           "#profile-update-interval: 1\n" .
           "#subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531\n" .
           "#support-url: https://t.me/sinavm\n" .
           "#profile-web-page-url: https://github.com/sinavm/SVM\n\n";
}
