<?php
// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

// Include the functions file
require "functions.php";

/**
 * Cache + retry fetcher for Telegram pages and any URL.
 * - Uses cache when fresh or when network fails.
 * - Retries on temporary failures.
 */
function fetchWithCache(string $url, string $cacheFile, int $ttlSeconds = 3600, int $retries = 3, int $sleepSeconds = 2): ?string {
    // fresh cache
    if (is_file($cacheFile) && (time() - filemtime($cacheFile)) < $ttlSeconds) {
        $cached = @file_get_contents($cacheFile);
        if ($cached !== false && strlen($cached) > 0) return $cached;
    }

    $data = null;
    for ($i = 0; $i < $retries; $i++) {
        $data = @file_get_contents($url);
        // Telegram sometimes returns small/empty HTML on rate limit; keep a sanity threshold
        if ($data !== false && strlen($data) > 800) {
            @file_put_contents($cacheFile, $data);
            return $data;
        }
        sleep($sleepSeconds);
    }

    // fallback to any cache
    if (is_file($cacheFile)) {
        $cached = @file_get_contents($cacheFile);
        if ($cached !== false && strlen($cached) > 0) return $cached;
    }
    return null;
}

// تابع برای پردازش کانفیگ‌های vmess و تنظیم ps
function processVmessConfig($config, $index) {
    if (strpos($config, 'vmess://') !== 0) {
        return $config; // اگه vmess نیست، بدون تغییر برگردون
    }

    $base64Part = substr($config, 8); // حذف "vmess://"
    $decodedJson = base64_decode($base64Part);
    if ($decodedJson === false) {
        echo "\nDebug: Invalid base64 for vmess: " . substr($config, 0, 50) . "...\n";
        return null;
    }

    $decodedConfig = json_decode($decodedJson, true);
    if ($decodedConfig === null) {
        echo "\nDebug: Invalid JSON for vmess: " . substr($config, 0, 50) . "...\n";
        return null;
    }

    // تنظیم ps به فرمت دلخواه
    $decodedConfig['ps'] = "@SiNAVM-vmess-$index";
    $encodedJson = json_encode($decodedConfig, JSON_UNESCAPED_UNICODE);
    if ($encodedJson === false) {
        echo "\nDebug: Failed to encode JSON for vmess: " . substr($config, 0, 50) . "...\n";
        return null;
    }

    $encodedBase64 = base64_encode($encodedJson);
    return "vmess://$encodedBase64";
}

// Cache directory (telegram + sublinks)
$cacheDir = __DIR__ . "/cache";
$tgCacheDir = $cacheDir . "/telegram";
$subCacheDir = $cacheDir . "/sublinks";
@mkdir($tgCacheDir, 0755, true);
@mkdir($subCacheDir, 0755, true);

// Fetch the JSON data from channels.json and sublinks.json
$sourcesArray = json_decode(file_get_contents("channels.json"), true);
$sublinksJson = file_get_contents("sublinks.json");

// Replace placeholders with actual URLs from environment variables
$sublinksJson = str_replace(
    [
        "__PRIVATE_LINK_SiNAVM_1__",
        "__PRIVATE_LINK_SiNAVM_2__",
        "__PRIVATE_LINK_SiNAVM_3__"
    ],
    [
        getenv("PRIVATE_LINK_SiNAVM_1"),
        getenv("PRIVATE_LINK_SiNAVM_2"),
        getenv("PRIVATE_LINK_SiNAVM_3")
    ],
    $sublinksJson
);

// Decode the modified JSON
$sublinksArray = json_decode($sublinksJson, true);

// Count the total number of sources
$totalSources = count($sourcesArray) + (isset($sublinksArray['sublinks']) ? count($sublinksArray['sublinks']) : 0);
$tempCounter = 1;

// Initialize an empty array to store the configurations
$configsList = [];
echo "Fetching Configs\n";

// Loop through each source in the channels array (Telegram)
foreach ($sourcesArray as $source => $types) {
    // Calculate the percentage complete
    $percentage = ($tempCounter / max(1, $totalSources)) * 100;

    // Print the progress bar
    echo "\rProgress: [";
    echo str_repeat("=", floor($percentage / (100 / max(1, $totalSources))));
    echo str_repeat(" ", max(1, $totalSources) - floor($percentage / (100 / max(1, $totalSources))));
    echo "] " . number_format($percentage, 2) . "%";
    $tempCounter++;

    // Fetch with cache+retry
    $url = "https://t.me/s/" . $source;
    $cacheFile = $tgCacheDir . "/" . md5($source) . ".html";
    $tempData = fetchWithCache($url, $cacheFile, 3600, 3, 2);
    if (!$tempData) continue;

    $type = implode("|", $types);
    $tempExtract = extractLinksByType($tempData, $type);
    if (!is_null($tempExtract)) {
        $configsList[$source] = $tempExtract;
    }
}

// Loop through each sublink in sublinks.json
if (isset($sublinksArray['sublinks']) && is_array($sublinksArray['sublinks'])) {
    foreach ($sublinksArray['sublinks'] as $sublink) {
        // Calculate the percentage complete
        $percentage = ($tempCounter / max(1, $totalSources)) * 100;

        // Print the progress bar
        echo "\rProgress: [";
        echo str_repeat("=", floor($percentage / (100 / max(1, $totalSources))));
        echo str_repeat(" ", max(1, $totalSources) - floor($percentage / (100 / max(1, $totalSources))));
        echo "] " . number_format($percentage, 2) . "%";
        $tempCounter++;

        $url = $sublink['url'] ?? null;
        if (!$url) continue;

        $protocols = isset($sublink['protocols']) ? implode("|", $sublink['protocols']) : "vmess|vless|trojan|ss|tuic|hy2";
        try {
            $cacheFile = $subCacheDir . "/" . md5($url) . ".txt";
            $response = fetchWithCache($url, $cacheFile, 900, 3, 2);
            if (!$response) continue;

            // If it's base64 subscription, decode
            $decoded = base64_decode(trim($response), true);
            if ($decoded !== false && strpos($decoded, "://") !== false) {
                $response = $decoded;
            }

            $sublink_configs = array_filter(explode("\n", $response), function($config) use ($protocols) {
                $config = trim($config);
                return $config !== "" && preg_match("/^($protocols):\/\//", $config);
            });
            if (!empty($sublink_configs)) {
                $configsList[$url] = $sublink_configs;
            }
        } catch (Exception $e) {
            echo "\nError fetching sublink $url: " . $e->getMessage() . "\n";
        }
    }
}

// Initialize arrays for final output and location-based configs
$finalOutput = [];
$locationBased = [];
$needleArray = ["amp%3B"];
$replaceArray = [""];
$allConfigs = [
    "mix" => [],
    "vmess" => [],
    "vless" => [],
    "reality" => [],
    "tuic" => [],
    "hy2" => [],
    "ss" => [],
    "trojan" => []
];

// Define the hash and IP keys for each type of configuration
$configsHash = [
    "vmess" => "ps",
    "vless" => "hash",
    "trojan" => "hash",
    "tuic" => "hash",
    "hy2" => "hash",
    "ss" => "name",
];
$configsIp = [
    "vmess" => "add",
    "vless" => "hostname",
    "trojan" => "hostname",
    "tuic" => "hostname",
    "hy2" => "hostname",
    "ss" => "server_address",
];

echo "\nProcessing Configs\n";
$totalSources = count($configsList);
$tempSource = 1;
$configIndex = 1; // اندیس کلی برای نام‌گذاری @SiNAVM-<index>

// Loop through each source in the configs list
foreach ($configsList as $source => $configs) {
    $totalConfigs = count($configs);
    $tempCounter = 1;
    echo "\nSource $tempSource/$totalSources: $source\n";

    // Loop through each config in the configs array
    $limitKey = max(0, count($configs) - 40); // محدود به 40 کانفیگ آخر
    foreach (array_reverse($configs) as $key => $config) {
        // Calculate the percentage complete
        $percentage = ($tempCounter / max(1, $totalConfigs)) * 100;

        // Print the progress bar
        echo "\rProgress: [";
        echo str_repeat("=", floor($percentage / (100 / max(1, $totalConfigs))));
        echo str_repeat(" ", max(1, $totalConfigs) - floor($percentage / (100 / max(1, $totalConfigs))));
        echo "] " . number_format($percentage, 2) . "%";
        $tempCounter++;

        // If the config is valid and within the last 40
        if (is_valid($config) && $key >= $limitKey) {
            $type = detect_type($config);
            if (!$type || !isset($configsHash[$type])) continue;

            $configHash = $configsHash[$type];
            $configIp = $configsIp[$type];

            // پردازش کانفیگ‌های vmess
            if ($type === "vmess") {
                $config = processVmessConfig($config, $configIndex);
                if ($config === null) {
                    continue;
                }
            } else {
                // برای پروتکل‌های غیر vmess
                $config = preg_replace("/#.*?(?=(<|$))/", "", $config);
                $decodedConfig = configParse($config, $source);
                if (!$decodedConfig) {
                    echo "\nDebug: configParse failed for $type: " . substr($config, 0, 50) . "...\n";
                    continue;
                }
                $decodedConfig[$configHash] = "@SiNAVM-$type-$configIndex";
                $config = reparseConfig($decodedConfig, $type);
            }

            // بررسی مکان (کشور) با استفاده از IP
            $decodedConfig = configParse($config, $source);
            if (!$decodedConfig) {
                continue;
            }
            $configLocation = ip_info($decodedConfig[$configIp] ?? "")->country ?? "XX";

            // اضافه کردن به لیست نهایی و دسته‌بندی‌ها
            if (substr($config, 0, 10) !== "ss://Og==@") {
                $cleanConfig = str_replace($needleArray, $replaceArray, $config);
                $finalOutput[] = $cleanConfig;
                $locationBased[$configLocation][] = $cleanConfig;
                $allConfigs["mix"][] = $cleanConfig;
                $allConfigs[$type][] = $cleanConfig;
                if ($type === "vless" && !empty($decodedConfig["params"]["security"]) && $decodedConfig["params"]["security"] === "reality") {
                    $allConfigs["reality"][] = $cleanConfig;
                }
            }

            $configIndex++;
        }
    }
    $tempSource++;
}

// حذف و بازسازی پوشه‌های خروجی
deleteFolder("subscriptions/location/normal");
deleteFolder("subscriptions/location/base64");
mkdir("subscriptions/location/normal", 0755, true);
mkdir("subscriptions/location/base64", 0755, true);

// ذخیره کانفیگ‌های دسته‌بندی‌شده
foreach ($allConfigs as $type => $configs) {
    if (!empty($configs)) {
        $tempConfig = implode("\n\n", array_map('trim', $configs)) . "\n\n";
        $base64TempConfig = base64_encode($tempConfig);
        file_put_contents("subscriptions/xray/normal/$type", $tempConfig);
        file_put_contents("subscriptions/xray/base64/$type", $base64TempConfig);
    }
}

// ذخیره کانفیگ‌های location-based
foreach ($locationBased as $location => $configs) {
    if (!empty($configs)) {
        $tempConfig = implode("\n\n", array_map('trim', $configs)) . "\n\n";
        $base64TempConfig = base64_encode($tempConfig);
        file_put_contents("subscriptions/location/normal/$location", $tempConfig);
        file_put_contents("subscriptions/location/base64/$location", $base64TempConfig);
    }
}

// ذخیره config.txt
if (!empty($finalOutput)) {
    file_put_contents("config.txt", implode("\n\n", array_map('trim', $finalOutput)) . "\n\n");
}

echo "\nGetting Configs Done!\n";
?>
