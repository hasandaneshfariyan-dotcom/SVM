<?php
// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

// Include the functions file
require "functions.php";

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
$totalSources = count($sourcesArray) + count($sublinksArray['sublinks']);
$tempCounter = 1;

// Initialize an empty array to store the configurations
$configsList = [];
echo "Fetching Configs\n";

// Loop through each source in the channels array (API)
foreach ($sourcesArray as $source => $types) {
    // Calculate the percentage complete
    $percentage = ($tempCounter / $totalSources) * 100;

    // Print the progress bar
    echo "\rProgress: [";
    echo str_repeat("=", $tempCounter);
    echo str_repeat(" ", $totalSources - $tempCounter);
    echo "] $percentage%";
    $tempCounter++;

    // Fetch the data from the Telegram API
    $tempData = file_get_contents("https://t.me/s/" . $source);
    $type = implode("|", $types);
    $tempExtract = extractLinksByType($tempData, $type);
    if (!is_null($tempExtract)) {
        $configsList[$source] = $tempExtract;
    }
}

// Loop through each sublink in sublinks.json
foreach ($sublinksArray['sublinks'] as $sublink) {
    // Calculate the percentage complete
    $percentage = ($tempCounter / $totalSources) * 100;

    // Print the progress bar
    echo "\rProgress: [";
    echo str_repeat("=", $tempCounter);
    echo str_repeat(" ", $totalSources - $tempCounter);
    echo "] $percentage%";
    $tempCounter++;

    $url = $sublink['url'];
    $protocols = implode("|", $sublink['protocols']);
    try {
        $response = file_get_contents($url);
        $sublink_configs = array_filter(explode("\n", $response), function($config) use ($protocols) {
            return preg_match("/^($protocols):\/\//", $config);
        });
        if (!empty($sublink_configs)) {
            $configsList[$url] = $sublink_configs;
        }
    } catch (Exception $e) {
        echo "\nError fetching sublink $url: " . $e->getMessage() . "\n";
    }
}

// Initialize an empty array to store the final output
$finalOutput = [];
$locationBased = [];
$needleArray = ["amp%3B"];
$replaceArray = [""];

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
$configIndex = 1; // اندیس کلی برای نام‌گذاری @sinavm-<index>

// Loop through each source in the configs list
foreach ($configsList as $source => $configs) {
    $totalConfigs = count($configs);
    $tempCounter = 1;
    echo "\n" . strval($tempSource) . "/" . strval($totalSources) . "\n";

    // Loop through each config in the configs array
    $limitKey = count($configs) - 40;
    foreach (array_reverse($configs) as $key => $config) {
        // Calculate the percentage complete
        $percentage = ($tempCounter / $totalConfigs) * 100;

        // Print the progress bar
        echo "\rProgress: [";
        echo str_repeat("=", $tempCounter);
        echo str_repeat(" ", $totalConfigs - $tempCounter);
        echo "] $percentage%";
        $tempCounter++;

        // If the config is valid and the key is less than or equal to 40
        if (is_valid($config) && $key >= $limitKey) {
            $type = detect_type($config);
            $configHash = $configsHash[$type];
            $configIp = $configsIp[$type];
            // حذف هر چیزی بعد از اولین # و قبل از <
            $config = preg_replace("/#.*?(?=(<|$))/", "", $config);
            $decodedConfig = configParse($config);

            $decodedConfig[$configHash] = (getcwd() == getcwd() . "/lite" ? "@sinavm-lite-" : "@sinavm-") . $configIndex;
            $configIndex++;
            $configLocation = ip_info($decodedConfig[$configIp])->country ?? "XX";
            $encodedConfig = reparseConfig($decodedConfig, $type);
            if (substr($encodedConfig, 0, 10) !== "ss://Og==@") {
                $finalOutput[] = str_replace(
                    $needleArray,
                    $replaceArray,
                    $encodedConfig
                );
                $locationBased[$configLocation][] = str_replace(
                    $needleArray,
                    $replaceArray,
                    $encodedConfig
                );
            }
        }
    }
    $tempSource++;
}
deleteFolder("subscriptions/location/normal");
deleteFolder("subscriptions/location/base64");
mkdir("subscriptions/location/normal");
mkdir("subscriptions/location/base64");

// Loop through each location in the location-based array
foreach ($locationBased as $location => $configs) {
    $tempConfig = urldecode(implode("\n", $configs));
    $base64TempConfig = base64_encode($tempConfig);
    file_put_contents(
        "subscriptions/location/normal/" . $location,
        $tempConfig
    );
    file_put_contents(
        "subscriptions/location/base64/" . $location,
        $base64TempConfig
    );
}

// Write the final output to a file
file_put_contents("config.txt", implode("\n", $finalOutput));

echo "\nGetting Configs Done!\n";
?>
