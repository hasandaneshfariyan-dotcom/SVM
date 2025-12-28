<?php
// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

// Include the functions file
require "functions.php";

$configsArray = array_filter(explode("\n", file_get_contents("config.txt")), function($x) {
    return trim($x) !== "";
});

// Strict deduplication using fingerprints (ignores display name)
$seen = [];
$finalOutput = [];

foreach ($configsArray as $config) {
    $type = detect_type($config);
    if (!$type) continue;

    $fp = fingerprint_config($config, $type);
    if (!$fp) continue;

    if (!isset($seen[$fp])) {
        $seen[$fp] = true;
        $finalOutput[] = $config;
    }
}

// Write the final output to the config file
file_put_contents("config.txt", implode("\n", $finalOutput));

// Update MIX subscriptions
$tempConfig = hiddifyHeader("SiNAVM | MIX") . urldecode(implode("\n", $finalOutput));
$base64TempConfig = base64_encode($tempConfig);

file_put_contents("subscriptions/xray/normal/mix", $tempConfig);
file_put_contents("subscriptions/xray/base64/mix", $base64TempConfig);

echo "done!";
?>
