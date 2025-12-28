<?php
// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

// Include the functions file
require "functions.php";

$configsArray = array_filter(explode("\n", file_get_contents("config.txt")), function($x){
    return trim($x) !== "";
});

$sortArray = [];

// Collect by type (and reality)
foreach ($configsArray as $config) {
    $configType = detect_type($config);
    if (!$configType) continue;

    $decoded = urldecode($config);
    $sortArray[$configType][] = $decoded;

    if ($configType === "vless" && is_reality($config)) {
        $sortArray["reality"][] = $decoded;
    }
}

// Normalize: unique + stable ordering (reduces CI diffs/conflicts)
foreach ($sortArray as $type => $arr) {
    $arr = array_values(array_unique($arr));
    sort($arr, SORT_STRING);
    $sortArray[$type] = $arr;
}

// Write each type subscription
foreach ($sortArray as $type => $sort) {
    if (!empty($sort)) {
        $tempConfigs = hiddifyHeader("SiNAVM | " . strtoupper($type)) . implode("\n", $sort);
        $base64TempConfigs = base64_encode($tempConfigs);

        file_put_contents("subscriptions/xray/normal/" . $type, $tempConfigs);
        file_put_contents("subscriptions/xray/base64/" . $type, $base64TempConfigs);
    }
}

echo "Sorting Done!";
?>
