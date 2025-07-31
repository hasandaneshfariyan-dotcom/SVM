<?php
// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

// Include the functions file
require "functions.php";

// Read the config.txt file and split it into an array by newline
$configsArray = explode("\n", file_get_contents("config.txt"));

// Initialize an empty array to hold the sorted configurations
$sortArray = [];

// Loop through each configuration in configsArray with index
foreach ($configsArray as $index => $config) {
    // Skip empty lines
    if (empty(trim($config))) {
        continue;
    }

    // Detect the type of the configuration
    $configType = detect_type($config);
    
    // Generate new name: @sinavm-<index+1>
    $newName = "@sinavm-" . ($index + 1);
    
    // Replace the original name (after #) with the new name
    $configParts = explode("#", $config, 2);
    $configBase = $configParts[0]; // Part before #
    $newConfig = $configBase . "#" . urlencode($newName);
    
    // Add the modified configuration to the corresponding array in sortArray
    $sortArray[$configType][] = urldecode($newConfig);
    
    // If the configuration is of type "vless" and is a reality, add it to the "reality" array
    if ($configType === "vless" && is_reality($newConfig)) {
        $sortArray["reality"][] = urldecode($newConfig);
    }
}

// Loop through each type of configuration in sortArray
foreach ($sortArray as $type => $sort) {
    // If the type is not empty
    if ($type !== "") {
        // Join the configurations into a string, encode it to base64, and write it to a file
        $tempConfigs = hiddifyHeader("@sinavm | " . strtoupper($type)) . implode("\n", $sort);
        $base64TempConfigs = base64_encode($tempConfigs);
        file_put_contents("subscriptions/xray/normal/" . $type, $tempConfigs);
        file_put_contents(
            "subscriptions/xray/base64/" . $type,
            $base64TempConfigs
        );
    }
}

// Print "done!" to the console
echo "Sorting Done!";
?>
