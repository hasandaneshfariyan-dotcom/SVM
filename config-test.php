<?php
// Load environment variables
$API_URL = "http://127.0.0.1:6756";
$BEARER_TOKEN = "xXxTestxXx";
$TEST_URL = "http://cp.cloudflare.com";
$TIMEOUT = 1000; // in milliseconds
$BATCH_SIZE = 10; // Number of proxies to process in parallel

function runHiddify()
{
    $hiddifyDir = __DIR__ . '/hiddify-cli';
    if (!is_dir($hiddifyDir)) {
        mkdir($hiddifyDir, 0755, true);
    }
    chdir($hiddifyDir);

    $downloadUrl = 'https://github.com/hiddify/hiddify-core/releases/download/v1.3.6/hiddify-cli-linux-amd64.tar.gz';
    $downloadedFile = 'hiddify-cli.tar.gz';
    file_put_contents($downloadedFile, fopen($downloadUrl, 'r'));

    $command = "tar -zxvf {$downloadedFile}";
    shell_exec($command);

    chmod('HiddifyCli', 0755);

    $configPath = escapeshellarg('../config.txt');
    $hiddifyConfigPath = escapeshellarg('../hiddify-conf.json');
    $command = "./HiddifyCli run -c {$configPath} --hiddify {$hiddifyConfigPath} > /dev/null 2>&1 & echo $!";
    $pid = (int)shell_exec($command);

    file_put_contents('hiddify.pid', $pid);
    chdir('../');

    echo "Hiddify started in background with PID: $pid\n";
}

function stopHiddify()
{
    $pidFile = 'hiddify-cli/hiddify.pid';
    if (file_exists($pidFile)) {
        $pid = (int)file_get_contents($pidFile);
        if ($pid) {
            posix_kill($pid, 9);
            echo "Hiddify process (PID: $pid) stopped.\n";
        }
        unlink($pidFile);
    }
}

function get_custom_headers()
{
    global $BEARER_TOKEN;
    return ["Authorization: Bearer $BEARER_TOKEN"];
}

function get_proxies()
{
    global $API_URL;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "$API_URL/proxies");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, get_custom_headers());

    $response = curl_exec($ch);
    $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpcode === 200) {
        return json_decode($response, true)["proxies"];
    } else {
        throw new Exception("Failed to get proxies: HTTP $httpcode");
    }
}

function get_real_delay_batch($proxy_names)
{
    global $API_URL, $TIMEOUT, $TEST_URL;

    $multiHandle = curl_multi_init();
    $curlHandles = [];

    foreach ($proxy_names as $proxy_name) {
        $ch = curl_init();
        $encoded_proxy_name = str_replace('+', '%20', urlencode($proxy_name));
        curl_setopt($ch, CURLOPT_URL, "$API_URL/proxies/$encoded_proxy_name/delay?timeout=$TIMEOUT&url=$TEST_URL");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, $TIMEOUT);
        curl_setopt($ch, CURLOPT_HTTPHEADER, get_custom_headers());

        curl_multi_add_handle($multiHandle, $ch);
        $curlHandles[$proxy_name] = $ch;
    }

    $running = null;
    do {
        curl_multi_exec($multiHandle, $running);
    } while ($running);

    $results = [];
    foreach ($curlHandles as $proxy_name => $ch) {
        $response = curl_multi_getcontent($ch);
        $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($httpcode === 200) {
            $results[$proxy_name] = json_decode($response, true)["delay"];
        } else {
            $results[$proxy_name] = $TIMEOUT;
        }
        curl_multi_remove_handle($multiHandle, $ch);
        curl_close($ch);
    }

    curl_multi_close($multiHandle);
    return $results;
}

function update_delay_info($proxies, $sampling_type)
{
    global $BATCH_SIZE;

    $proxy_names = array_keys($proxies);
    $batches = array_chunk($proxy_names, $BATCH_SIZE);

    foreach ($batches as $batch) {
        if ($sampling_type === "single") {
            $delays = get_real_delay_batch($batch);
            foreach ($delays as $proxy_name => $delay) {
                $proxies[$proxy_name]["delay_single"] = $delay;
            }
        }
    }
    return $proxies;
}

function filter_single_working_proxies($proxies)
{
    global $TIMEOUT;

    $working_proxies = array_filter($proxies, function ($proxy_data) use ($TIMEOUT) {
        return in_array($proxy_data["type"], ["VLESS", "Trojan", "Shadowsocks", "VMess", "TUIC"]) &&
            isset($proxy_data["delay_single"]) &&
            $proxy_data["delay_single"] < $TIMEOUT;
    });

    usort($working_proxies, function ($a, $b) {
        return $a["delay_single"] - $b["delay_single"];
    });

    return $working_proxies;
}

function filterConfigs($names, $configFile)
{
    if (!file_exists($configFile)) {
        echo "\nConfig file not found: {$configFile}\n";
        return;
    }

    $configs = file($configFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($configs === false) {
        echo "\nUnable to read config file: {$configFile}\n";
        return;
    }

    $filteredConfigs = [];
    $searchPatterns = [];

    foreach ($names as $name) {
        $name = trim($name);
        if ($name === '') continue;

        if (strpos($name, '|') !== false) {
            $parts = array_map('trim', explode('|', $name));
            $p0 = isset($parts[0]) ? $parts[0] : '';
            $p1 = isset($parts[1]) ? $parts[1] : '';
            $p2 = isset($parts[2]) ? $parts[2] : '';
            $p3 = isset($parts[3]) ? $parts[3] : '';
            $key = $p3 !== '' ? explode(" § ", $p3)[0] : '';

            $pattern1 = str_replace(' ', '%20', $p0) . "%20|%20" . str_replace(' ', '%20', $p1) . "%20|%20" .
                        str_replace(' ', '%20', $p2) . "%20|%20" . $key;
            $pattern2 = $p0 . '|' . $p1 . '|' . $p2 . '|' . $key;
            $searchPatterns[] = $pattern1;
            $searchPatterns[] = $pattern2;
        } else {
            $searchPatterns[] = $name;
            $searchPatterns[] = str_replace(' ', '%20', $name);
        }
    }

    $searchPatterns = array_values(array_unique($searchPatterns));

    if (empty($searchPatterns)) {
        echo "\nNo search keys available. Config file not written.\n";
        return;
    }

    foreach ($configs as $configLine) {
        foreach ($searchPatterns as $pattern) {
            if ($pattern === '') continue;
            if (strpos($configLine, $pattern) !== false) {
                $filteredConfigs[] = trim($configLine);
                break;
            }
        }
    }

    $filteredConfigs = array_values(array_unique($filteredConfigs));

    if (!empty($filteredConfigs)) {
        file_put_contents("config.txt", implode("\n\n", $filteredConfigs) . "\n\n");
        echo "\nConfig file written successfully. " . count($filteredConfigs) . " lines.\n";
    } else {
        echo "\nNo valid new configurations found. Config file not written.\n";
    }
}

function main()
{
    try {
        runHiddify();
        sleep(30); // منتظر بارگذاری Hiddify

        $proxies = get_proxies();
        $proxies = update_delay_info($proxies, "single");
        $working_proxies = filter_single_working_proxies($proxies);

        $names = [];
        foreach ($working_proxies as $item) {
            if (isset($item['name']) && is_string($item['name']) && $item['name'] !== '') {
                $names[] = $item['name'];
            }
            if (isset($item['tags']) && is_array($item['tags'])) {
                foreach ($item['tags'] as $t) {
                    if (is_string($t) && $t !== '') {
                        $names[] = $t;
                    }
                }
            }
            if (isset($item['labels']) && is_array($item['labels'])) {
                foreach ($item['labels'] as $t) {
                    if (is_string($t) && $t !== '') {
                        $names[] = $t;
                    }
                }
            }
        }
        $names = array_values(array_unique($names));

        $configFile = 'config.txt';
        filterConfigs($names, $configFile);

        echo "\nTesting Configs Done!\n";
    } catch (Exception $e) {
        echo "An error occurred: " . $e->getMessage() . "\n";
    }
}

echo "Running The Config-Test Script...\n";
register_shutdown_function('stopHiddify');
main();
?>
