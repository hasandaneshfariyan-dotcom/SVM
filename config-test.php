// --- جایگزین بخش جمع‌آوری نام‌ها در main() ---
$names = []; // ذخیره کلیدهای قابل جستجو (name و تگ‌ها)
foreach ($working_proxies as $item) {
    if (isset($item['name']) && is_string($item['name']) && $item['name'] !== '') {
        $names[] = $item['name'];
    }
    // اگر فیلد tags یا labels وجود دارد و آرایه است، آنها را هم اضافه کن
    if (isset($item['tags']) && is_array($item['tags'])) {
        foreach ($item['tags'] as $t) {
            if (is_string($t) && $t !== '') {
                $names[] = $t;
            }
        }
    }
    // بعضی کلاینت‌ها ممکن است از کلید دیگر مثل 'labels' یا 'remark' استفاده کنند:
    if (isset($item['labels']) && is_array($item['labels'])) {
        foreach ($item['labels'] as $t) {
            if (is_string($t) && $t !== '') {
                $names[] = $t;
            }
        }
    }
}
// حذف تکراری‌ها (برای بهینه‌سازی)
$names = array_values(array_unique($names));

// --- جایگزین تابع filterConfigs با نسخه‌ی امن و بهینه ---
function filterConfigs($names, $configFile)
{
    // خواندن کل فایل کانفیگ (هر خط یک عنصر)
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

    // آماده‌سازی کلیدهای جستجو (به شکل‌هایی که ممکن است در فایل کانفیگ وجود داشته باشند)
    $searchPatterns = [];

    foreach ($names as $name) {
        $name = trim($name);
        if ($name === '') continue;

        // حالت 1: اگر name شامل | هست و به فرم خاصی شباهت دارد، سعی کن به شکل قبلی %20|%20 فرم‌دهی کنی (ایمن)
        if (strpos($name, '|') !== false) {
            $parts = array_map('trim', explode('|', $name));
            // اگر حداقل 1 قسمت وجود دارد، ما سعی می‌کنیم از سه قسمت اول و قسمت چهارم (در صورت وجود) یک رشته مقایسه‌ای بسازیم
            // اما هر دسترسی به اندیس را ایمن انجام می‌دهیم
            $p0 = isset($parts[0]) ? $parts[0] : '';
            $p1 = isset($parts[1]) ? $parts[1] : '';
            $p2 = isset($parts[2]) ? $parts[2] : '';
            $p3 = isset($parts[3]) ? $parts[3] : '';

            // اگر p3 شامل " § " هست، قسمت قبل از آن کلید است
            if ($p3 !== '') {
                $keyParts = explode(" § ", $p3);
                $key = trim($keyParts[0]);
            } else {
                $key = '';
            }

            // ساخت چند الگوی احتمالی برای جستجو (هم encoded و هم غیر encoded)
            $pattern1 = str_replace(' ', '%20', $p0) . "%20|%20" . str_replace(' ', '%20', $p1) . "%20|%20" .
                        str_replace(' ', '%20', $p2) . "%20|%20" . $key;
            $pattern2 = $p0 . '|' . $p1 . '|' . $p2 . '|' . $key;
            $searchPatterns[] = $pattern1;
            $searchPatterns[] = $pattern2;
        } else {
            // حالت 2: معمولی — سعی کن هم نسخه URL-encoded و هم خام را جستجو کنی
            $searchPatterns[] = $name;
            $searchPatterns[] = str_replace(' ', '%20', $name);
        }
    }

    // حذف الگوهای تکراری و مرتب‌سازی (برای کارایی)
    $searchPatterns = array_values(array_unique($searchPatterns));

    // اگر الگوها خالی است، خروج
    if (empty($searchPatterns)) {
        echo "\nNo search keys available. Config file not written.\n";
        return;
    }

    // برای هر خط کانفیگ، فقط یکبار بررسی می‌کنیم که آیا با یکی از الگوها همخوانی دارد
    foreach ($configs as $configLine) {
        foreach ($searchPatterns as $pattern) {
            if ($pattern === '') continue;
            if (strpos($configLine, $pattern) !== false) {
                $filteredConfigs[] = $configLine;
                break; // این خط کانفیگ مطابق یک الگو بود، دیگر الگوها را بررسی نکن
            }
        }
    }

    // حذف تکراری‌ها در خروجی و نوشتن فایل
    $filteredConfigs = array_values(array_unique($filteredConfigs));

    if (!empty($filteredConfigs)) {
        file_put_contents("config.txt", implode("\n", $filteredConfigs));
        echo "\nConfig file written successfully. " . count($filteredConfigs) . " lines.\n";
    } else {
        echo "\nNo valid new configurations found. Config file not written.\n";
    }
}
