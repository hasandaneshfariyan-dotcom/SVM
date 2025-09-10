import json
import re
import os
import requests
from telethon import TelegramClient
from telethon.sessions import StringSession
import asyncio
import logging

# تنظیمات لاگ
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# اطلاعات API تلگرام از متغیرهای محیطی
api_id = int(os.getenv('TELEGRAM_API_ID'))
api_hash = os.getenv('TELEGRAM_API_HASH')
session_string = os.getenv('TELEGRAM_SESSION')

# مسیر فایل‌ها
channels_file = 'channels.json'  # فایل لیست کانال‌های تلگرام
sublinks_file = 'sublinks.json'  # فایل لیست ساب‌لینک‌ها
output_file = 'config.txt'       # فایل خروجی برای کانفیگ‌ها

# تابع برای دریافت کانفیگ‌ها از ساب‌لینک
def fetch_configs_from_sublink(url, protocols):
    try:
        response = requests.get(url.split('#')[0])  # حذف بخش #VIBE%7CPOWER
        response.raise_for_status()
        configs = response.text.strip().split('\n')
        # فیلتر کردن کانفیگ‌ها بر اساس پروتکل‌های مجاز
        filtered_configs = [
            config for config in configs
            if config and re.match(r'(vless|vmess|trojan|ss|tuic|hy2):\/\/[^\s]+', config)
            and config.split('://')[0] in protocols
        ]
        logging.info(f"Fetched {len(filtered_configs)} configs from {url}")
        return filtered_configs
    except Exception as e:
        logging.error(f"Error fetching sublink {url}: {e}")
        return []

# تابع اصلی
async def main():
    # ایجاد کلاینت تلگرام با StringSession
    client = TelegramClient(StringSession(session_string), api_id, api_hash)
    
    try:
        # اتصال به تلگرام
        await client.start()
        logging.info("Successfully connected to Telegram")

        # لیست کانفیگ‌ها
        configs = []

        # 1. جمع‌آوری کانفیگ‌ها از کانال‌های تلگرام
        try:
            with open(channels_file, 'r', encoding='utf-8') as f:
                channels_data = json.load(f)

            for channel_name, protocols in channels_data.items():
                logging.info(f"Processing channel: {channel_name}")
                try:
                    channel_entity = await client.get_entity(f"@{channel_name}")
                    async for message in client.iter_messages(channel_entity, limit=100):
                        if message.text:
                            config_matches = re.findall(r'(vless|vmess|trojan|ss|tuic|hy2):\/\/[^\s]+', message.text)
                            for config in config_matches:
                                if config.split('://')[0] in protocols:
                                    configs.append(config)
                except Exception as e:
                    logging.error(f"Error processing channel {channel_name}: {e}")
        except FileNotFoundError:
            logging.warning(f"{channels_file} not found, skipping Telegram channels")

        # 2. جمع‌آوری کانفیگ‌ها از ساب‌لینک‌ها
        try:
            with open(sublinks_file, 'r', encoding='utf-8') as f:
                sublinks_data = json.load(f)

            for sublink in sublinks_data.get('sublinks', []):
                url = sublink.get('url')
                protocols = sublink.get('protocols', [])
                sublink_configs = fetch_configs_from_sublink(url, protocols)
                configs.extend(sublink_configs)
        except FileNotFoundError:
            logging.warning(f"{sublinks_file} not found, skipping sublinks")

        # حذف موارد تکراری
        configs = list(dict.fromkeys(configs))

        # ذخیره کانفیگ‌ها در config.txt با تگ شماره‌دار
        with open(output_file, 'w', encoding='utf-8') as f:
            for idx, config in enumerate(configs, start=1):
                tagged_config = f"{config}#@SiNAVM-{idx}"
                f.write(tagged_config + '\n')
        logging.info(f"Saved {len(configs)} configs to {output_file}")

    except Exception as e:
        logging.error(f"Error: {e}")
    finally:
        await client.disconnect()

# اجرای اسکریپت
if __name__ == '__main__':
    asyncio.run(main())
