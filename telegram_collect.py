import logging
import json
import re
import requests
import os
from telethon.sync import TelegramClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

with open('channels.json', 'r', encoding='utf-8') as file:
    channels = json.load(file)

with open('sublinks.json', 'r', encoding='utf-8') as file:
    sublinks_data = json.load(file)

api_id = os.getenv('TELEGRAM_API_ID')
api_hash = os.getenv('TELEGRAM_API_HASH')
session = os.getenv('TELEGRAM_SESSION')

configs = []

async def main():
    async with TelegramClient('session', api_id, api_hash) as client:
        logging.info("Connecting to Telegram...")
        await client.connect()
        if not await client.is_user_authorized():
            logging.error("Failed to connect to Telegram")
            return
        logging.info("Successfully connected to Telegram")

        for channel, protocols in channels.items():
            logging.info(f"Processing channel: {channel}")
            try:
                async for message in client.iter_messages(channel, limit=40):
                    if message.text:
                        for protocol in protocols:
                            pattern = rf'({protocol}:\/\/[^\s<]+)'
                            matches = re.findall(pattern, message.text)
                            for match in matches:
                                configs.append(match)
            except Exception as e:
                logging.error(f"Error processing channel {channel}: {e}")

        for sublink in sublinks_data['sublinks']:
            url = sublink['url']
            protocols = sublink['protocols']
            logging.info(f"Fetching configs from {url}")
            try:
                response = requests.get(url)
                response.raise_for_status()
                sublink_configs = response.text.strip().split('\n')
                for config in sublink_configs:
                    for protocol in protocols:
                        if config.startswith(f"{protocol}://"):
                            configs.append(config)
            except Exception as e:
                logging.error(f"Error fetching sublink {url}: {e}")

        # ذخیره کانفیگ‌ها با نام‌های @sinavm-<index> یا @sinavm-lite-<index>
        output_file = 'config.txt'
        name_prefix = '@sinavm-lite' if os.getcwd().endswith('lite') else '@sinavm'
        logging.info(f"Saving {len(configs)} configs to {output_file}")
        with open(output_file, 'w', encoding='utf-8') as f:
            for i, config in enumerate(configs, 1):
                config_parts = config.split('#', 1)
                new_config = config_parts[0] + f"#{name_prefix}-{i}"
                f.write(new_config + '\n')

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())
