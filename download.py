import asyncio
from pathlib import Path
from .utils import CONFIG, ensure_dir
import re

async def run(args, config, logger):
    for target in args.targets:
        target_dir = Path(args.output) / target
        ensure_dir(target_dir)
        logger.log('INFO', f"[{target}] Downloading JavaScript files...")
        live_js_file = Path(args.input) if args.input else target_dir / CONFIG['files']['live_js']
        js_files_dir = target_dir / CONFIG['dirs']['js_files']
        ensure_dir(js_files_dir)
        if not live_js_file.exists():
            logger.log('WARN', f"[{target}] No live JS URLs found.")
            continue
        with open(live_js_file, 'r') as f:
            urls = [line.split()[0] for line in f if line.strip()]
        if not urls:
            logger.log('WARN', f"[{target}] No live JS URLs found.")
            continue
        semaphore = asyncio.Semaphore(CONFIG['max_concurrent_downloads'])
        async def download_file(session, url, index, total):
            import aiohttp
            retries = 3
            async with semaphore:
                for attempt in range(retries):
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=CONFIG['timeouts']['download'])) as response:
                            if response.status == 200:
                                content = await response.read()
                                filename = sanitize_filename(url)
                                file_path = js_files_dir / filename
                                if file_path.exists():
                                    logger.log('INFO', f"[{target}] [{index+1}/{total}] Duplicate skipped: {url}")
                                    return False
                                with open(file_path, 'wb') as f:
                                    f.write(content)
                                logger.log('SUCCESS', f"[{target}] [{index+1}/{total}] Downloaded: {filename}")
                                return True
                            else:
                                logger.log('ERROR', f"[{target}] [{index+1}/{total}] Failed: {url} (status: {response.status})")
                                return False
                    except Exception as e:
                        if attempt < retries - 1:
                            await asyncio.sleep(2)
                            logger.log('WARN', f"[{target}] [{index+1}/{total}] Retry {attempt+1} for {url}")
                        else:
                            logger.log('ERROR', f"[{target}] [{index+1}/{total}] Failed: {url} - {str(e)}")
                            return False
        import aiohttp
        tasks = [download_file(aiohttp.ClientSession(), url, i, len(urls)) for i, url in enumerate(urls)]
        await asyncio.gather(*tasks)

def sanitize_filename(url):
    # Remove scheme and replace unsafe chars
    filename = re.sub(r'^https?://', '', url)
    filename = re.sub(r'[\\/*?:"<>|]', '_', filename)
    filename = filename.replace('/', '_')
    if not filename.endswith('.js'):
        filename += '.js'
    return filename