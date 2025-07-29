import asyncio
import aiohttp
from pathlib import Path
from .utils import CONFIG, ensure_dir
import re
import hashlib

# Optional: Import deduplication module for pre-download hash checking
# from .deduplication import calculate_file_hash_before_download

def sanitize_filename(url):
    filename = re.sub(r'^https?://', '', url)
    filename = re.sub(r'[\\/*?:"<>|]', '_', filename)
    filename = filename.replace('/', '_')
    if not filename.endswith('.js'):
        filename += '.js'
    return filename

async def run(args, config, logger):
    # Handle independent mode
    if args.independent:
        return await run_independent(args, config, logger)
    
    # Normal mode - process all targets
    for target in args.targets:
        target_dir = Path(args.output) / target
        ensure_dir(target_dir)
        logger.log('INFO', f"[{target}] Downloading JavaScript files...")
        
        # Use deduplicated file if available, otherwise fall back to live_js
        input_file = Path(args.input) if args.input else target_dir / CONFIG['files']['deduplicated_js']
        if not input_file.exists():
            input_file = target_dir / CONFIG['files']['live_js']
        
        js_files_dir = target_dir / CONFIG['dirs']['js_files']
        ensure_dir(js_files_dir)
        if not input_file.exists():
            logger.log('WARN', f"[{target}] No live JS URLs found.")
            continue
        with open(input_file, 'r') as f:
            urls = [line.split()[0] for line in f if line.strip()]
        if not urls:
            logger.log('WARN', f"[{target}] No live JS URLs found.")
            continue
        hash_set = set()
        hash_lock = asyncio.Lock()
        semaphore = asyncio.Semaphore(CONFIG['max_concurrent_downloads'])

        async def download_file(session, url, index, total):
            retries = 3
            async with semaphore:
                for attempt in range(retries):
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=CONFIG['timeouts']['download'])) as response:
                            if response.status == 200:
                                content = await response.read()
                                file_hash = hashlib.sha256(content).hexdigest()
                                logger.log('DEBUG', f"[{target}] [{index+1}/{total}] Hash: {file_hash[:16]}... for URL: {url}")
                                async with hash_lock:
                                    if file_hash in hash_set:
                                        logger.log('INFO', f"[{target}] [{index+1}/{total}] Duplicate content skipped: {url} (hash_set size: {len(hash_set)})")
                                        return False
                                    hash_set.add(file_hash)
                                    logger.log('DEBUG', f"[{target}] [{index+1}/{total}] Added hash to set. New size: {len(hash_set)}")
                                base_filename = sanitize_filename(url)
                                filename = f"{base_filename}__{file_hash}.js"
                                file_path = js_files_dir / filename
                                if file_path.exists():
                                    logger.log('INFO', f"[{target}] [{index+1}/{total}] Duplicate filename skipped: {url}")
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
        async with aiohttp.ClientSession() as session:
            tasks = [download_file(session, url, i, len(urls)) for i, url in enumerate(urls)]
            await asyncio.gather(*tasks)

async def run_independent(args, config, logger):
    """Run download module independently with custom input file"""
    input_file = Path(args.input)
    if not input_file.exists():
        logger.log('ERROR', f"Input file not found: {input_file}")
        return False
    
    # Determine output directory
    if args.output:
        output_dir = Path(args.output)
        ensure_dir(output_dir)
    else:
        # Use same directory as input file
        output_dir = input_file.parent / "downloaded_js"
        ensure_dir(output_dir)
    
    logger.log('INFO', f"Downloading JS files from: {input_file}")
    logger.log('INFO', f"Files will be saved to: {output_dir}")
    
    # Read URLs
    with open(input_file, 'r') as f:
        urls = [line.strip().split()[0] for line in f if line.strip()]
    
    if not urls:
        logger.log('WARN', "No URLs found to download")
        return False
    
    logger.log('INFO', f"Downloading {len(urls)} JS files...")
    
    hash_set = set()
    hash_lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(CONFIG['max_concurrent_downloads'])
    downloaded_count = 0

    async def download_file(session, url, index, total):
        nonlocal downloaded_count
        retries = 3
        async with semaphore:
            for attempt in range(retries):
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=CONFIG['timeouts']['download'])) as response:
                        if response.status == 200:
                            content = await response.read()
                            file_hash = hashlib.sha256(content).hexdigest()
                            
                            async with hash_lock:
                                if file_hash in hash_set:
                                    logger.log('INFO', f"[{index+1}/{total}] Duplicate content skipped: {url}")
                                    return False
                                hash_set.add(file_hash)
                            
                            base_filename = sanitize_filename(url)
                            filename = f"{base_filename}__{file_hash}.js"
                            file_path = output_dir / filename
                            
                            if file_path.exists():
                                logger.log('INFO', f"[{index+1}/{total}] Duplicate filename skipped: {url}")
                                return False
                            
                            with open(file_path, 'wb') as f:
                                f.write(content)
                            
                            downloaded_count += 1
                            logger.log('SUCCESS', f"[{index+1}/{total}] Downloaded: {filename}")
                            return True
                        else:
                            logger.log('ERROR', f"[{index+1}/{total}] Failed: {url} (status: {response.status})")
                            return False
                except Exception as e:
                    if attempt < retries - 1:
                        await asyncio.sleep(2)
                        logger.log('WARN', f"[{index+1}/{total}] Retry {attempt+1} for {url}")
                    else:
                        logger.log('ERROR', f"[{index+1}/{total}] Failed: {url} - {str(e)}")
                        return False
    
    async with aiohttp.ClientSession() as session:
        tasks = [download_file(session, url, i, len(urls)) for i, url in enumerate(urls)]
        await asyncio.gather(*tasks)
    
    logger.log('SUCCESS', f"Downloaded {downloaded_count} unique JS files out of {len(urls)} URLs")
    logger.log('INFO', f"Files saved to: {output_dir}")
    
    return downloaded_count > 0