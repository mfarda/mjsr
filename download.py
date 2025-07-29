import asyncio
import aiohttp
from pathlib import Path
from tqdm import tqdm
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
        
        logger.log('INFO', f"[{target}] Found {len(urls)} JS URLs to download")
        
        hash_set = set()
        hash_lock = asyncio.Lock()
        semaphore = asyncio.Semaphore(CONFIG['max_concurrent_downloads'])
        downloaded_count = 0
        skipped_count = 0
        failed_count = 0

        async def download_file(session, url, pbar):
            nonlocal downloaded_count, skipped_count, failed_count
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
                                        skipped_count += 1
                                        pbar.set_postfix({
                                            'Downloaded': downloaded_count,
                                            'Skipped': skipped_count,
                                            'Failed': failed_count
                                        })
                                        return False
                                    hash_set.add(file_hash)
                                
                                base_filename = sanitize_filename(url)
                                filename = f"{base_filename}__{file_hash}.js"
                                file_path = js_files_dir / filename
                                if file_path.exists():
                                    skipped_count += 1
                                    pbar.set_postfix({
                                        'Downloaded': downloaded_count,
                                        'Skipped': skipped_count,
                                        'Failed': failed_count
                                    })
                                    return False
                                
                                with open(file_path, 'wb') as f:
                                    f.write(content)
                                
                                downloaded_count += 1
                                pbar.set_postfix({
                                    'Downloaded': downloaded_count,
                                    'Skipped': skipped_count,
                                    'Failed': failed_count
                                })
                                return True
                            else:
                                failed_count += 1
                                pbar.set_postfix({
                                    'Downloaded': downloaded_count,
                                    'Skipped': skipped_count,
                                    'Failed': failed_count
                                })
                                return False
                    except Exception as e:
                        if attempt < retries - 1:
                            await asyncio.sleep(2)
                        else:
                            failed_count += 1
                            pbar.set_postfix({
                                'Downloaded': downloaded_count,
                                'Skipped': skipped_count,
                                'Failed': failed_count
                            })
                            return False

        async with aiohttp.ClientSession() as session:
            with tqdm(total=len(urls), desc=f"[{target}] Downloading JS files", unit="file") as pbar:
                tasks = [download_file(session, url, pbar) for url in urls]
                await asyncio.gather(*tasks)
                pbar.update(len(urls))  # Ensure progress bar completes
        
        logger.log('SUCCESS', f"[{target}] Download complete: {downloaded_count} downloaded, {skipped_count} skipped, {failed_count} failed")

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
    
    # Read URLs from input file
    with open(input_file, 'r') as f:
        urls = [line.strip().split()[0] for line in f if line.strip()]
    
    if not urls:
        logger.log('WARN', "No URLs found to download")
        return False
    
    logger.log('INFO', f"Found {len(urls)} JS URLs to download")
    
    hash_set = set()
    hash_lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(CONFIG['max_concurrent_downloads'])
    downloaded_count = 0
    skipped_count = 0
    failed_count = 0

    async def download_file(session, url, pbar):
        nonlocal downloaded_count, skipped_count, failed_count
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
                                    skipped_count += 1
                                    pbar.set_postfix({
                                        'Downloaded': downloaded_count,
                                        'Skipped': skipped_count,
                                        'Failed': failed_count
                                    })
                                    return False
                                hash_set.add(file_hash)
                            
                            base_filename = sanitize_filename(url)
                            filename = f"{base_filename}__{file_hash}.js"
                            file_path = output_dir / filename
                            if file_path.exists():
                                skipped_count += 1
                                pbar.set_postfix({
                                    'Downloaded': downloaded_count,
                                    'Skipped': skipped_count,
                                    'Failed': failed_count
                                })
                                return False
                            
                            with open(file_path, 'wb') as f:
                                f.write(content)
                            
                            downloaded_count += 1
                            pbar.set_postfix({
                                'Downloaded': downloaded_count,
                                'Skipped': skipped_count,
                                'Failed': failed_count
                            })
                            return True
                        else:
                            failed_count += 1
                            pbar.set_postfix({
                                'Downloaded': downloaded_count,
                                'Skipped': skipped_count,
                                'Failed': failed_count
                            })
                            return False
                except Exception as e:
                    if attempt < retries - 1:
                        await asyncio.sleep(2)
                    else:
                        failed_count += 1
                        pbar.set_postfix({
                            'Downloaded': downloaded_count,
                            'Skipped': skipped_count,
                            'Failed': failed_count
                        })
                        return False

    async with aiohttp.ClientSession() as session:
        with tqdm(total=len(urls), desc="Downloading JS files", unit="file") as pbar:
            tasks = [download_file(session, url, pbar) for url in urls]
            await asyncio.gather(*tasks)
            pbar.update(len(urls))  # Ensure progress bar completes
    
    logger.log('SUCCESS', f"Download complete: {downloaded_count} downloaded, {skipped_count} skipped, {failed_count} failed")
    logger.log('INFO', f"Files saved to: {output_dir}")
    
    return downloaded_count > 0