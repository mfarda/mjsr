import requests
import urllib3
from pathlib import Path
from .utils import CONFIG, ensure_dir
import concurrent.futures
from tqdm import tqdm


# Suppress SSL warnings for reconnaissance
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run(args, config, logger):
    # Handle independent mode
    if args.independent:
        return run_independent(args, config, logger)
    
    # Normal mode - process all targets
    for target in args.targets:
        target_dir = Path(args.output) / target
        ensure_dir(target_dir)
        logger.log('INFO', f"[{target}] Verifying live JavaScript files...")
        all_js_file = Path(args.input) if args.input else target_dir / CONFIG['files']['all_js']
        live_js_file = target_dir / CONFIG['files']['live_js']
        if not all_js_file.exists():
            logger.log('ERROR', f"[{target}] No JS URLs file found")
            continue
        
        # Read all JS URLs
        with open(all_js_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            logger.log('WARN', f"[{target}] No JS URLs found to verify")
            continue
        
        logger.log('INFO', f"[{target}] Checking {len(urls)} JS URLs...")
        
        # Use ThreadPoolExecutor for concurrent requests
        max_workers = min(20, len(urls))  # Limit concurrent requests
        live_urls = []
        
        def check_url(url):
            try:
                response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
                if 200 <= response.status_code < 400:  # 20x and 30x status codes
                    return url
                return None
            except requests.exceptions.RequestException:
                return None
        
        with tqdm(total=len(urls), desc=f"[{target}] Verifying URLs", unit="url") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_url = {executor.submit(check_url, url): url for url in urls}
                for future in concurrent.futures.as_completed(future_to_url):
                    result = future.result()
                    if result:
                        live_urls.append(result)
                    pbar.update(1)
        
        # Save live URLs
        with open(live_js_file, 'w') as f:
            for url in live_urls:
                f.write(f"{url}\n")
        
        logger.log('SUCCESS', f"[{target}] Found {len(live_urls)} live JS URLs out of {len(urls)} total")
        return len(live_urls) > 0

def run_independent(args, config, logger):
    """Run verify module independently with custom input file"""
    input_file = Path(args.input)
    if not input_file.exists():
        logger.log('ERROR', f"Input file not found: {input_file}")
        return False
    
    # Determine output file
    if args.output:
        output_dir = Path(args.output)
        ensure_dir(output_dir)
        output_file = output_dir / "live_urls.txt"
    else:
        # Use same directory as input file
        output_file = input_file.parent / "live_urls.txt"
    
    logger.log('INFO', f"Verifying URLs from: {input_file}")
    logger.log('INFO', f"Output will be saved to: {output_file}")
    
    # Read all URLs
    with open(input_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    if not urls:
        logger.log('WARN', "No URLs found to verify")
        return False
    
    logger.log('INFO', f"Checking {len(urls)} URLs...")
    
    # Use ThreadPoolExecutor for concurrent requests
    max_workers = min(20, len(urls))
    live_urls = []
    
    def check_url(url):
        try:
            response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            if 200 <= response.status_code < 400:
                return url
            return None
        except requests.exceptions.RequestException:
            return None
    
    with tqdm(total=len(urls), desc="Verifying URLs", unit="url") as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(check_url, url): url for url in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                result = future.result()
                if result:
                    live_urls.append(result)
                pbar.update(1)
    
    # Save live URLs
    with open(output_file, 'w') as f:
        for url in live_urls:
            f.write(f"{url}\n")
    
    logger.log('SUCCESS', f"Found {len(live_urls)} live URLs out of {len(urls)} total")
    logger.log('INFO', f"Results saved to: {output_file}")
    
    return len(live_urls) > 0