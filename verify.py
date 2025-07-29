import requests
from pathlib import Path
from .utils import CONFIG, ensure_dir
import concurrent.futures
from tqdm import tqdm


# Suppress SSL warnings for reconnaissance
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run(args, config, logger):
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