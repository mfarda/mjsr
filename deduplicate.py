import requests
from pathlib import Path
from .utils import CONFIG, ensure_dir
import concurrent.futures
from tqdm import tqdm
import hashlib
from urllib.parse import urlparse

def run(args, config, logger):
    """
    Deduplicate JS URLs by checking for identical content using HTTP headers
    and conditional requests to avoid downloading duplicate files.
    """
    # Handle independent mode
    if args.independent:
        return run_independent(args, config, logger)
    
    # Normal mode - process all targets
    for target in args.targets:
        target_dir = Path(args.output) / target
        ensure_dir(target_dir)
        logger.log('INFO', f"[{target}] Deduplicating JavaScript URLs...")
        
        # Determine input and output files
        input_file = Path(args.input) if args.input else target_dir / CONFIG['files']['live_js']
        output_file = target_dir / CONFIG['files']['deduplicated_js']
        
        if not input_file.exists():
            logger.log('ERROR', f"[{target}] No input file found for deduplication")
            continue
        
        # Read URLs
        with open(input_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            logger.log('WARN', f"[{target}] No URLs found to deduplicate")
            continue
        
        logger.log('INFO', f"[{target}] Deduplicating {len(urls)} JS URLs...")
        
        # Group URLs by domain for better organization
        domain_groups = {}
        for url in urls:
            domain = urlparse(url).netloc
            if domain not in domain_groups:
                domain_groups[domain] = []
            domain_groups[domain].append(url)
        
        unique_urls = []
        duplicate_count = 0
        
        # Process each domain separately
        for domain, domain_urls in domain_groups.items():
            logger.log('INFO', f"[{target}] Processing domain: {domain} ({len(domain_urls)} URLs)")
            
            # Use ThreadPoolExecutor for concurrent HEAD requests
            max_workers = min(10, len(domain_urls))
            
            def check_url_headers(url):
                try:
                    # First try HEAD request to get headers
                    response = requests.head(url, timeout=10, allow_redirects=True, verify=False)
                    if response.status_code == 200:
                        # Get content identifiers
                        etag = response.headers.get('ETag', '').strip('"')
                        content_length = response.headers.get('Content-Length', '')
                        last_modified = response.headers.get('Last-Modified', '')
                        
                        # Create a content identifier
                        content_id = f"{etag}_{content_length}_{last_modified}"
                        
                        return {
                            'url': url,
                            'content_id': content_id,
                            'etag': etag,
                            'content_length': content_length,
                            'last_modified': last_modified
                        }
                    return None
                except requests.exceptions.RequestException:
                    return None
            
            # Get headers for all URLs in this domain
            content_map = {}
            with tqdm(total=len(domain_urls), desc=f"[{target}] Checking {domain}", unit="url") as pbar:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_url = {executor.submit(check_url_headers, url): url for url in domain_urls}
                    for future in concurrent.futures.as_completed(future_to_url):
                        result = future.result()
                        if result:
                            content_id = result['content_id']
                            if content_id in content_map:
                                duplicate_count += 1
                                logger.log('DEBUG', f"[{target}] Duplicate found: {result['url']} (same as {content_map[content_id]['url']})")
                            else:
                                content_map[content_id] = result
                                unique_urls.append(result['url'])
                        pbar.update(1)
        
        # Save deduplicated URLs
        with open(output_file, 'w') as f:
            for url in unique_urls:
                f.write(f"{url}\n")
        
        logger.log('SUCCESS', f"[{target}] Deduplication complete: {len(unique_urls)} unique URLs (removed {duplicate_count} duplicates)")
        return len(unique_urls) > 0

def run_independent(args, config, logger):
    """Run deduplicate module independently with custom input file"""
    input_file = Path(args.input)
    if not input_file.exists():
        logger.log('ERROR', f"Input file not found: {input_file}")
        return False
    
    # Determine output file
    if args.output:
        output_dir = Path(args.output)
        ensure_dir(output_dir)
        output_file = output_dir / "deduplicated_urls.txt"
    else:
        # Use same directory as input file
        output_file = input_file.parent / "deduplicated_urls.txt"
    
    logger.log('INFO', f"Deduplicating URLs from: {input_file}")
    logger.log('INFO', f"Output will be saved to: {output_file}")
    
    # Read URLs
    with open(input_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    if not urls:
        logger.log('WARN', "No URLs found to deduplicate")
        return False
    
    logger.log('INFO', f"Deduplicating {len(urls)} URLs...")
    
    # Group URLs by domain for better organization
    domain_groups = {}
    for url in urls:
        domain = urlparse(url).netloc
        if domain not in domain_groups:
            domain_groups[domain] = []
        domain_groups[domain].append(url)
    
    unique_urls = []
    duplicate_count = 0
    
    # Process each domain separately
    for domain, domain_urls in domain_groups.items():
        logger.log('INFO', f"Processing domain: {domain} ({len(domain_urls)} URLs)")
        
        # Use ThreadPoolExecutor for concurrent HEAD requests
        max_workers = min(10, len(domain_urls))
        
        def check_url_headers(url):
            try:
                # First try HEAD request to get headers
                response = requests.head(url, timeout=10, allow_redirects=True, verify=False)
                if response.status_code == 200:
                    # Get content identifiers
                    etag = response.headers.get('ETag', '').strip('"')
                    content_length = response.headers.get('Content-Length', '')
                    last_modified = response.headers.get('Last-Modified', '')
                    
                    # Create a content identifier
                    content_id = f"{etag}_{content_length}_{last_modified}"
                    
                    return {
                        'url': url,
                        'content_id': content_id,
                        'etag': etag,
                        'content_length': content_length,
                        'last_modified': last_modified
                    }
                return None
            except requests.exceptions.RequestException:
                return None
        
        # Get headers for all URLs in this domain
        content_map = {}
        with tqdm(total=len(domain_urls), desc=f"Checking {domain}", unit="url") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_url = {executor.submit(check_url_headers, url): url for url in domain_urls}
                for future in concurrent.futures.as_completed(future_to_url):
                    result = future.result()
                    if result:
                        content_id = result['content_id']
                        if content_id in content_map:
                            duplicate_count += 1
                            logger.log('DEBUG', f"Duplicate found: {result['url']} (same as {content_map[content_id]['url']})")
                        else:
                            content_map[content_id] = result
                            unique_urls.append(result['url'])
                    pbar.update(1)
    
    # Save deduplicated URLs
    with open(output_file, 'w') as f:
        for url in unique_urls:
            f.write(f"{url}\n")
    
    logger.log('SUCCESS', f"Deduplication complete: {len(unique_urls)} unique URLs (removed {duplicate_count} duplicates)")
    logger.log('INFO', f"Results saved to: {output_file}")
    
    return len(unique_urls) > 0

def calculate_file_hash_before_download(url, logger, target=""):
    """
    Calculate file hash before downloading using conditional requests.
    This is useful for deduplication without downloading the full content.
    
    Returns:
        tuple: (hash, success) where hash is the file hash and success is boolean
    """
    try:
        # First, try to get ETag from HEAD request
        head_response = requests.head(url, timeout=10, allow_redirects=True, verify=False)
        
        if head_response.status_code == 200:
            etag = head_response.headers.get('ETag', '').strip('"')
            if etag:
                # Use ETag as a reliable content identifier
                logger.log('DEBUG', f"[{target}] Using ETag for {url}: {etag}")
                return etag, True
        
        # If no ETag, try conditional GET with If-None-Match
        if etag:
            get_response = requests.get(url, headers={'If-None-Match': f'"{etag}"'}, 
                                     timeout=10, allow_redirects=True, verify=False)
            if get_response.status_code == 304:  # Not Modified
                logger.log('DEBUG', f"[{target}] File unchanged for {url}")
                return etag, True
        
        # Fallback: download a small portion to calculate hash
        logger.log('DEBUG', f"[{target}] Downloading partial content for hash calculation: {url}")
        response = requests.get(url, stream=True, timeout=10, allow_redirects=True, verify=False)
        
        if response.status_code == 200:
            # Read first 8KB to calculate hash (usually enough for JS files)
            content = response.raw.read(8192)
            file_hash = hashlib.sha256(content).hexdigest()
            response.close()
            return file_hash, True
        
        return None, False
        
    except requests.exceptions.RequestException as e:
        logger.log('ERROR', f"[{target}] Failed to calculate hash for {url}: {str(e)}")
        return None, False

def get_content_hash_map(urls, logger, target=""):
    """
    Get content hash map for a list of URLs without downloading full content.
    Useful for pre-download deduplication.
    
    Returns:
        dict: {content_hash: [urls_with_same_content]}
    """
    content_hash_map = {}
    max_workers = min(10, len(urls))
    
    def process_url(url):
        hash_value, success = calculate_file_hash_before_download(url, logger, target)
        if success and hash_value:
            return url, hash_value
        return None
    
    with tqdm(total=len(urls), desc=f"[{target}] Calculating content hashes", unit="url") as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(process_url, url): url for url in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                result = future.result()
                if result:
                    url, hash_value = result
                    if hash_value not in content_hash_map:
                        content_hash_map[hash_value] = []
                    content_hash_map[hash_value].append(url)
                pbar.update(1)
    
    return content_hash_map 