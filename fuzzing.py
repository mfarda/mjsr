import subprocess
import json
import os
import re
import time
from pathlib import Path
from tqdm import tqdm
from urllib.parse import urlparse
from .utils import CONFIG, ensure_dir

def run(args, config, logger):
    """Run fuzzing module in chain mode or independent mode"""
    # Handle independent mode
    if args.independent:
        return run_independent(args, config, logger)
    
    # Chain mode - process all targets
    for target in args.targets:
        target_dir = Path(args.output) / target
        ensure_dir(target_dir)
        
        # Determine input file (use live_js_urls.txt from previous steps)
        url_list_file = args.input if args.input else (target_dir / CONFIG['files']['live_js'])
        if not Path(url_list_file).exists():
            logger.log('ERROR', f"[{target}] No input URL list file found: {url_list_file}")
            continue
        
        # Run fuzzing for this target
        run_fuzzing_for_target(target, target_dir, url_list_file, args, config, logger)

def run_independent(args, config, logger):
    """Run fuzzing module independently with custom input file"""
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
        output_dir = input_file.parent / "fuzzing_results"
        ensure_dir(output_dir)
    
    logger.log('INFO', f"Running fuzzing on URLs from: {input_file}")
    logger.log('INFO', f"Results will be saved to: {output_dir}")
    
    # Run fuzzing
    success = run_fuzzing_independent(input_file, output_dir, args, config, logger)
    
    if success:
        logger.log('SUCCESS', f"Fuzzing complete! Results saved to: {output_dir}")
    
    return success

def run_fuzzing_for_target(target, target_dir, url_list_file, args, config, logger):
    """Run fuzzing for a specific target in chain mode"""
    logger.log('INFO', f"[{target}] Starting fuzzing workflow...")
    
    # Step 1: Get JS files from deduplicated file or downloaded files or live URLs
    js_urls = []
    
    # First try to use deduplicated JS file
    deduplicated_file = target_dir / CONFIG['files']['deduplicated_js']
    if deduplicated_file.exists():
        logger.log('INFO', f"[{target}] Using deduplicated JS file as primary input...")
        js_urls = read_js_urls_from_file(deduplicated_file)
        if js_urls:
            logger.log('INFO', f"[{target}] Found {len(js_urls)} URLs from deduplicated file")
        else:
            logger.log('WARN', f"[{target}] Deduplicated file is empty, trying downloaded files...")
    
    # If no URLs from deduplicated file, try downloaded JS files
    if not js_urls:
        js_files_dir = target_dir / CONFIG['dirs']['js_files']
        if js_files_dir.exists():
            js_files = list(js_files_dir.glob("*.js"))
            if js_files:
                logger.log('INFO', f"[{target}] Found {len(js_files)} downloaded JS files, extracting URLs...")
                extracted_urls = extract_urls_from_downloaded_js_files(js_files, logger)
                if extracted_urls:
                    # Check if extracted URLs are suitable for fuzzing (have absolute URLs)
                    suitable_urls = [url for url in extracted_urls if url.startswith(('http://', 'https://'))]
                    if suitable_urls:
                        js_urls = suitable_urls
                        logger.log('INFO', f"[{target}] Using {len(js_urls)} absolute URLs from downloaded JS files")
                        logger.log('INFO', f"[{target}] Total extracted URLs: {len(extracted_urls)}, Absolute URLs: {len(js_urls)}")
                        logger.log('DEBUG', f"[{target}] Absolute URLs: {js_urls}")
                        logger.log('DEBUG', f"[{target}] Filtered out URLs: {[url for url in extracted_urls if not url.startswith(('http://', 'https://'))]}")
                    else:
                        logger.log('INFO', f"[{target}] No absolute URLs found in downloaded files, will use live URLs")
                        logger.log('INFO', f"[{target}] Total extracted URLs: {len(extracted_urls)}, Absolute URLs: 0")
                else:
                    logger.log('INFO', f"[{target}] No URLs extracted from downloaded files, will use live URLs")
    
    # If no suitable URLs from deduplicated or downloaded files, fall back to live JS URLs
    if not js_urls:
        logger.log('INFO', f"[{target}] Using live JS URLs from previous steps...")
        js_urls = read_js_urls_from_file(url_list_file)
        if not js_urls:
            logger.log('ERROR', f"[{target}] No live JS URLs found in {url_list_file}")
            return False
        logger.log('INFO', f"[{target}] Found {len(js_urls)} live JS URLs")
    
    # Step 2: Get unique paths from JS URLs
    unique_paths = get_unique_paths_from_urls(js_urls, logger)
    breakpoint()  # DEBUG: Inspect unique_paths here
    logger.log('INFO', f"[{target}] Found {len(unique_paths)} unique paths to fuzz")
    
    # Validate that we have valid paths for fuzzing
    if not unique_paths:
        logger.log('WARN', f"[{target}] No valid paths found from extracted URLs. Trying fallback to live URLs...")
        
        # Fallback: Try to get paths from live URLs
        live_urls = read_js_urls_from_file(url_list_file)
        if live_urls:
            logger.log('INFO', f"[{target}] Using {len(live_urls)} live URLs as fallback")
            unique_paths = get_unique_paths_from_urls(live_urls, logger)
            logger.log('INFO', f"[{target}] Fallback found {len(unique_paths)} unique paths to fuzz")
        
        if not unique_paths:
            logger.log('ERROR', f"[{target}] No valid paths found for fuzzing. Check if URLs are properly formatted.")
            logger.log('DEBUG', f"[{target}] Extracted URLs that failed: {js_urls}")
            return False
    
    # Create ffuf results directory
    ffuf_results_dir = target_dir / CONFIG['dirs']['ffuf_results']
    ensure_dir(ffuf_results_dir)
    
    # Run fuzzing based on mode
    success = execute_fuzzing_by_mode(target, js_urls, unique_paths, ffuf_results_dir, args, config, logger)
    
    if success:
        # Save and analyze results
        save_fuzzing_results(target, target_dir, ffuf_results_dir, js_urls, logger)
    
    return success

def run_fuzzing_independent(input_file, output_dir, args, config, logger):
    """Run fuzzing independently with custom input file"""
    # Step 1: Get JS URLs from input (could be deduplicated file, downloaded files directory, or URL list)
    input_path = Path(input_file)
    js_urls = []
    
    # Check if input is a deduplicated file
    if input_path.is_file() and input_path.name == CONFIG['files']['deduplicated_js']:
        logger.log('INFO', f"Using deduplicated JS file as input: {input_path}")
        js_urls = read_js_urls_from_file(input_file)
        if js_urls:
            logger.log('INFO', f"Found {len(js_urls)} URLs from deduplicated file")
        else:
            logger.log('WARN', f"Deduplicated file is empty")
    
    # If no URLs from deduplicated file, check if input is a directory of downloaded JS files
    if not js_urls and input_path.is_dir():
        js_files = list(input_path.glob("*.js"))
        if js_files:
            logger.log('INFO', f"Found {len(js_files)} downloaded JS files, extracting URLs...")
            js_urls = extract_urls_from_downloaded_js_files(js_files, logger)
            if js_urls:
                logger.log('INFO', f"Extracted {len(js_urls)} URLs from downloaded JS files")
    
    # If still no URLs, treat input as a URL list file
    if not js_urls:
        js_urls = read_js_urls_from_file(input_file)
        if not js_urls:
            logger.log('ERROR', f"No JS URLs found in {input_file}")
            return False
        logger.log('INFO', f"Found {len(js_urls)} JS URLs from file")
    
    # Step 2: Get unique paths from JS URLs
    unique_paths = get_unique_paths_from_urls(js_urls, logger)
    logger.log('INFO', f"Found {len(unique_paths)} unique paths to fuzz")
    
    # Create ffuf results directory
    ffuf_results_dir = output_dir / "ffuf_results"
    ensure_dir(ffuf_results_dir)
    
    # Run fuzzing based on mode
    success = execute_fuzzing_by_mode("independent", js_urls, unique_paths, ffuf_results_dir, args, config, logger)
    
    if success:
        # Save results for independent mode
        save_independent_fuzzing_results(input_file, output_dir, ffuf_results_dir, js_urls, logger)
    
    return success

def read_js_urls_from_file(file_path):
    """Read JS URLs from file"""
    urls = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and line.endswith('.js'):
                    urls.append(line)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return urls

def get_unique_paths_from_urls(urls, logger):
    """Step 2: Get unique paths from live JS files"""
    unique_paths = {}
    
    logger.log('DEBUG', f"Parsing {len(urls)} URLs for unique paths...")
    
    for url in urls:
        try:
            # Handle relative URLs by adding a base scheme and domain
            if url.startswith('//'):
                url = 'https:' + url
            elif url.startswith('/'):
                # This is a relative URL, we need to skip it or handle it differently
                logger.log('DEBUG', f"Skipping relative URL: {url}")
                continue
            elif not url.startswith(('http://', 'https://')):
                # Skip malformed URLs
                logger.log('DEBUG', f"Skipping malformed URL: {url}")
                continue
            
            parsed = urlparse(url)
            
            # Validate parsed URL
            if not parsed.scheme or not parsed.netloc:
                logger.log('DEBUG', f"Skipping invalid URL (missing scheme/netloc): {url}")
                continue
            
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path
            
            logger.log('DEBUG', f"Processing URL: {url}")
            logger.log('DEBUG', f"  - Base URL: {base_url}")
            logger.log('DEBUG', f"  - Path: {path}")
            
            # Get directory path (everything except filename)
            # Handle URLs that might not end with .js but contain .js
            if path.endswith('.js') or '.js' in path:
                # Extract the directory containing the .js file
                if path.endswith('.js'):
                    # Standard case: path ends with .js
                    dir_path = '/'.join(path.split('/')[:-1])
                else:
                    # Case where .js is in the middle of the path
                    js_index = path.find('.js')
                    if js_index != -1:
                        # Find the last slash before .js
                        last_slash = path.rfind('/', 0, js_index)
                        if last_slash != -1:
                            dir_path = path[:last_slash]
                        else:
                            dir_path = '/'
                    else:
                        dir_path = path
                
                if not dir_path:
                    dir_path = '/'
                
                if dir_path not in unique_paths:
                    unique_paths[dir_path] = base_url
                    logger.log('DEBUG', f"Added path: {dir_path} -> {base_url}")
            else:
                logger.log('DEBUG', f"Path does not contain .js: {path}")
        except Exception as e:
            logger.log('DEBUG', f"Error parsing URL {url}: {str(e)}")
            continue
    
    logger.log('DEBUG', f"Found {len(unique_paths)} unique paths: {list(unique_paths.keys())}")
    return unique_paths

def execute_fuzzing_by_mode(target, live_js_urls, unique_paths, ffuf_results_dir, args, config, logger):
    """Execute fuzzing based on the specified mode"""
    
    if args.fuzz_mode == "off":
        logger.log('INFO', f"[{target}] Fuzzing disabled (mode: off)")
        return True
    
    # Step 3: Get unique JS filenames (for permute mode)
    unique_js_filenames = []
    if args.fuzz_mode in ["permutation", "both"]:
        unique_js_filenames = get_unique_js_filenames(live_js_urls)
        breakpoint()  # DEBUG: Inspect unique_js_filenames here
        logger.log('INFO', f"[{target}] Found {len(unique_js_filenames)} unique JS filenames for permutation")
    
    # Generate permutation wordlist if needed
    permutation_wordlist = None
    if args.fuzz_mode in ["permutation", "both"]:
        permutation_wordlist = generate_permutation_wordlist(target, unique_js_filenames, ffuf_results_dir, logger)
    
    # Execute fuzzing for each unique path
    total_paths = len(unique_paths)
    logger.log('INFO', f"[{target}] Starting fuzzing on {total_paths} unique paths")
    
    with tqdm(total=total_paths, desc=f"[{target}] Fuzzing paths", unit="path") as pbar:
        for dir_path, base_url in unique_paths.items():
            try:
                execute_fuzzing_for_path(
                    target, base_url, dir_path, ffuf_results_dir,
                    args, permutation_wordlist, logger
                )
            except KeyboardInterrupt:
                logger.log('WARN', f"[{target}] Fuzzing interrupted by user")
                break
            except Exception as e:
                logger.log('ERROR', f"[{target}] Error fuzzing path {dir_path}: {str(e)}")
                continue
            pbar.update(1)
    
    return True

def get_unique_js_filenames(urls):
    """Step 3: Get unique JS filenames from URLs"""
    filenames = set()
    
    for url in urls:
        try:
            parsed = urlparse(url)
            filename = parsed.path.split('/')[-1]
            if filename and filename.endswith('.js'):
                filenames.add(filename)
        except Exception as e:
            continue
    
    return list(filenames)

def generate_permutation_wordlist(target, js_filenames, ffuf_results_dir, logger):
    """Step 4: Generate permutation wordlist from unique JS filenames"""
    if not js_filenames:
        logger.log('WARN', f"[{target}] No JS filenames found for permutation generation")
        return None
    
    logger.log('INFO', f"[{target}] Generating permutation wordlist from {len(js_filenames)} JS filenames...")
    
    # Hardcoded prefixes and suffixes
    prefixes = [
        'app', 'lib', 'test', 'spec', 'src', 'dist', 'build', 'vendor', 'node', 'client', 'server', 'common', '_' 
    ]
    
    suffixes = [
        'app', 'lib', 'test', 'spec', 'src', 'dist', 'build', 'vendor', 'node', 'client', 'server', 'common', '_' 
    ]
    
    
    separators = ['', '-', '_', '.']
    
    # Generate permutations
    permutations = set()
    
    for filename in js_filenames:
        # Extract base name (remove .js extension)
        base_name = filename.replace('.js', '')
        
        # Add original base name
        permutations.add(base_name)
        
        # Generate prefix combinations
        for prefix in prefixes:
            for sep in separators:
                permutations.add(f"{prefix}{sep}{base_name}")
                permutations.add(f"{base_name}{sep}{prefix}")
        
        # Generate suffix combinations
        for suffix in suffixes:
            for sep in separators:
                permutations.add(f"{base_name}{sep}{suffix}")
                permutations.add(f"{suffix}{sep}{base_name}")
    
    # Save permutation wordlist
    permutation_wordlist = ffuf_results_dir / "permutation_wordlist.txt"
    with open(permutation_wordlist, 'w') as f:
        f.write('\n'.join(sorted(permutations)))
    
    logger.log('SUCCESS', f"[{target}] Generated {len(permutations)} permutation words")
    return permutation_wordlist

def execute_fuzzing_for_path(target, base_url, dir_path, ffuf_results_dir, args, permutation_wordlist, logger):
    """Execute fuzzing for a specific path"""
    
    # Build fuzz URL
    fuzz_url = f"{base_url}{dir_path}/FUZZ.{args.fuzz_extensions}"
    safe_path_name = dir_path.strip('/').replace('/', '_') or 'root'
    
    # Enhanced logging for fuzz URL construction
    logger.log('INFO', f"[{target}] Starting fuzzing for path: {dir_path}")
    logger.log('DEBUG', f"[{target}] Building fuzz URL:")
    logger.log('DEBUG', f"[{target}]   Base URL: '{base_url}'")
    logger.log('DEBUG', f"[{target}]   Dir path: '{dir_path}'")
    logger.log('DEBUG', f"[{target}]   Extensions: '{args.fuzz_extensions}'")
    logger.log('DEBUG', f"[{target}]   Final fuzz URL: '{fuzz_url}'")
    logger.log('DEBUG', f"[{target}]   Safe path name: '{safe_path_name}'")
    
    # Run wordlist fuzzing
    if args.fuzz_mode in ["wordlist", "both"]:
        if not args.fuzz_wordlist:
            logger.log('ERROR', f"[{target}] Wordlist file required for wordlist mode")
            return False
        
        logger.log('INFO', f"[{target}] Starting wordlist fuzzing for path: {dir_path}")
        output_file = ffuf_results_dir / f"ffuf_wordlist_{safe_path_name}.txt"
        logger.log('DEBUG', f"[{target}] Wordlist output file: {output_file}")
        
        success = run_ffuf_command(
            target, fuzz_url, args.fuzz_wordlist, output_file, 
            "wordlist", args, logger
        )
        
        if success:
            logger.log('SUCCESS', f"[{target}] Wordlist fuzzing completed for path: {dir_path}")
        else:
            logger.log('ERROR', f"[{target}] Wordlist fuzzing failed for path: {dir_path}")
    
    # Run permutation fuzzing
    if args.fuzz_mode in ["permutation", "both"] and permutation_wordlist:
        logger.log('INFO', f"[{target}] Starting permutation fuzzing for path: {dir_path}")
        output_file = ffuf_results_dir / f"ffuf_permutation_{safe_path_name}.txt"
        logger.log('DEBUG', f"[{target}] Permutation output file: {output_file}")
        logger.log('DEBUG', f"[{target}] Using permutation wordlist: {permutation_wordlist}")
        
        success = run_ffuf_command(
            target, fuzz_url, str(permutation_wordlist), output_file, 
            "permutation", args, logger
        )
        
        if success:
            logger.log('SUCCESS', f"[{target}] Permutation fuzzing completed for path: {dir_path}")
        else:
            logger.log('ERROR', f"[{target}] Permutation fuzzing failed for path: {dir_path}")
    
    logger.log('INFO', f"[{target}] Completed fuzzing for path: {dir_path}")

def run_ffuf_command(target, fuzz_url, wordlist, output_file, fuzz_type, args, logger):
    """Run ffuf command with enhanced configuration and progress tracking"""
    
    # Check if wordlist file exists
    if not os.path.exists(wordlist):
        logger.log('ERROR', f"[{target}] Wordlist file not found: {wordlist}")
        return False
    
    # Count wordlist size for progress estimation
    wordlist_size = count_wordlist_lines(wordlist)
    
    cmd = [
        "ffuf",
        "-u", fuzz_url,
        "-w", wordlist,
        "-mc", args.fuzz_status_codes,
        "-t", str(args.fuzz_threads),
        "-timeout", str(args.fuzz_timeout),
        "-of", "json",
        "-o", str(output_file),
        "-v"  # Verbose output for better debugging
    ]
    
    # Enhanced logging for ffuf execution
    logger.log('INFO', f"[{target}] Running ffuf {fuzz_type} on {fuzz_url}")
    logger.log('INFO', f"[{target}] Fuzzing configuration:")
    logger.log('INFO', f"[{target}]   - Wordlist: {wordlist}")
    logger.log('INFO', f"[{target}]   - Wordlist size: {wordlist_size:,} words")
    logger.log('INFO', f"[{target}]   - Status codes: {args.fuzz_status_codes}")
    logger.log('INFO', f"[{target}]   - Threads: {args.fuzz_threads}")
    logger.log('INFO', f"[{target}]   - Timeout per request: {args.fuzz_timeout}s")
    logger.log('INFO', f"[{target}]   - Output file: {output_file}")
    logger.log('DEBUG', f"[{target}] Full command: {' '.join(cmd)}")
    
    # Calculate timeout
    if args.fuzz_no_timeout:
        timeout = None
        logger.log('INFO', f"[{target}] Running ffuf without timeout")
    else:
        timeout = calculate_ffuf_timeout(wordlist_size, args.fuzz_threads, args.fuzz_timeout)
        logger.log('INFO', f"[{target}] Estimated total timeout: {timeout}s")
        logger.log('DEBUG', f"[{target}] Timeout calculation: ({wordlist_size} words / {args.fuzz_threads} threads) * {args.fuzz_timeout}s * 1.5 = {timeout}s")
    
    # Run ffuf with progress tracking
    logger.log('INFO', f"[{target}] Starting ffuf {fuzz_type} execution...")
    exit_code, stdout, stderr = run_command_with_progress(cmd, timeout, wordlist_size, target, fuzz_type, logger)
    
    # Process results with enhanced logging
    logger.log('INFO', f"[{target}] ffuf {fuzz_type} execution completed (exit code: {exit_code})")
    
    if exit_code == 0 and output_file.exists() and output_file.stat().st_size > 0:
        results_count = count_ffuf_results(output_file)
        file_size = output_file.stat().st_size
        logger.log('SUCCESS', f"[{target}] ffuf {fuzz_type} completed successfully:")
        logger.log('SUCCESS', f"[{target}]   - Results found: {results_count}")
        logger.log('SUCCESS', f"[{target}]   - Output file size: {file_size:,} bytes")
        logger.log('SUCCESS', f"[{target}]   - Output file: {output_file}")
        return True
    elif exit_code == 0 and output_file.exists():
        file_size = output_file.stat().st_size
        logger.log('WARN', f"[{target}] ffuf {fuzz_type} completed but no results found:")
        logger.log('WARN', f"[{target}]   - Output file size: {file_size:,} bytes")
        logger.log('WARN', f"[{target}]   - Output file: {output_file}")
        return True
    else:
        logger.log('ERROR', f"[{target}] ffuf {fuzz_type} failed:")
        logger.log('ERROR', f"[{target}]   - Exit code: {exit_code}")
        logger.log('ERROR', f"[{target}]   - Error output: {stderr}")
        if stdout:
            logger.log('DEBUG', f"[{target}]   - Standard output: {stdout}")
        return False

def count_wordlist_lines(wordlist_path):
    """Count lines in wordlist file"""
    try:
        with open(wordlist_path, 'r') as f:
            return sum(1 for line in f if line.strip())
    except:
        return 1000  # Default estimate

def calculate_ffuf_timeout(wordlist_size, threads, per_request_timeout):
    """Calculate timeout for ffuf"""
    base_timeout = (wordlist_size / threads) * per_request_timeout * 1.5
    return max(60, min(3600, int(base_timeout)))  # 1min to 1hour

def run_command_with_progress(cmd, timeout, wordlist_size, target, fuzz_type, logger):
    """Run ffuf command with progress tracking"""
    try:
        # Start ffuf process
        logger.log('DEBUG', f"[{target}] Starting ffuf process...")
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Monitor progress
        results_found = 0
        progress_updates = 0
        start_time = time.time()
        
        logger.log('DEBUG', f"[{target}] Monitoring ffuf {fuzz_type} progress...")
        
        try:
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    # Parse ffuf output for progress
                    if ':: Progress' in output:
                        progress_updates += 1
                        # Log progress every 10 updates to avoid spam
                        if progress_updates % 10 == 0:
                            logger.log('INFO', f"[{target}] {fuzz_type} progress: {output.strip()}")
                        else:
                            logger.log('DEBUG', f"[{target}] {fuzz_type}: {output.strip()}")
                    elif ':: Result' in output:
                        results_found += 1
                        logger.log('INFO', f"[{target}] {fuzz_type}: Found result #{results_found}")
                        logger.log('DEBUG', f"[{target}] {fuzz_type}: {output.strip()}")
                    elif ':: Error' in output:
                        logger.log('WARN', f"[{target}] {fuzz_type} error: {output.strip()}")
                    else:
                        logger.log('DEBUG', f"[{target}] {fuzz_type}: {output.strip()}")
            
            # Wait for process to complete
            stdout, stderr = process.communicate(timeout=timeout)
            execution_time = time.time() - start_time
            
            logger.log('INFO', f"[{target}] {fuzz_type} execution completed in {execution_time:.2f}s")
            logger.log('INFO', f"[{target}] {fuzz_type} found {results_found} results during execution")
            
            return process.returncode, stdout, stderr
            
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            execution_time = time.time() - start_time
            logger.log('ERROR', f"[{target}] {fuzz_type} timed out after {execution_time:.2f}s")
            return 1, stdout, f"Command timed out after {timeout} seconds"
            
    except Exception as e:
        logger.log('ERROR', f"[{target}] {fuzz_type} process error: {str(e)}")
        return 1, "", str(e)

def count_ffuf_results(output_file):
    """Count results in ffuf output file"""
    try:
        count = 0
        with open(output_file, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        data = json.loads(line)
                        if 'url' in data:
                            count += 1
                    except json.JSONDecodeError:
                        continue
        return count
    except:
        return 0

def save_fuzzing_results(target, target_dir, ffuf_results_dir, original_urls, logger):
    """Save and analyze fuzzing results for chain mode"""
    # Save original URL list for reference
    original_urls_file = target_dir / CONFIG['files']['original_urls']
    with open(original_urls_file, 'w') as f:
        f.write('\n'.join(original_urls))
    
    # Extract and save all found JS URLs
    all_ffuf_urls = extract_js_urls_from_ffuf_results(ffuf_results_dir)
    all_js_file = target_dir / CONFIG['files']['fuzzing_all']
    with open(all_js_file, 'w') as f:
        f.write('\n'.join(sorted(all_ffuf_urls)))
    
    # Count and report findings
    wordlist_count, permutation_count = count_fuzzing_findings(ffuf_results_dir)
    
    if wordlist_count > 0:
        logger.log('SUCCESS', f"[{target}] Wordlist fuzzing found {wordlist_count} JS files")
    if permutation_count > 0:
        logger.log('SUCCESS', f"[{target}] Permutation fuzzing found {permutation_count} JS files")
    
    logger.log('SUCCESS', f"[{target}] Total JS files found via fuzzing: {len(all_ffuf_urls)}")
    
    # Save new findings (not in original list)
    save_new_findings(target, target_dir, all_ffuf_urls, original_urls, logger)

def save_independent_fuzzing_results(input_file, output_dir, ffuf_results_dir, original_urls, logger):
    """Save fuzzing results for independent mode"""
    # Extract all found JS URLs
    all_ffuf_urls = extract_js_urls_from_ffuf_results(ffuf_results_dir)
    
    # Save all findings
    all_js_file = output_dir / "all_fuzzing_results.txt"
    with open(all_js_file, 'w') as f:
        f.write('\n'.join(sorted(all_ffuf_urls)))
    
    # Count findings by type
    wordlist_count, permutation_count = count_fuzzing_findings(ffuf_results_dir)
    
    # Save detailed results
    results_summary = {
        'input_file': str(input_file),
        'total_input_urls': len(original_urls),
        'total_found_urls': len(all_ffuf_urls),
        'wordlist_findings': wordlist_count,
        'permutation_findings': permutation_count,
        'new_findings': len(all_ffuf_urls - set(original_urls))
    }
    
    summary_file = output_dir / "fuzzing_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(results_summary, f, indent=2)
    
    # Log results
    logger.log('SUCCESS', f"Fuzzing complete!")
    logger.log('INFO', f"  - Input URLs: {len(original_urls)}")
    logger.log('INFO', f"  - Total found: {len(all_ffuf_urls)}")
    logger.log('INFO', f"  - Wordlist findings: {wordlist_count}")
    logger.log('INFO', f"  - Permutation findings: {permutation_count}")
    logger.log('INFO', f"  - New findings: {results_summary['new_findings']}")

def extract_js_urls_from_ffuf_results(ffuf_results_dir):
    """Extract JS URLs from ffuf result files"""
    js_urls = set()
    
    for result_file in ffuf_results_dir.glob("*.txt"):
        if result_file.name.endswith('.txt'):
            try:
                with open(result_file, 'r') as f:
                    content = f.read()
                    for line in content.splitlines():
                        if line.strip():
                            try:
                                data = json.loads(line)
                                if 'url' in data and data['url'].endswith('.js'):
                                    js_urls.add(data['url'])
                            except json.JSONDecodeError:
                                continue
            except Exception as e:
                continue
    
    return js_urls

def count_fuzzing_findings(ffuf_results_dir):
    """Count findings by fuzzing type"""
    wordlist_count = 0
    permutation_count = 0
    
    for result_file in ffuf_results_dir.glob("*.txt"):
        if result_file.name.startswith("ffuf_permutation_"):
            try:
                with open(result_file, 'r') as f:
                    content = f.read()
                    for line in content.splitlines():
                        if line.strip():
                            try:
                                data = json.loads(line)
                                if 'url' in data and data['url'].endswith('.js'):
                                    permutation_count += 1
                            except json.JSONDecodeError:
                                continue
            except:
                continue
        elif result_file.name.startswith("ffuf_wordlist_"):
            try:
                with open(result_file, 'r') as f:
                    content = f.read()
                    for line in content.splitlines():
                        if line.strip():
                            try:
                                data = json.loads(line)
                                if 'url' in data and data['url'].endswith('.js'):
                                    wordlist_count += 1
                            except json.JSONDecodeError:
                                continue
            except:
                continue
    
    return wordlist_count, permutation_count

def save_new_findings(target, target_dir, all_ffuf_urls, original_urls, logger):
    """Save new findings (not in original URL list)"""
    original_url_set = set(original_urls)
    new_urls = all_ffuf_urls - original_url_set
    
    new_js_file = target_dir / CONFIG['files']['fuzzing_new']
    with open(new_js_file, 'w') as f:
        f.write('\n'.join(sorted(new_urls)))
    
    if new_urls:
        logger.log('SUCCESS', f"[{target}] Found {len(new_urls)} new JS files via fuzzing")

def run_command(cmd, timeout=CONFIG['timeouts']['command']):
    """Run subprocess command with timeout"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        return 1, "", str(e)

def extract_urls_from_downloaded_js_files(js_files, logger):
    """Extract URLs from downloaded JS files using jsluice and regex fallback"""
    extracted_urls = set()
    
    logger.log('INFO', f"Extracting URLs from {len(js_files)} JS files...")
    
    with tqdm(total=len(js_files), desc="Extracting URLs", unit="file") as pbar:
        for js_file in js_files:
            file_urls_found = 0  # Count URLs found for this specific file
            
            try:
                # Use jsluice to extract URLs from JS file
                exit_code, stdout, stderr = run_command(["jsluice", "urls", str(js_file)])
                
                if exit_code == 0 and stdout.strip():
                    logger.log('DEBUG', f"jsluice output for {js_file.name}: {stdout[:200]}...")
                    try:
                        urls_data = [json.loads(line) for line in stdout.splitlines() if line.strip()]
                        logger.log('DEBUG', f"Parsed {len(urls_data)} URL entries from {js_file.name}")
                        
                        for url_data in urls_data:
                            if 'url' in url_data:
                                url = url_data['url']
                                # Accept more URL patterns, not just .js files
                                if (url.endswith('.js') or 
                                    '/js/' in url or 
                                    'javascript' in url.lower() or
                                    url.startswith(('http://', 'https://', '//')) or
                                    '.js?' in url or  # URLs with query parameters
                                    '.js#' in url or  # URLs with fragments
                                    '.js' in url):    # URLs containing .js anywhere
                                    # Log the extracted URL for debugging
                                    logger.log('DEBUG', f"Extracted URL from {js_file.name}: {url}")
                                    extracted_urls.add(url)
                                    file_urls_found += 1
                                else:
                                    logger.log('DEBUG', f"Skipped URL from {js_file.name}: {url} (doesn't match JS patterns)")
                    except json.JSONDecodeError as e:
                        logger.log('DEBUG', f"JSON decode error for {js_file.name}: {str(e)}")
                else:
                    logger.log('DEBUG', f"No jsluice output for {js_file.name} (exit code: {exit_code})")
                
                # Fallback: Use regex to extract URLs if jsluice didn't find URLs for this file
                if file_urls_found == 0:
                    try:
                        with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            # Extract URLs using regex patterns
                            url_patterns = [
                                r'["\']([^"\']*\.js[^"\']*)["\']',  # URLs in quotes
                                r'["\']([^"\']*\/js\/[^"\']*)["\']',  # URLs with /js/ path
                                r'["\']([^"\']*javascript[^"\']*)["\']',  # URLs with javascript
                                r'["\'](https?://[^"\']*)["\']',  # HTTP/HTTPS URLs
                                r'["\'](//[^"\']*)["\']',  # Protocol-relative URLs
                            ]
                            
                            for pattern in url_patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    if match and (match.endswith('.js') or '/js/' in match or 'javascript' in match.lower() or '.js' in match):
                                        logger.log('DEBUG', f"Regex extracted URL from {js_file.name}: {match}")
                                        extracted_urls.add(match)
                    except Exception as e:
                        logger.log('DEBUG', f"Error in regex fallback for {js_file.name}: {str(e)}")
                
            except Exception as e:
                logger.log('DEBUG', f"Error extracting URLs from {js_file.name}: {str(e)}")
                continue
            pbar.update(1)
    
    # Log all extracted URLs for debugging
    if extracted_urls:
        logger.log('DEBUG', f"All extracted URLs: {list(extracted_urls)}")
    
    logger.log('SUCCESS', f"Extracted {len(extracted_urls)} unique URLs from downloaded files")
    return list(extracted_urls)