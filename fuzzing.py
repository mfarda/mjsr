import subprocess
import json
from pathlib import Path
from tqdm import tqdm
from .utils import CONFIG, ensure_dir, extract_js_filenames_from_urls, group_urls_by_directory, generate_js_permutations

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
    
    # Read URLs from input file
    with open(url_list_file, 'r') as f:
        url_list = [line.strip().split()[0] for line in f if line.strip()]
    
    if not url_list:
        logger.log('ERROR', f"[{target}] No URLs found in {url_list_file}")
        return False
    
    logger.log('INFO', f"[{target}] Found {len(url_list)} URLs to fuzz")
    
    # Create ffuf results directory
    ffuf_results_dir = target_dir / CONFIG['dirs']['ffuf_results']
    ensure_dir(ffuf_results_dir)
    
    # Run fuzzing
    success = execute_fuzzing_workflow(target, url_list, ffuf_results_dir, args, config, logger)
    
    if success:
        # Save and analyze results
        save_fuzzing_results(target, target_dir, ffuf_results_dir, url_list, logger)
    
    return success

def run_fuzzing_independent(input_file, output_dir, args, config, logger):
    """Run fuzzing independently with custom input file"""
    # Read URLs from input file
    with open(input_file, 'r') as f:
        url_list = [line.strip().split()[0] for line in f if line.strip()]
    
    if not url_list:
        logger.log('ERROR', f"No URLs found in {input_file}")
        return False
    
    logger.log('INFO', f"Found {len(url_list)} URLs to fuzz")
    
    # Create ffuf results directory
    ffuf_results_dir = output_dir / "ffuf_results"
    ensure_dir(ffuf_results_dir)
    
    # Run fuzzing
    success = execute_fuzzing_workflow("independent", url_list, ffuf_results_dir, args, config, logger)
    
    if success:
        # Save results for independent mode
        save_independent_fuzzing_results(input_file, output_dir, ffuf_results_dir, url_list, logger)
    
    return success

def execute_fuzzing_workflow(target, url_list, ffuf_results_dir, args, config, logger):
    """Execute the main fuzzing workflow"""
    # Extract filenames for permutation generation
    js_filenames = extract_js_filenames_from_urls(url_list)
    
    # Generate permutation wordlist if needed
    permutation_wordlist = None
    if args.fuzz_mode in ["permutation", "both"]:
        permutation_wordlist = generate_permutation_wordlist(target, js_filenames, ffuf_results_dir, logger)
    
    # Group URLs by directory for efficient fuzzing
    url_groups = group_urls_by_directory(url_list)
    
    logger.log('INFO', f"[{target}] Fuzzing {len(url_groups)} unique directories")
    
    # Execute fuzzing for each directory
    with tqdm(total=len(url_groups), desc=f"[{target}] Fuzzing directories", unit="dir") as pbar:
        for dir_path, base_url in url_groups.items():
            execute_fuzzing_for_directory(
                target, base_url, dir_path, ffuf_results_dir,
                args, permutation_wordlist, logger
            )
            pbar.update(1)
    
    return True

def execute_fuzzing_for_directory(target, base_url, dir_path, ffuf_results_dir, args, permutation_wordlist, logger):
    """Execute fuzzing for a specific directory"""
    # Build fuzz URL
    fuzz_url = f"{base_url}{dir_path}/FUZZ.{args.fuzz_extensions}"
    safe_dir_name = dir_path.strip('/').replace('/', '_') or 'root'
    
    # Skip if fuzzing is disabled
    if args.fuzz_mode == "off":
        return
    
    # Run wordlist fuzzing
    if args.fuzz_mode in ["wordlist", "both"]:
        output_file = ffuf_results_dir / f"ffuf_wordlist_{safe_dir_name}.txt"
        run_ffuf_command(
            target, fuzz_url, args.fuzz_wordlist, output_file, 
            "wordlist", args, logger
        )
    
    # Run permutation fuzzing
    if args.fuzz_mode in ["permutation", "both"] and permutation_wordlist:
        output_file = ffuf_results_dir / f"ffuf_permutation_{safe_dir_name}.txt"
        run_ffuf_command(
            target, fuzz_url, str(permutation_wordlist), output_file, 
            "permutation", args, logger
        )

def run_ffuf_command(target, fuzz_url, wordlist, output_file, fuzz_type, args, logger):
    """Run ffuf command with enhanced configuration"""
    cmd = [
        "ffuf",
        "-u", fuzz_url,
        "-w", wordlist,
        "-mc", args.fuzz_status_codes,
        "-t", str(args.fuzz_threads),
        "-timeout", str(args.fuzz_timeout),
        "-of", "json",
        "-o", str(output_file)
    ]
    
    logger.log('INFO', f"[{target}] Running ffuf {fuzz_type} on {fuzz_url}")
    logger.log('DEBUG', f"[{target}] Command: {' '.join(cmd)}")
    
    exit_code, stdout, stderr = run_command(cmd, timeout=args.fuzz_timeout * 2)
    
    if exit_code == 0 and output_file.exists() and output_file.stat().st_size > 0:
        logger.log('SUCCESS', f"[{target}] ffuf {fuzz_type} completed successfully")
        return True
    else:
        logger.log('ERROR', f"[{target}] ffuf {fuzz_type} failed: {stderr}")
        return False

def generate_permutation_wordlist(target, js_filenames, ffuf_results_dir, logger):
    """Generate permutation wordlist from JS filenames"""
    if not js_filenames:
        logger.log('WARN', f"[{target}] No JS filenames found for permutation generation")
        return None
    
    logger.log('INFO', f"[{target}] Generating permutation wordlist from {len(js_filenames)} JS files...")
    
    # Generate permutations
    permutations = generate_js_permutations(js_filenames)
    
    # Save permutation wordlist
    permutation_wordlist = ffuf_results_dir / "permutation_wordlist.txt"
    with open(permutation_wordlist, 'w') as f:
        f.write('\n'.join(sorted(permutations)))
    
    logger.log('SUCCESS', f"[{target}] Generated {len(permutations)} permutation words")
    return permutation_wordlist

def save_fuzzing_results(target, target_dir, ffuf_results_dir, url_list, logger):
    """Save and analyze fuzzing results for chain mode"""
    # Save original URL list for reference
    original_urls_file = target_dir / CONFIG['files']['original_urls']
    with open(original_urls_file, 'w') as f:
        f.write('\n'.join(url_list))
    
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
    save_new_findings(target, target_dir, all_ffuf_urls, url_list, logger)

def save_independent_fuzzing_results(input_file, output_dir, ffuf_results_dir, url_list, logger):
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
        'total_input_urls': len(url_list),
        'total_found_urls': len(all_ffuf_urls),
        'wordlist_findings': wordlist_count,
        'permutation_findings': permutation_count,
        'new_findings': len(all_ffuf_urls - set(url_list))
    }
    
    summary_file = output_dir / "fuzzing_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(results_summary, f, indent=2)
    
    # Log results
    logger.log('SUCCESS', f"Fuzzing complete!")
    logger.log('INFO', f"  - Input URLs: {len(url_list)}")
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