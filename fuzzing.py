import subprocess
import json
from pathlib import Path
from .utils import CONFIG, ensure_dir, extract_js_filenames_from_urls, group_urls_by_directory, generate_js_permutations

def run(args, config, logger):
    for target in args.targets:
        target_dir = Path(args.output) / target
        ensure_dir(target_dir)
        # Determine input file
        url_list_file = args.input if args.input else (target_dir / CONFIG['files']['live_js'])
        if not Path(url_list_file).exists():
            logger.log('ERROR', f"[{target}] No input URL list file found: {url_list_file}")
            continue
        with open(url_list_file, 'r') as f:
            url_list = [line.strip().split()[0] for line in f if line.strip()]
        if not url_list:
            logger.log('ERROR', f"[{target}] No URLs found in {url_list_file}")
            continue
        ffuf_results_dir = target_dir / CONFIG['dirs']['ffuf_results']
        ensure_dir(ffuf_results_dir)
        # Extract filenames and generate permutation wordlist
        js_filenames = extract_js_filenames_from_urls(url_list)
        permutation_wordlist = None
        if args.ffuf_mode in ["permutation", "both"]:
            permutation_wordlist = generate_permutation_wordlist(target, js_filenames, ffuf_results_dir, logger)
        # Group URLs by directory and fuzz each unique directory
        url_groups = group_urls_by_directory(url_list)
        from tqdm import tqdm
        with tqdm(total=len(url_groups), desc=f"[{target}] Fuzzing dirs", unit="dir") as pbar:
            for dir_path, base_url in url_groups.items():
                execute_fuzzing_for_directory(
                    target, base_url, dir_path, ffuf_results_dir,
                    args.ffuf_wordlist, permutation_wordlist, args.ffuf_mode, args.ext if hasattr(args, 'ext') else "js", logger
                )
                pbar.update(1)
        # Save and analyze results
        save_fuzzing_results(target, target_dir, ffuf_results_dir, url_list, logger)

def run_ffuf_command(target, fuzz_url, wordlist, output_file, fuzz_type, logger):
    cmd = [
        "ffuf", "-u", fuzz_url, "-w", wordlist, "-mc", CONFIG['ffuf']['http_status_codes'],
        "-of", CONFIG['ffuf']['output_format'], "-o", str(output_file)
    ]
    fuzz_type_str = "permutation" if "perm" in str(output_file) else "wordlist"
    logger.log('INFO', f"[{target}] Running ffuf {fuzz_type_str} on {fuzz_url}")
    exit_code, stdout, stderr = run_command(cmd)
    if exit_code == 0 and output_file.exists():
        logger.log('SUCCESS', f"[{target}] ffuf {fuzz_type_str} results saved to {output_file}")
        return True
    else:
        logger.log('ERROR', f"[{target}] ffuf {fuzz_type_str} failed for {fuzz_url}: {stderr}")
        return False

def execute_fuzzing_for_directory(target, base_url, dir_path, ffuf_results_dir, wordlist, permutation_wordlist, fuzz_mode, extensions, logger):
    fuzz_url = f"{base_url}{dir_path}/{CONFIG['ffuf']['fuzz_word']}.{extensions}"
    safe_dir_name = dir_path.strip('/').replace('/', '_') or 'root'
    if fuzz_mode == "off":
        return
    # Run wordlist fuzzing
    if fuzz_mode in ["fuzz", "both"]:
        output_file = ffuf_results_dir / f"ffuf_{safe_dir_name}.txt"
        run_ffuf_command(target, fuzz_url, wordlist, output_file, "wordlist", logger)
    # Run permutation fuzzing
    if fuzz_mode in ["permutation", "both"] and permutation_wordlist:
        output_file = ffuf_results_dir / f"ffuf_perm_{safe_dir_name}.txt"
        run_ffuf_command(target, fuzz_url, str(permutation_wordlist), output_file, "permutation", logger)

def generate_permutation_wordlist(target, js_filenames, ffuf_results_dir, logger):
    if not js_filenames:
        return None
    logger.log('INFO', f"[{target}] Generating permutation wordlist from {len(js_filenames)} JS files...")
    permutations = generate_js_permutations(js_filenames)
    permutation_wordlist = ffuf_results_dir / CONFIG['files']['permutation_wordlist']
    with open(permutation_wordlist, 'w') as f:
        f.write('\n'.join(sorted(permutations)))
    logger.log('SUCCESS', f"[{target}] Generated {len(permutations)} permutation words")
    return permutation_wordlist

def save_fuzzing_results(target, target_dir, ffuf_results_dir, url_list, logger):
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
    fuzz_count, perm_count = compare_and_save_new_js_files(target, target_dir, ffuf_results_dir, logger)
    if fuzz_count > 0:
        logger.log('SUCCESS', f"[{target}] Wordlist fuzzing found {fuzz_count} JS files")
    if perm_count > 0:
        logger.log('SUCCESS', f"[{target}] Permutation fuzzing found {perm_count} JS files")
    logger.log('SUCCESS', f"[{target}] Total JS files found via fuzzing: {len(all_ffuf_urls)}")

def extract_js_urls_from_ffuf_results(ffuf_results_dir):
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
            except Exception:
                continue
    return js_urls

def compare_and_save_new_js_files(target, target_dir, ffuf_results_dir, logger):
    static_js_urls = set()
    live_js_file = target_dir / CONFIG['files']['live_js']
    if live_js_file.exists():
        with open(live_js_file, 'r') as f:
            static_js_urls = {line.split()[0] for line in f if line.strip()}
    ffuf_js_urls = extract_js_urls_from_ffuf_results(ffuf_results_dir)
    new_js_urls = ffuf_js_urls - static_js_urls
    new_js_file = target_dir / CONFIG['files']['fuzzing_new']
    with open(new_js_file, 'w') as f:
        f.write('\n'.join(sorted(new_js_urls)))
    fuzz_count = 0
    perm_count = 0
    for result_file in ffuf_results_dir.glob("*.txt"):
        if result_file.name.startswith("ffuf_perm_"):
            try:
                with open(result_file, 'r') as f:
                    content = f.read()
                    for line in content.splitlines():
                        if line.strip():
                            try:
                                data = json.loads(line)
                                if 'url' in data and data['url'].endswith('.js'):
                                    perm_count += 1
                            except json.JSONDecodeError:
                                continue
            except:
                continue
        elif result_file.name.startswith("ffuf_") and not result_file.name.startswith("ffuf_perm_"):
            try:
                with open(result_file, 'r') as f:
                    content = f.read()
                    for line in content.splitlines():
                        if line.strip():
                            try:
                                data = json.loads(line)
                                if 'url' in data and data['url'].endswith('.js'):
                                    fuzz_count += 1
                            except json.JSONDecodeError:
                                continue
            except:
                continue
    return fuzz_count, perm_count

def run_command(cmd, timeout=CONFIG['timeouts']['command']):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        return 1, "", str(e)