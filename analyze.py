import concurrent.futures
import subprocess
import json
from pathlib import Path
from tqdm import tqdm
from .utils import CONFIG, ensure_dir

def run(args, config, logger):
    # Handle independent mode
    if args.independent:
        return run_independent(args, config, logger)
    
    # Normal mode - process all targets
    for target in args.targets:
        target_dir = Path(args.output) / target
        js_files_dir = target_dir / CONFIG['dirs']['js_files']
        js_files = list(js_files_dir.glob("*.js"))
        if not js_files:
            logger.log('ERROR', f"[{target}] No JS files found for analysis.")
            continue
        
        logger.log('INFO', f"[{target}] Found {len(js_files)} JS files to analyze")
        
        max_workers = CONFIG['analysis_threads']
        results_dir = target_dir / CONFIG['dirs']['results']
        for subdir in CONFIG['results_dirs']:
            ensure_dir(results_dir / subdir)
        
        processed_count = 0
        failed_count = 0
        
        def analyze_file(js_file, pbar):
            nonlocal processed_count, failed_count
            try:
                analyze_js_file_optimized(target, target_dir, js_file, logger)
                processed_count += 1
                pbar.set_postfix({
                    'Processed': processed_count,
                    'Failed': failed_count
                })
                return True
            except Exception as e:
                failed_count += 1
                pbar.set_postfix({
                    'Processed': processed_count,
                    'Failed': failed_count
                })
                return False
        
        with tqdm(total=len(js_files), desc=f"[{target}] Analyzing JS files", unit="file") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(analyze_file, js_file, pbar) for js_file in js_files]
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
        
        logger.log('SUCCESS', f"[{target}] Analysis complete: {processed_count} processed, {failed_count} failed")

def run_independent(args, config, logger):
    """Run analyze module independently with custom input directory"""
    # Determine input directory
    if args.input:
        input_dir = Path(args.input)
    else:
        logger.log('ERROR', "Input directory is required for independent analysis")
        return False
    
    if not input_dir.exists():
        logger.log('ERROR', f"Input directory not found: {input_dir}")
        return False
    
    # Find JS files in input directory
    js_files = list(input_dir.glob("*.js"))
    if not js_files:
        logger.log('ERROR', f"No JS files found in: {input_dir}")
        return False
    
    # Determine output directory
    if args.output:
        output_dir = Path(args.output)
        ensure_dir(output_dir)
    else:
        # Use same directory as input
        output_dir = input_dir.parent / "analysis_results"
        ensure_dir(output_dir)
    
    logger.log('INFO', f"Analyzing JS files from: {input_dir}")
    logger.log('INFO', f"Results will be saved to: {output_dir}")
    logger.log('INFO', f"Found {len(js_files)} JS files to analyze")
    
    # Create results subdirectories
    for subdir in CONFIG['results_dirs']:
        ensure_dir(output_dir / subdir)
    
    max_workers = CONFIG['analysis_threads']
    processed_count = 0
    failed_count = 0
    
    def analyze_file(js_file, pbar):
        nonlocal processed_count, failed_count
        try:
            analyze_js_file_independent_optimized(input_dir, output_dir, js_file, logger)
            processed_count += 1
            pbar.set_postfix({
                'Processed': processed_count,
                'Failed': failed_count
            })
            return True
        except Exception as e:
            failed_count += 1
            pbar.set_postfix({
                'Processed': processed_count,
                'Failed': failed_count
            })
            return False
    
    with tqdm(total=len(js_files), desc="Analyzing JS files", unit="file") as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(analyze_file, js_file, pbar) for js_file in js_files]
            for future in concurrent.futures.as_completed(futures):
                future.result()
                pbar.update(1)
    
    logger.log('SUCCESS', f"Analysis complete: {processed_count} processed, {failed_count} failed")
    logger.log('INFO', f"Results saved to: {output_dir}")
    return True

def analyze_js_file_optimized(target, target_dir, js_file, logger):
    """Optimized analysis with parallel tool execution"""
    results_dir = target_dir / CONFIG['dirs']['results']
    
    # Create directories
    jsluice_dir = results_dir / CONFIG['dirs']['jsluice']
    secretfinder_dir = results_dir / CONFIG['dirs']['secretfinder']
    linkfinder_dir = results_dir / CONFIG['dirs']['linkfinder']
    trufflehog_dir = results_dir / CONFIG['dirs']['trufflehog']
    
    ensure_dir(jsluice_dir)
    ensure_dir(secretfinder_dir)
    ensure_dir(linkfinder_dir)
    ensure_dir(trufflehog_dir)
    
    # Define analysis tasks
    def run_jsluice_urls():
        exit_code, stdout, stderr = _run_command(["jsluice", "urls", str(js_file)], CONFIG['timeouts']['analysis'])
        if exit_code == 0 and stdout.strip():
            try:
                urls_data = [json.loads(line) for line in stdout.splitlines() if line.strip()]
                with open(jsluice_dir / f"urls_{js_file.name}.json", 'w') as f:
                    json.dump(urls_data, f, indent=2)
            except json.JSONDecodeError:
                pass
    
    def run_jsluice_secrets():
        exit_code, stdout, stderr = _run_command(["jsluice", "secrets", str(js_file)], CONFIG['timeouts']['analysis'])
        if exit_code == 0 and stdout.strip():
            try:
                secrets_data = json.loads(stdout)
                with open(jsluice_dir / f"secrets_{js_file.name}.json", 'w') as f:
                    json.dump(secrets_data, f, indent=2)
            except json.JSONDecodeError:
                pass
    
    def run_secretfinder():
        exit_code, stdout, stderr = _run_command([
            "python3", CONFIG['tools']['python_tools']['secretfinder'], "-i", str(js_file), "-o", "cli"
        ], CONFIG['timeouts']['analysis'])
        if exit_code == 0:
            with open(secretfinder_dir / f"secrets_{js_file.name}.txt", 'w') as f:
                f.write(stdout)
    
    def run_linkfinder():
        exit_code, stdout, stderr = _run_command([
            "python3", CONFIG['tools']['python_tools']['linkfinder'], "-i", str(js_file), "-o", "cli"
        ], CONFIG['timeouts']['analysis'])
        if exit_code == 0:
            with open(linkfinder_dir / f"endpoints_{js_file.name}.txt", 'w') as f:
                f.write(stdout)
    
    def run_trufflehog():
        exit_code, stdout, stderr = _run_command([
            "trufflehog", "filesystem", str(js_file), "--json"
        ], CONFIG['timeouts']['analysis'])
        if exit_code == 0:
            with open(trufflehog_dir / f"secrets_{js_file.name}.json", 'w') as f:
                f.write(stdout)
    
    # Run all tools in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [
            executor.submit(run_jsluice_urls),
            executor.submit(run_jsluice_secrets),
            executor.submit(run_secretfinder),
            executor.submit(run_linkfinder),
            executor.submit(run_trufflehog)
        ]
        concurrent.futures.wait(futures)

def analyze_js_file_independent_optimized(input_dir, output_dir, js_file, logger):
    """Optimized analysis for independent mode with parallel tool execution"""
    # Create directories
    jsluice_dir = output_dir / CONFIG['dirs']['jsluice']
    secretfinder_dir = output_dir / CONFIG['dirs']['secretfinder']
    linkfinder_dir = output_dir / CONFIG['dirs']['linkfinder']
    trufflehog_dir = output_dir / CONFIG['dirs']['trufflehog']
    
    ensure_dir(jsluice_dir)
    ensure_dir(secretfinder_dir)
    ensure_dir(linkfinder_dir)
    ensure_dir(trufflehog_dir)
    
    # Define analysis tasks
    def run_jsluice_urls():
        exit_code, stdout, stderr = _run_command(["jsluice", "urls", str(js_file)], CONFIG['timeouts']['analysis'])
        if exit_code == 0 and stdout.strip():
            try:
                urls_data = [json.loads(line) for line in stdout.splitlines() if line.strip()]
                with open(jsluice_dir / f"urls_{js_file.name}.json", 'w') as f:
                    json.dump(urls_data, f, indent=2)
            except json.JSONDecodeError:
                pass
    
    def run_jsluice_secrets():
        exit_code, stdout, stderr = _run_command(["jsluice", "secrets", str(js_file)], CONFIG['timeouts']['analysis'])
        if exit_code == 0 and stdout.strip():
            try:
                secrets_data = json.loads(stdout)
                with open(jsluice_dir / f"secrets_{js_file.name}.json", 'w') as f:
                    json.dump(secrets_data, f, indent=2)
            except json.JSONDecodeError:
                pass
    
    def run_secretfinder():
        exit_code, stdout, stderr = _run_command([
            "python3", CONFIG['tools']['python_tools']['secretfinder'], "-i", str(js_file), "-o", "cli"
        ], CONFIG['timeouts']['analysis'])
        if exit_code == 0:
            with open(secretfinder_dir / f"secrets_{js_file.name}.txt", 'w') as f:
                f.write(stdout)
    
    def run_linkfinder():
        exit_code, stdout, stderr = _run_command([
            "python3", CONFIG['tools']['python_tools']['linkfinder'], "-i", str(js_file), "-o", "cli"
        ], CONFIG['timeouts']['analysis'])
        if exit_code == 0:
            with open(linkfinder_dir / f"endpoints_{js_file.name}.txt", 'w') as f:
                f.write(stdout)
    
    def run_trufflehog():
        exit_code, stdout, stderr = _run_command([
            "trufflehog", "filesystem", str(js_file), "--json"
        ], CONFIG['timeouts']['analysis'])
        if exit_code == 0:
            with open(trufflehog_dir / f"secrets_{js_file.name}.json", 'w') as f:
                f.write(stdout)
    
    # Run all tools in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [
            executor.submit(run_jsluice_urls),
            executor.submit(run_jsluice_secrets),
            executor.submit(run_secretfinder),
            executor.submit(run_linkfinder),
            executor.submit(run_trufflehog)
        ]
        concurrent.futures.wait(futures)

def _run_command(cmd, timeout=CONFIG['timeouts']['command']):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        return 1, "", str(e)