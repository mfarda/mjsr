import concurrent.futures
import subprocess
import json
from pathlib import Path
from tqdm import tqdm
from .utils import CONFIG, ensure_dir

def run(args, config, logger):
    for target in args.targets:
        target_dir = Path(args.output) / target
        js_files_dir = target_dir / CONFIG['dirs']['js_files']
        js_files = list(js_files_dir.glob("*.js"))
        if not js_files:
            logger.log('ERROR', f"[{target}] No JS files found for analysis.")
            continue
        max_workers = CONFIG['analysis_threads']
        results_dir = target_dir / CONFIG['dirs']['results']
        for subdir in CONFIG['results_dirs']:
            ensure_dir(results_dir / subdir)
        with tqdm(total=len(js_files), desc=f"[{target}] Analyzing JS", unit="file") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(analyze_js_file, target, target_dir, js_file, logger) for js_file in js_files]
                for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                    try:
                        future.result()
                        pbar.update(1)
                        logger.log('INFO', f"[{target}] [{i}/{len(js_files)}] Processed")
                    except Exception as e:
                        logger.log('ERROR', f"[{target}] Error processing file: {str(e)}")

def analyze_js_file(target, target_dir, js_file, logger):
    results_dir = target_dir / CONFIG['dirs']['results']
    # jsluice analysis
    jsluice_dir = results_dir / CONFIG['dirs']['jsluice']
    ensure_dir(jsluice_dir)
    # URLs
    exit_code, stdout, stderr = _run_command(["jsluice", "urls", str(js_file)], CONFIG['timeouts']['analysis'])
    if exit_code == 0 and stdout.strip():
        try:
            urls_data = [json.loads(line) for line in stdout.splitlines() if line.strip()]
            with open(jsluice_dir / f"urls_{js_file.name}.json", 'w') as f:
                json.dump(urls_data, f, indent=2)
        except json.JSONDecodeError:
            pass
    # Secrets
    exit_code, stdout, stderr = _run_command(["jsluice", "secrets", str(js_file)], CONFIG['timeouts']['analysis'])
    if exit_code == 0 and stdout.strip():
        try:
            secrets_data = json.loads(stdout)
            with open(jsluice_dir / f"secrets_{js_file.name}.json", 'w') as f:
                json.dump(secrets_data, f, indent=2)
        except json.JSONDecodeError:
            pass
    # SecretFinder
    secretfinder_dir = results_dir / CONFIG['dirs']['secretfinder']
    ensure_dir(secretfinder_dir)
    exit_code, stdout, stderr = _run_command([
        "python3", CONFIG['tools']['python_tools']['secretfinder'], "-i", str(js_file), "-o", "cli"
    ], CONFIG['timeouts']['analysis'])
    if exit_code == 0:
        with open(secretfinder_dir / f"secrets_{js_file.name}.txt", 'w') as f:
            f.write(stdout)
    # LinkFinder
    linkfinder_dir = results_dir / CONFIG['dirs']['linkfinder']
    ensure_dir(linkfinder_dir)
    exit_code, stdout, stderr = _run_command([
        "python3", CONFIG['tools']['python_tools']['linkfinder'], "-i", str(js_file), "-o", "cli"
    ], CONFIG['timeouts']['analysis'])
    if exit_code == 0:
        with open(linkfinder_dir / f"endpoints_{js_file.name}.txt", 'w') as f:
            f.write(stdout)
    # trufflehog
    trufflehog_dir = results_dir / CONFIG['dirs']['trufflehog']
    ensure_dir(trufflehog_dir)
    exit_code, stdout, stderr = _run_command([
        "trufflehog", "filesystem", str(js_file), "--json"
    ], CONFIG['timeouts']['analysis'])
    if exit_code == 0:
        with open(trufflehog_dir / f"secrets_{js_file.name}.json", 'w') as f:
            f.write(stdout)

def _run_command(cmd, timeout=CONFIG['timeouts']['command']):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        return 1, "", str(e)