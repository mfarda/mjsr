import subprocess
from pathlib import Path
from .utils import CONFIG, ensure_dir

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
        cmd = ["httpx", "-l", str(all_js_file), "-sc", "-cl", "-mc", "200", "-fl", "0", "-silent", "-o", str(live_js_file)]
        exit_code, stdout, stderr = _run_command(cmd)
        if live_js_file.exists():
            with open(live_js_file, 'r') as f:
                live_count = sum(1 for _ in f)
            logger.log('SUCCESS', f"[{target}] Found {live_count} live JS URLs")
        else:
            logger.log('ERROR', f"[{target}] Failed to verify live JS files")

def _run_command(cmd, timeout=CONFIG['timeouts']['command']):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        return 1, "", str(e)