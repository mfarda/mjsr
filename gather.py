import subprocess
from pathlib import Path
from .utils import CONFIG, ensure_dir

def run(args, config, logger):
    for target in args.targets:
        target_dir = Path(args.output) / target
        ensure_dir(target_dir)
        logger.log('INFO', f"[{target}] Gathering JavaScript files...")
        all_js_urls = set()
        # waybackurls
        logger.log('INFO', f"[{target}] Running waybackurls...")
        exit_code, stdout, stderr = _run_command(["waybackurls", target])
        if exit_code == 0:
            wayback_file = target_dir / CONFIG['files']['wayback_raw']
            wayback_urls = _process_tool_output(target, "waybackurls", stdout, wayback_file, logger)
            all_js_urls.update(wayback_urls)
        # gau
        logger.log('INFO', f"[{target}] Running gau...")
        exit_code, stdout, stderr = _run_command(["gau", "--subs", target])
        if exit_code == 0:
            gau_file = target_dir / CONFIG['files']['gau_raw']
            gau_urls = _process_tool_output(target, "gau", stdout, gau_file, logger)
            all_js_urls.update(gau_urls)
        # katana
        logger.log('INFO', f"[{target}] Running katana...")
        katana_file = target_dir / CONFIG['files']['katana_raw']
        exit_code, stdout, stderr = _run_command([
            "katana", "-u", f"{CONFIG['default_url_scheme']}{target}", "-jc", "-d", str(args.depth), "-o", str(katana_file)
        ])
        if exit_code == 0 and katana_file.exists() and katana_file.stat().st_size > 0:
            with open(katana_file, 'r') as f:
                content = f.read()
            katana_urls = _process_tool_output(target, "katana", content, katana_file, logger)
            all_js_urls.update(katana_urls)
        # Save all unique URLs
        all_js_file = target_dir / CONFIG['files']['all_js']
        with open(all_js_file, 'w') as f:
            f.write('\n'.join(sorted(all_js_urls)))
        logger.log('INFO', f"[{target}] Total unique JS URLs: {len(all_js_urls)}")

def _run_command(cmd, timeout=CONFIG['timeouts']['command']):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        return 1, "", str(e)

def _extract_js_urls(content):
    import re
    from urllib.parse import urlparse
    js_urls = re.findall(r'https?://[^\s<>"\'()]+\.js(?:\?[^\s<>"\'()]*)?(?:#[^\s<>"\'()]*)?', content, re.IGNORECASE)
    valid_urls = set()
    for url in js_urls:
        try:
            parsed = urlparse(url)
            if parsed.netloc and parsed.scheme in ['http', 'https']:
                if not any(ext in url.lower() for ext in CONFIG['excluded_extensions']):
                    valid_urls.add(url)
        except:
            continue
    return valid_urls

def _process_tool_output(target, tool_name, stdout, output_file, logger):
    if not stdout.strip():
        logger.log('WARN', f"[{target}] {tool_name} produced no output.")
        return set()
    with open(output_file, 'w') as f:
        f.write(stdout)
    js_urls = _extract_js_urls(stdout)
    filtered_file = output_file.parent / f"{output_file.stem}{CONFIG['ffuf']['filtered_suffix']}"
    with open(filtered_file, 'w') as f:
        f.write('\n'.join(sorted(js_urls)))
    logger.log('SUCCESS', f"[{target}] Found {len(js_urls)} JS URLs from {tool_name}")
    return js_urls