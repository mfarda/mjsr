import subprocess
from pathlib import Path
from .utils import CONFIG, ensure_dir

def run(args, config, logger):
    # Handle independent mode
    if args.independent:
        return run_independent(args, config, logger)
    
    # Normal mode - process all targets
    for target in args.targets:
        target_dir = Path(args.output) / target
        ensure_dir(target_dir)
        logger.log('INFO', f"[{target}] Gathering JavaScript files...")
        logger.log('INFO', f"[{target}] Gather mode: {args.gather_mode}")
        
        all_js_urls = set()
        
        # waybackurls
        if 'w' in args.gather_mode:
            logger.log('INFO', f"[{target}] Running waybackurls...")
            exit_code, stdout, stderr = _run_command(["waybackurls", target])
            if exit_code == 0:
                wayback_file = target_dir / CONFIG['files']['wayback_raw']
                wayback_urls = _process_tool_output(target, "waybackurls", stdout, wayback_file, logger)
                all_js_urls.update(wayback_urls)
                logger.log('SUCCESS', f"[{target}] waybackurls found {len(wayback_urls)} JS URLs")
            else:
                logger.log('ERROR', f"[{target}] waybackurls failed: {stderr}")
        else:
            logger.log('INFO', f"[{target}] Skipping waybackurls (not in gather mode)")
        
        # gau
        if 'g' in args.gather_mode:
            logger.log('INFO', f"[{target}] Running gau...")
            exit_code, stdout, stderr = _run_command(["gau", "--subs", target])
            if exit_code == 0:
                gau_file = target_dir / CONFIG['files']['gau_raw']
                gau_urls = _process_tool_output(target, "gau", stdout, gau_file, logger)
                all_js_urls.update(gau_urls)
                logger.log('SUCCESS', f"[{target}] gau found {len(gau_urls)} JS URLs")
            else:
                logger.log('ERROR', f"[{target}] gau failed: {stderr}")
        else:
            logger.log('INFO', f"[{target}] Skipping gau (not in gather mode)")
        
        # katana
        if 'k' in args.gather_mode:
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
                logger.log('SUCCESS', f"[{target}] katana found {len(katana_urls)} JS URLs")
            else:
                logger.log('ERROR', f"[{target}] katana failed: {stderr}")
        else:
            logger.log('INFO', f"[{target}] Skipping katana (not in gather mode)")
        
        # Save all unique URLs
        all_js_file = target_dir / CONFIG['files']['all_js']
        with open(all_js_file, 'w') as f:
            f.write('\n'.join(sorted(all_js_urls)))
        logger.log('SUCCESS', f"[{target}] Total unique JS URLs: {len(all_js_urls)}")

def run_independent(args, config, logger):
    """Run gather module independently with custom input target or target file"""
    # Determine targets
    targets = []
    
    if args.input:
        input_path = Path(args.input)
        if input_path.exists():
            if input_path.is_file():
                # Read targets from file
                with open(input_path, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
                logger.log('INFO', f"Reading targets from file: {input_path}")
            else:
                # Single target as string
                targets = [input_path.name]
                logger.log('INFO', f"Using single target: {input_path.name}")
        else:
            # Treat as single target string
            targets = [str(input_path)]
            logger.log('INFO', f"Using single target: {input_path}")
    else:
        logger.log('ERROR', "Input target or target file is required for independent gathering")
        return False
    
    if not targets:
        logger.log('ERROR', "No valid targets found")
        return False
    
    logger.log('INFO', f"Gathering JS URLs for {len(targets)} target(s)")
    logger.log('INFO', f"Gather mode: {args.gather_mode}")
    
    # Determine output directory
    if args.output:
        output_dir = Path(args.output)
        ensure_dir(output_dir)
    else:
        # Use current directory
        output_dir = Path.cwd() / "gathered_js"
        ensure_dir(output_dir)
    
    all_target_urls = {}
    
    # Process each target
    for target in targets:
        logger.log('INFO', f"Gathering JavaScript files for: {target}")
        target_urls = set()
        
        # waybackurls
        if 'w' in args.gather_mode:
            logger.log('INFO', f"Running waybackurls for {target}...")
            exit_code, stdout, stderr = _run_command(["waybackurls", target])
            if exit_code == 0:
                wayback_urls = _extract_js_urls(stdout)
                target_urls.update(wayback_urls)
                logger.log('SUCCESS', f"Found {len(wayback_urls)} JS URLs from waybackurls for {target}")
            else:
                logger.log('ERROR', f"waybackurls failed for {target}: {stderr}")
        else:
            logger.log('INFO', f"Skipping waybackurls for {target} (not in gather mode)")
        
        # gau
        if 'g' in args.gather_mode:
            logger.log('INFO', f"Running gau for {target}...")
            exit_code, stdout, stderr = _run_command(["gau", "--subs", target])
            if exit_code == 0:
                gau_urls = _extract_js_urls(stdout)
                target_urls.update(gau_urls)
                logger.log('SUCCESS', f"Found {len(gau_urls)} JS URLs from gau for {target}")
            else:
                logger.log('ERROR', f"gau failed for {target}: {stderr}")
        else:
            logger.log('INFO', f"Skipping gau for {target} (not in gather mode)")
        
        # katana
        if 'k' in args.gather_mode:
            logger.log('INFO', f"Running katana for {target}...")
            katana_temp_file = output_dir / f"katana_temp_{target}.txt"
            exit_code, stdout, stderr = _run_command([
                "katana", "-u", f"{CONFIG['default_url_scheme']}{target}", "-jc", "-d", str(args.depth), "-o", str(katana_temp_file)
            ])
            if exit_code == 0 and katana_temp_file.exists() and katana_temp_file.stat().st_size > 0:
                with open(katana_temp_file, 'r') as f:
                    content = f.read()
                katana_urls = _extract_js_urls(content)
                target_urls.update(katana_urls)
                logger.log('SUCCESS', f"Found {len(katana_urls)} JS URLs from katana for {target}")
                # Clean up temp file
                katana_temp_file.unlink(missing_ok=True)
            else:
                logger.log('ERROR', f"katana failed for {target}: {stderr}")
        else:
            logger.log('INFO', f"Skipping katana for {target} (not in gather mode)")
        
        all_target_urls[target] = target_urls
    
    # Save results
    if len(targets) == 1:
        # Single target - save to simple files
        target = targets[0]
        urls = all_target_urls[target]
        
        all_js_file = output_dir / "all_js_urls.txt"
        with open(all_js_file, 'w') as f:
            f.write('\n'.join(sorted(urls)))
        
        logger.log('SUCCESS', f"Total unique JS URLs for {target}: {len(urls)}")
        logger.log('INFO', f"Results saved to: {all_js_file}")
    else:
        # Multiple targets - save to separate files
        for target, urls in all_target_urls.items():
            target_file = output_dir / f"js_urls_{target}.txt"
            with open(target_file, 'w') as f:
                f.write('\n'.join(sorted(urls)))
            logger.log('SUCCESS', f"Found {len(urls)} JS URLs for {target}")
        
        # Also save combined results
        all_urls = set()
        for urls in all_target_urls.values():
            all_urls.update(urls)
        
        combined_file = output_dir / "all_js_urls_combined.txt"
        with open(combined_file, 'w') as f:
            f.write('\n'.join(sorted(all_urls)))
        
        logger.log('SUCCESS', f"Combined total unique JS URLs: {len(all_urls)}")
        logger.log('INFO', f"Results saved to: {output_dir}")
    
    return len(all_target_urls) > 0

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