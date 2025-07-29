import json
import os
from pathlib import Path
from datetime import datetime
from .utils import CONFIG, ensure_dir

def run(args, config, logger):
    """Generate comprehensive report with findings statistics"""
    # Handle independent mode
    if args.independent:
        return run_independent(args, config, logger)
    
    logger.log('INFO', "Generating comprehensive reconnaissance report...")
    
    total_stats = {
        'targets': {},
        'summary': {
            'total_targets': 0,
            'total_js_urls': 0,
            'total_live_urls': 0,
            'total_downloaded_files': 0,
            'total_secrets': 0,
            'total_endpoints': 0,
            'total_fuzzing_findings': 0
        }
    }
    
    # Analyze each target
    for target in args.targets:
        target_dir = Path(args.output) / target
        if not target_dir.exists():
            logger.log('WARN', f"[{target}] Target directory not found, skipping...")
            continue
            
        target_stats = analyze_target(target, target_dir, logger)
        total_stats['targets'][target] = target_stats
        
        # Update summary
        total_stats['summary']['total_targets'] += 1
        total_stats['summary']['total_js_urls'] += target_stats.get('gathering', {}).get('total_urls', 0)
        total_stats['summary']['total_live_urls'] += target_stats.get('verification', {}).get('live_urls', 0)
        total_stats['summary']['total_downloaded_files'] += target_stats.get('download', {}).get('downloaded_files', 0)
        total_stats['summary']['total_secrets'] += target_stats.get('analysis', {}).get('total_secrets', 0)
        total_stats['summary']['total_endpoints'] += target_stats.get('analysis', {}).get('total_endpoints', 0)
        total_stats['summary']['total_fuzzing_findings'] += target_stats.get('fuzzing', {}).get('total_findings', 0)
    
    # Generate and display report
    generate_report(total_stats, args.output, logger)
    
    return len(total_stats['targets']) > 0

def run_independent(args, config, logger):
    """Run report module independently with custom input directory"""
    # Determine input directory
    if args.input:
        input_dir = Path(args.input)
    else:
        logger.log('ERROR', "Input directory is required for independent reporting")
        return False
    
    if not input_dir.exists():
        logger.log('ERROR', f"Input directory not found: {input_dir}")
        return False
    
    logger.log('INFO', f"Generating report for directory: {input_dir}")
    
    # Analyze the input directory
    stats = analyze_directory_independent(input_dir, logger)
    
    # Determine output directory
    if args.output:
        output_dir = Path(args.output)
        ensure_dir(output_dir)
    else:
        # Use same directory as input
        output_dir = input_dir
    
    # Generate and display report
    generate_simple_report(stats, output_dir, input_dir.name, logger)
    
    return True

def analyze_directory_independent(input_dir, logger):
    """Analyze a directory independently and return statistics"""
    stats = {
        'directory': str(input_dir),
        'js_files': 0,
        'analysis_results': {
            'jsluice_secrets': 0,
            'jsluice_urls': 0,
            'secretfinder_secrets': 0,
            'linkfinder_endpoints': 0,
            'trufflehog_secrets': 0,
            'total_secrets': 0,
            'total_endpoints': 0
        },
        'file_sizes': {
            'total_size': 0,
            'average_size': 0
        }
    }
    
    # Count JS files
    js_files = list(input_dir.glob("*.js"))
    stats['js_files'] = len(js_files)
    
    # Calculate file sizes
    total_size = 0
    for js_file in js_files:
        total_size += js_file.stat().st_size
    
    stats['file_sizes']['total_size'] = total_size
    if stats['js_files'] > 0:
        stats['file_sizes']['average_size'] = total_size / stats['js_files']
    
    # Look for analysis results in subdirectories
    for subdir in ['jsluice', 'secretfinder', 'linkfinder', 'trufflehog']:
        analysis_dir = input_dir / subdir
        if analysis_dir.exists():
            if subdir == 'jsluice':
                for file in analysis_dir.glob("*.json"):
                    try:
                        with open(file, 'r') as f:
                            data = json.load(f)
                            if 'secrets' in file.name:
                                stats['analysis_results']['jsluice_secrets'] += len(data) if isinstance(data, list) else 1
                            elif 'urls' in file.name:
                                stats['analysis_results']['jsluice_urls'] += len(data) if isinstance(data, list) else 1
                    except:
                        continue
            elif subdir == 'secretfinder':
                for file in analysis_dir.glob("*.txt"):
                    try:
                        with open(file, 'r') as f:
                            content = f.read()
                            lines = [line.strip() for line in content.splitlines() if line.strip()]
                            stats['analysis_results']['secretfinder_secrets'] += len(lines)
                    except:
                        continue
            elif subdir == 'linkfinder':
                for file in analysis_dir.glob("*.txt"):
                    try:
                        with open(file, 'r') as f:
                            content = f.read()
                            lines = [line.strip() for line in content.splitlines() if line.strip()]
                            stats['analysis_results']['linkfinder_endpoints'] += len(lines)
                    except:
                        continue
            elif subdir == 'trufflehog':
                for file in analysis_dir.glob("*.json"):
                    try:
                        with open(file, 'r') as f:
                            data = json.load(f)
                            stats['analysis_results']['trufflehog_secrets'] += len(data) if isinstance(data, list) else 1
                    except:
                        continue
    
    # Calculate totals
    stats['analysis_results']['total_secrets'] = (
        stats['analysis_results']['jsluice_secrets'] + 
        stats['analysis_results']['secretfinder_secrets'] + 
        stats['analysis_results']['trufflehog_secrets']
    )
    stats['analysis_results']['total_endpoints'] = (
        stats['analysis_results']['jsluice_urls'] + 
        stats['analysis_results']['linkfinder_endpoints']
    )
    
    return stats

def generate_simple_report(stats, output_dir, dir_name, logger):
    """Generate a simple report for independent mode"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    report_content = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                        INDEPENDENT ANALYSIS REPORT                           ║
║                                {timestamp}                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

📁 DIRECTORY ANALYSIS: {dir_name}
─────────────────────────────────────────────────────────────────────────────────
• Directory Path: {stats['directory']}
• JS Files Found: {stats['js_files']:,}
• Total Size: {stats['file_sizes']['total_size']:,} bytes
• Average File Size: {stats['file_sizes']['average_size']:.0f} bytes

🔍 ANALYSIS RESULTS
─────────────────────────────────────────────────────────────────────────────────
• JSLuice Secrets: {stats['analysis_results']['jsluice_secrets']:,}
• JSLuice URLs: {stats['analysis_results']['jsluice_urls']:,}
• SecretFinder Secrets: {stats['analysis_results']['secretfinder_secrets']:,}
• LinkFinder Endpoints: {stats['analysis_results']['linkfinder_endpoints']:,}
• TruffleHog Secrets: {stats['analysis_results']['trufflehog_secrets']:,}
• Total Secrets Found: {stats['analysis_results']['total_secrets']:,}
• Total Endpoints Found: {stats['analysis_results']['total_endpoints']:,}

╔══════════════════════════════════════════════════════════════════════════════╗
║                              END OF REPORT                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    
    # Display report on screen
    print(report_content)
    
    # Save report to file
    report_file = output_dir / f"independent_report_{dir_name}.txt"
    with open(report_file, 'w') as f:
        f.write(report_content)
    
    logger.log('SUCCESS', f"Independent report generated and saved to: {report_file}")
    
    # Also save JSON version
    json_report_file = output_dir / f"independent_report_{dir_name}.json"
    with open(json_report_file, 'w') as f:
        json.dump(stats, f, indent=2, default=str)
    
    logger.log('INFO', f"JSON report saved to: {json_report_file}")

def analyze_target(target, target_dir, logger):
    """Analyze a single target and return statistics"""
    stats = {
        'gathering': analyze_gathering_phase(target, target_dir),
        'verification': analyze_verification_phase(target, target_dir),
        'deduplication': analyze_deduplication_phase(target, target_dir),
        'download': analyze_download_phase(target, target_dir),
        'analysis': analyze_analysis_phase(target, target_dir),
        'fuzzing': analyze_fuzzing_phase(target, target_dir)
    }
    
    logger.log('INFO', f"[{target}] Analysis complete")
    return stats

def analyze_gathering_phase(target, target_dir):
    """Analyze gathering phase results"""
    stats = {
        'wayback_urls': 0,
        'gau_urls': 0,
        'katana_urls': 0,
        'total_urls': 0,
        'unique_urls': 0
    }
    
    # Check waybackurls results
    wayback_file = target_dir / CONFIG['files']['wayback_raw']
    if wayback_file.exists():
        with open(wayback_file, 'r') as f:
            stats['wayback_urls'] = len([line for line in f if line.strip()])
    
    # Check gau results
    gau_file = target_dir / CONFIG['files']['gau_raw']
    if gau_file.exists():
        with open(gau_file, 'r') as f:
            stats['gau_urls'] = len([line for line in f if line.strip()])
    
    # Check katana results
    katana_file = target_dir / CONFIG['files']['katana_raw']
    if katana_file.exists():
        with open(katana_file, 'r') as f:
            stats['katana_urls'] = len([line for line in f if line.strip()])
    
    # Check all JS URLs
    all_js_file = target_dir / CONFIG['files']['all_js']
    if all_js_file.exists():
        with open(all_js_file, 'r') as f:
            stats['total_urls'] = len([line for line in f if line.strip()])
    
    stats['unique_urls'] = stats['total_urls']
    return stats

def analyze_verification_phase(target, target_dir):
    """Analyze verification phase results"""
    stats = {
        'live_urls': 0,
        'failed_urls': 0
    }
    
    live_js_file = target_dir / CONFIG['files']['live_js']
    if live_js_file.exists():
        with open(live_js_file, 'r') as f:
            stats['live_urls'] = len([line for line in f if line.strip()])
    
    # Calculate failed URLs (total - live)
    all_js_file = target_dir / CONFIG['files']['all_js']
    total_urls = 0
    if all_js_file.exists():
        with open(all_js_file, 'r') as f:
            total_urls = len([line for line in f if line.strip()])
    
    stats['failed_urls'] = total_urls - stats['live_urls']
    return stats

def analyze_deduplication_phase(target, target_dir):
    """Analyze deduplication phase results"""
    stats = {
        'original_urls': 0,
        'unique_urls': 0,
        'duplicates_removed': 0
    }
    
    deduplicated_file = target_dir / CONFIG['files']['deduplicated_js']
    if deduplicated_file.exists():
        with open(deduplicated_file, 'r') as f:
            stats['unique_urls'] = len([line for line in f if line.strip()])
    
    # Get original count from live_js
    live_js_file = target_dir / CONFIG['files']['live_js']
    if live_js_file.exists():
        with open(live_js_file, 'r') as f:
            stats['original_urls'] = len([line for line in f if line.strip()])
    
    stats['duplicates_removed'] = stats['original_urls'] - stats['unique_urls']
    return stats

def analyze_download_phase(target, target_dir):
    """Analyze download phase results"""
    stats = {
        'downloaded_files': 0,
        'total_size': 0,
        'average_size': 0
    }
    
    js_files_dir = target_dir / CONFIG['dirs']['js_files']
    if js_files_dir.exists():
        js_files = list(js_files_dir.glob("*.js"))
        stats['downloaded_files'] = len(js_files)
        
        total_size = 0
        for js_file in js_files:
            total_size += js_file.stat().st_size
        
        stats['total_size'] = total_size
        if stats['downloaded_files'] > 0:
            stats['average_size'] = total_size / stats['downloaded_files']
    
    return stats

def analyze_analysis_phase(target, target_dir):
    """Analyze analysis phase results"""
    stats = {
        'jsluice_secrets': 0,
        'jsluice_urls': 0,
        'secretfinder_secrets': 0,
        'linkfinder_endpoints': 0,
        'trufflehog_secrets': 0,
        'total_secrets': 0,
        'total_endpoints': 0,
        'analyzed_files': 0
    }
    
    results_dir = target_dir / CONFIG['dirs']['results']
    if not results_dir.exists():
        return stats
    
    # Count jsluice results
    jsluice_dir = results_dir / CONFIG['dirs']['jsluice']
    if jsluice_dir.exists():
        for file in jsluice_dir.glob("*.json"):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    if 'secrets' in file.name:
                        stats['jsluice_secrets'] += len(data) if isinstance(data, list) else 1
                    elif 'urls' in file.name:
                        stats['jsluice_urls'] += len(data) if isinstance(data, list) else 1
            except:
                continue
    
    # Count secretfinder results
    secretfinder_dir = results_dir / CONFIG['dirs']['secretfinder']
    if secretfinder_dir.exists():
        for file in secretfinder_dir.glob("*.txt"):
            try:
                with open(file, 'r') as f:
                    content = f.read()
                    # Count lines that look like secrets
                    lines = [line.strip() for line in content.splitlines() if line.strip()]
                    stats['secretfinder_secrets'] += len(lines)
            except:
                continue
    
    # Count linkfinder results
    linkfinder_dir = results_dir / CONFIG['dirs']['linkfinder']
    if linkfinder_dir.exists():
        for file in linkfinder_dir.glob("*.txt"):
            try:
                with open(file, 'r') as f:
                    content = f.read()
                    # Count lines that look like endpoints
                    lines = [line.strip() for line in content.splitlines() if line.strip()]
                    stats['linkfinder_endpoints'] += len(lines)
            except:
                continue
    
    # Count trufflehog results
    trufflehog_dir = results_dir / CONFIG['dirs']['trufflehog']
    if trufflehog_dir.exists():
        for file in trufflehog_dir.glob("*.json"):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    stats['trufflehog_secrets'] += len(data) if isinstance(data, list) else 1
            except:
                continue
    
    # Calculate totals
    stats['total_secrets'] = stats['jsluice_secrets'] + stats['secretfinder_secrets'] + stats['trufflehog_secrets']
    stats['total_endpoints'] = stats['jsluice_urls'] + stats['linkfinder_endpoints']
    
    # Count analyzed files
    js_files_dir = target_dir / CONFIG['dirs']['js_files']
    if js_files_dir.exists():
        stats['analyzed_files'] = len(list(js_files_dir.glob("*.js")))
    
    return stats

def analyze_fuzzing_phase(target, target_dir):
    """Analyze fuzzing phase results"""
    stats = {
        'wordlist_findings': 0,
        'permutation_findings': 0,
        'total_findings': 0,
        'new_findings': 0
    }
    
    # Count fuzzing results
    ffuf_results_dir = target_dir / CONFIG['dirs']['ffuf_results']
    if ffuf_results_dir.exists():
        for file in ffuf_results_dir.glob("*.txt"):
            try:
                with open(file, 'r') as f:
                    content = f.read()
                    lines = [line.strip() for line in content.splitlines() if line.strip()]
                    
                    if 'perm' in file.name:
                        stats['permutation_findings'] += len(lines)
                    else:
                        stats['wordlist_findings'] += len(lines)
            except:
                continue
    
    # Count new findings
    new_js_file = target_dir / CONFIG['files']['fuzzing_new']
    if new_js_file.exists():
        with open(new_js_file, 'r') as f:
            stats['new_findings'] = len([line for line in f if line.strip()])
    
    stats['total_findings'] = stats['wordlist_findings'] + stats['permutation_findings']
    return stats

def generate_report(total_stats, output_dir, logger):
    """Generate and display comprehensive report"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Create report content
    report_content = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                        JS RECONNAISSANCE REPORT                              ║
║                                {timestamp}                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

📊 SUMMARY STATISTICS
─────────────────────────────────────────────────────────────────────────────────
• Total Targets Processed: {total_stats['summary']['total_targets']}
• Total JS URLs Found: {total_stats['summary']['total_js_urls']:,}
• Total Live URLs: {total_stats['summary']['total_live_urls']:,}
• Total Downloaded Files: {total_stats['summary']['total_downloaded_files']:,}
• Total Secrets Found: {total_stats['summary']['total_secrets']:,}
• Total Endpoints Found: {total_stats['summary']['total_endpoints']:,}
• Total Fuzzing Findings: {total_stats['summary']['total_fuzzing_findings']:,}

📋 DETAILED TARGET ANALYSIS
─────────────────────────────────────────────────────────────────────────────────
"""
    
    # Add per-target details
    for target, stats in total_stats['targets'].items():
        report_content += f"""
🎯 TARGET: {target}
   Gathering Phase:
     • Wayback URLs: {stats['gathering']['wayback_urls']:,}
     • Gau URLs: {stats['gathering']['gau_urls']:,}
     • Katana URLs: {stats['gathering']['katana_urls']:,}
     • Total Unique URLs: {stats['gathering']['unique_urls']:,}
   
   Verification Phase:
     • Live URLs: {stats['verification']['live_urls']:,}
     • Failed URLs: {stats['verification']['failed_urls']:,}
   
   Deduplication Phase:
     • Original URLs: {stats['deduplication']['original_urls']:,}
     • Unique URLs: {stats['deduplication']['unique_urls']:,}
     • Duplicates Removed: {stats['deduplication']['duplicates_removed']:,}
   
   Download Phase:
     • Downloaded Files: {stats['download']['downloaded_files']:,}
     • Total Size: {stats['download']['total_size']:,} bytes
     • Average File Size: {stats['download']['average_size']:.0f} bytes
   
   Analysis Phase:
     • Analyzed Files: {stats['analysis']['analyzed_files']:,}
     • JSLuice Secrets: {stats['analysis']['jsluice_secrets']:,}
     • JSLuice URLs: {stats['analysis']['jsluice_urls']:,}
     • SecretFinder Secrets: {stats['analysis']['secretfinder_secrets']:,}
     • LinkFinder Endpoints: {stats['analysis']['linkfinder_endpoints']:,}
     • TruffleHog Secrets: {stats['analysis']['trufflehog_secrets']:,}
     • Total Secrets: {stats['analysis']['total_secrets']:,}
     • Total Endpoints: {stats['analysis']['total_endpoints']:,}
   
   Fuzzing Phase:
     • Wordlist Findings: {stats['fuzzing']['wordlist_findings']:,}
     • Permutation Findings: {stats['fuzzing']['permutation_findings']:,}
     • Total Findings: {stats['fuzzing']['total_findings']:,}
     • New Findings: {stats['fuzzing']['new_findings']:,}
"""
    
    report_content += f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                              END OF REPORT                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    
    # Display report on screen
    print(report_content)
    
    # Save report to file
    report_file = Path(output_dir) / "js_recon_report.txt"
    with open(report_file, 'w') as f:
        f.write(report_content)
    
    logger.log('SUCCESS', f"Report generated and saved to: {report_file}")
    
    # Also save JSON version for programmatic access
    json_report_file = Path(output_dir) / "js_recon_report.json"
    with open(json_report_file, 'w') as f:
        json.dump(total_stats, f, indent=2, default=str)
    
    logger.log('INFO', f"JSON report saved to: {json_report_file}")