import argparse
from pathlib import Path
from .utils import CONFIG
from .logger import Logger
from . import gather, verify, deduplicate, download, analyze, fuzzing, toolcheck, report, github_recon

def main():
    parser = argparse.ArgumentParser(description="Modular JS Recon Tool")
    parser.add_argument('commands', nargs='+', choices=['gather', 'verify', 'deduplicate', 'download', 'analyze', 'fuzz', 'report', 'github'], help='Commands to run in sequence')
    parser.add_argument('-t', '--targets', help='Target domains (comma-separated) - required unless using --input')
    parser.add_argument('-o', '--output', default='./output', help='Output directory')
    parser.add_argument('-d', '--depth', type=int, default=5, help='Katana crawl depth (for gather)')
    parser.add_argument('--input', help='Input file for the current command (overrides default)')
    parser.add_argument('--independent', action='store_true', help='Run modules independently with custom input files')
    
    # Logging options
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging (debug level)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress info messages (warning level only)')
    
    # Fuzzing specific arguments
    parser.add_argument('--fuzz-mode', choices=['wordlist', 'permutation', 'both', 'off'], default='off', 
                       help='Fuzzing mode: wordlist only, permutation only, both, or off (default: off)')
    parser.add_argument('--fuzz-wordlist', help='Custom wordlist file for fuzzing (required if fuzz-mode is wordlist or both)')
    parser.add_argument('--fuzz-extensions', default='js', help='File extensions to fuzz (default: js)')
    parser.add_argument('--fuzz-status-codes', default='200,403,401', help='HTTP status codes to consider valid (default: 200,403,401)')
    parser.add_argument('--fuzz-threads', type=int, default=10, help='Number of concurrent fuzzing threads (default: 10)')
    parser.add_argument('--fuzz-timeout', type=int, default=30, help='Timeout for each fuzzing request in seconds (default: 30)')
    parser.add_argument('--fuzz-no-timeout', action='store_true', help='Disable timeout for ffuf (useful for large wordlists)')
    
    # GitHub reconnaissance specific arguments
    parser.add_argument('--github-token', help='GitHub API token for higher rate limits')
    parser.add_argument('--github-max-repos', type=int, default=10, help='Maximum number of repositories to analyze per target (default: 10)')
    parser.add_argument('--github-scan-tools', choices=['trufflehog', 'gitleaks', 'custom', 'all'], default='all', 
                       help='Secret scanning tools to use (default: all)')
    parser.add_argument('--github-skip-clone', action='store_true', help='Skip cloning repositories (only use API data)')
    
    args = parser.parse_args()

    # Validate arguments
    if not args.independent and not args.targets:
        parser.error("--targets is required unless using --independent mode")
    
    if args.independent and not args.input:
        parser.error("--input is required when using --independent mode")
    
    # Validate fuzzing arguments
    if 'fuzz' in args.commands:
        if args.fuzz_mode in ['wordlist', 'both'] and not args.fuzz_wordlist:
            parser.error("--fuzz-wordlist is required when using fuzz-mode wordlist or both")
        if args.fuzz_wordlist and not Path(args.fuzz_wordlist).exists():
            parser.error(f"Fuzzing wordlist file not found: {args.fuzz_wordlist}")

    # Parse targets (only if provided)
    if args.targets:
        targets = [t.strip() for t in args.targets.split(',')]
        args.targets = targets
    else:
        args.targets = []

    # Setup logger with verbosity options
    log_file = Path(args.output) / "js_recon.log"
    logger = Logger(log_file, verbose=args.verbose, quiet=args.quiet)

    # Check tools only if not in independent mode
    if not args.independent:
        toolcheck.check_tools(logger)

    for command in args.commands:
        if command == 'gather':
            gather.run(args, CONFIG, logger)
        elif command == 'verify':
            verify.run(args, CONFIG, logger)
        elif command == 'deduplicate':
            deduplicate.run(args, CONFIG, logger)
        elif command == 'download':
            import asyncio
            asyncio.run(download.run(args, CONFIG, logger))
        elif command == 'analyze':
            analyze.run(args, CONFIG, logger)
        elif command == 'fuzz':
            fuzzing.run(args, CONFIG, logger)
        elif command == 'report':
            report.run(args, CONFIG, logger)
        elif command == 'github':
            github_recon.run(args, CONFIG, logger)

if __name__ == "__main__":
    main()