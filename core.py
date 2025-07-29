import argparse
from pathlib import Path
from .utils import CONFIG
from .logger import Logger
from . import gather, verify, deduplicate, download, analyze, fuzzing, toolcheck, report

def main():
    parser = argparse.ArgumentParser(description="Modular JS Recon Tool")
    parser.add_argument('commands', nargs='+', choices=['gather', 'verify', 'deduplicate', 'download', 'analyze', 'fuzz', 'report'], help='Commands to run in sequence')
    parser.add_argument('-t', '--targets', help='Target domains (comma-separated) - required unless using --input')
    parser.add_argument('-o', '--output', default='./output', help='Output directory')
    parser.add_argument('-d', '--depth', type=int, default=5, help='Katana crawl depth (for gather)')
    parser.add_argument('--input', help='Input file for the current command (overrides default)')
    parser.add_argument('--independent', action='store_true', help='Run modules independently with custom input files')
    
    # Fuzzing specific arguments
    parser.add_argument('--fuzz-mode', choices=['wordlist', 'permutation', 'both', 'off'], default='off', 
                       help='Fuzzing mode: wordlist only, permutation only, both, or off (default: off)')
    parser.add_argument('--fuzz-wordlist', help='Custom wordlist file for fuzzing (required if fuzz-mode is wordlist or both)')
    parser.add_argument('--fuzz-extensions', default='js', help='File extensions to fuzz (default: js)')
    parser.add_argument('--fuzz-status-codes', default='200,403,401', help='HTTP status codes to consider valid (default: 200,403,401)')
    parser.add_argument('--fuzz-threads', type=int, default=10, help='Number of concurrent fuzzing threads (default: 10)')
    parser.add_argument('--fuzz-timeout', type=int, default=30, help='Timeout for each fuzzing request in seconds (default: 30)')
    
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

    # Setup logger
    log_file = Path(args.output) / "js_recon.log"
    logger = Logger(log_file)

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

if __name__ == "__main__":
    main()