import argparse
from pathlib import Path
from .utils import CONFIG
from .logger import Logger
from . import gather, verify, download, analyze, fuzzing, toolcheck

def main():
    parser = argparse.ArgumentParser(description="Modular JS Recon Tool")
    parser.add_argument('commands', nargs='+', choices=['gather', 'verify', 'download', 'analyze', 'fuzz'], help='Commands to run in sequence')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--targets', help='Comma-separated target domains')
    group.add_argument('-f', '--file', help='File with target domains')
    parser.add_argument('-o', '--output', default='js_recon_output', help='Output directory')
    parser.add_argument('-d', '--depth', type=int, default=5, help='Katana crawl depth (for gather)')
    parser.add_argument('--ffuf-wordlist', help='Wordlist for ffuf JS bruteforce (for fuzz)')
    parser.add_argument('--ffuf-mode', choices=['off', 'fuzz', 'permutation', 'both'], default='off', help='ffuf fuzzing mode (for fuzz)')
    parser.add_argument('--url-list', help='File containing a list of URLs to run fuzzing on (for fuzz-only mode)')
    parser.add_argument('--input', help='Input file for the current command (overrides default)')
    args = parser.parse_args()

    # Parse targets
    if args.targets:
        args.targets = [t.strip() for t in args.targets.split(',')]
    elif args.file:
        with open(args.file) as f:
            args.targets = [line.strip() for line in f if line.strip()]

    # Setup logger
    log_file = Path(args.output) / "js_recon.log"
    logger = Logger(log_file)

    toolcheck.check_tools(logger)

    for command in args.commands:
        if command == 'gather':
            gather.run(args, CONFIG, logger)
        elif command == 'verify':
            verify.run(args, CONFIG, logger)
        elif command == 'download':
            import asyncio
            asyncio.run(download.run(args, CONFIG, logger))
        elif command == 'analyze':
            analyze.run(args, CONFIG, logger)
        elif command == 'fuzz':
            fuzzing.run(args, CONFIG, logger)

if __name__ == "__main__":
    main()