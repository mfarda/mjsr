import argparse
from pathlib import Path
from .utils import CONFIG
from .logger import Logger
from . import gather, verify, deduplicate, download, analyze, fuzzing, toolcheck

def main():
    parser = argparse.ArgumentParser(description="Modular JS Recon Tool")
    parser.add_argument('commands', nargs='+', choices=['gather', 'verify', 'deduplicate', 'download', 'analyze', 'fuzz'], help='Commands to run in sequence')
    parser.add_argument('-t', '--targets', required=True, help='Target domains (comma-separated)')
    parser.add_argument('-o', '--output', default='./output', help='Output directory')
    parser.add_argument('--input', help='Input file for the current command (overrides default)')
    args = parser.parse_args()

    # Parse targets
    targets = [t.strip() for t in args.targets.split(',')]
    args.targets = targets

    # Setup logger
    log_file = Path(args.output) / "js_recon.log"
    logger = Logger(log_file)

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

if __name__ == "__main__":
    main()