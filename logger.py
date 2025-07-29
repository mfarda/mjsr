import logging
import os
import sys
from pathlib import Path

# Handle both relative and absolute imports
try:
    from .utils import ensure_dir
except ImportError:
    # If running as standalone script, add parent to path
    sys.path.insert(0, str(Path(__file__).parent))
    from utils import ensure_dir

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

class Logger:
    def __init__(self, log_file: str, verbose: bool = False, quiet: bool = False):
        ensure_dir(str(log_file.parent))
        
        # Set log level based on verbosity
        if quiet:
            log_level = logging.WARNING
        elif verbose:
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler(str(log_file))]
        )
        self.logger = logging.getLogger(__name__)
        self.verbose = verbose
        self.quiet = quiet

    def log(self, level: str, message: str):
        level = level.upper()
        
        # Skip debug messages if not verbose
        if level == 'DEBUG' and not self.verbose:
            return
            
        # Skip info messages if quiet mode
        if level == 'INFO' and self.quiet:
            return
        
        color_map = {
            'INFO': Colors.BLUE,
            'WARN': Colors.YELLOW,
            'ERROR': Colors.RED,
            'SUCCESS': Colors.GREEN,
            'DEBUG': Colors.NC
        }
        color = color_map.get(level, Colors.NC)
        
        # Only print to console if not quiet or if it's an error/warning
        if not self.quiet or level in ['ERROR', 'WARN']:
            print(f"[{color}{level}{Colors.NC}] {message}")
        
        # Always log to file
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(message)