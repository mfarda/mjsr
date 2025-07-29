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
    def __init__(self, log_file: str):
        ensure_dir(str(log_file.parent))
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler(str(log_file))]
        )
        self.logger = logging.getLogger(__name__)

    def log(self, level: str, message: str):
        level = level.upper()
        color_map = {
            'INFO': Colors.BLUE,
            'WARN': Colors.YELLOW,
            'ERROR': Colors.RED,
            'SUCCESS': Colors.GREEN
        }
        color = color_map.get(level, Colors.NC)
        print(f"[{color}{level}{Colors.NC}] {message}")
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(message)