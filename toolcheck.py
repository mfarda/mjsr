import shutil
from pathlib import Path
from .utils import CONFIG

def check_tools(logger):
    required_tools = set(CONFIG['tools']['required'])
    required_tools.update(CONFIG['tools'].get('full_mode', []))
    # Add ffuf if fuzzing is enabled (handled in fuzzing module)
    # Check for python scripts
    python_tools = CONFIG['tools'].get('python_tools', {})
    all_ok = True

    for tool in required_tools:
        if shutil.which(tool) is None:
            logger.log('ERROR', f"Required tool '{tool}' is not installed or not in PATH.")
            all_ok = False
        else:
            logger.log('INFO', f"Found tool: {tool}")

    for script_name, script_path in python_tools.items():
        if not Path(script_path).exists():
            logger.log('ERROR', f"Required script '{script_name}' not found at {script_path}")
            all_ok = False
        else:
            logger.log('INFO', f"Found script: {script_name} at {script_path}")

    if not all_ok:
        logger.log('ERROR', "One or more required tools/scripts are missing. Exiting.")
        exit(1)
