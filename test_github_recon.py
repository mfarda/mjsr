#!/usr/bin/env python3
"""
Simple test script for the GitHub reconnaissance module
"""

import sys
import os
import time
from pathlib import Path

# Add the current directory to the path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all required modules can be imported"""
    try:
        from github_recon import GitHubRecon
        from utils import CONFIG
        from logger import Logger
        print("✅ All imports successful")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_config():
    """Test that the configuration is properly loaded"""
    try:
        from utils import CONFIG
        required_keys = ['tools', 'timeouts', 'excluded_extensions']
        for key in required_keys:
            if key not in CONFIG:
                print(f"❌ Missing config key: {key}")
                return False
        print("✅ Configuration loaded successfully")
        return True
    except Exception as e:
        print(f"❌ Config error: {e}")
        return False

def test_logger():
    """Test that the logger can be initialized"""
    try:
        from logger import Logger
        from pathlib import Path
        
        log_file = Path("./test_log.log")
        logger = Logger(log_file)
        logger.log('INFO', 'Test log message')
        print("✅ Logger initialized successfully")
        
        # Clean up - wait a bit for file to be released
        time.sleep(0.1)
        try:
            if log_file.exists():
                log_file.unlink()
        except Exception:
            pass  # Ignore cleanup errors
        return True
    except Exception as e:
        print(f"❌ Logger error: {e}")
        return False

def test_github_recon_class():
    """Test that the GitHubRecon class can be instantiated"""
    try:
        from github_recon import GitHubRecon
        from utils import CONFIG
        from logger import Logger
        from pathlib import Path
        
        # Create a simple args object
        class Args:
            def __init__(self):
                self.output = "./test_output"
                self.targets = ["test-target"]
                self.github_token = None
                self.github_max_repos = 5
                self.github_scan_tools = 'all'
                self.github_skip_clone = False
        
        args = Args()
        log_file = Path("./test_github_recon.log")
        logger = Logger(log_file)
        
        # Ensure output directory exists
        output_dir = Path(args.output)
        output_dir.mkdir(exist_ok=True)
        
        github_recon = GitHubRecon(args, CONFIG, logger)
        
        # Test basic attributes
        assert hasattr(github_recon, 'repositories')
        assert hasattr(github_recon, 'secrets_found')
        assert hasattr(github_recon, 'useful_data')
        assert hasattr(github_recon, 'tools')
        assert hasattr(github_recon, 'secret_patterns')
        
        print("✅ GitHubRecon class instantiated successfully")
        
        # Clean up
        time.sleep(0.1)
        try:
            if log_file.exists():
                log_file.unlink()
            # Clean up test output directory
            test_output = Path("./test_output")
            if test_output.exists():
                import shutil
                shutil.rmtree(test_output)
        except Exception:
            pass  # Ignore cleanup errors
        return True
    except Exception as e:
        print(f"❌ GitHubRecon class error: {e}")
        return False

def test_secret_patterns():
    """Test that secret patterns are properly defined"""
    try:
        from github_recon import GitHubRecon
        from utils import CONFIG
        from logger import Logger
        from pathlib import Path
        
        class Args:
            def __init__(self):
                self.output = "./test_output"
                self.targets = ["test-target"]
                self.github_token = None
                self.github_max_repos = 5
                self.github_scan_tools = 'all'
                self.github_skip_clone = False
        
        args = Args()
        log_file = Path("./test_patterns.log")
        logger = Logger(log_file)
        
        # Ensure output directory exists
        output_dir = Path(args.output)
        output_dir.mkdir(exist_ok=True)
        
        github_recon = GitHubRecon(args, CONFIG, logger)
        
        # Test that secret patterns are defined
        expected_patterns = ['api_keys', 'aws_keys', 'google_keys', 'database_connections', 'private_keys', 'passwords']
        for pattern_type in expected_patterns:
            if pattern_type not in github_recon.secret_patterns:
                print(f"❌ Missing secret pattern type: {pattern_type}")
                return False
        
        # Test that patterns are lists and contain regex patterns
        for pattern_type, patterns in github_recon.secret_patterns.items():
            if not isinstance(patterns, list):
                print(f"❌ Patterns for {pattern_type} is not a list")
                return False
            if len(patterns) == 0:
                print(f"❌ No patterns defined for {pattern_type}")
                return False
        
        print("✅ Secret patterns properly defined")
        
        # Clean up
        time.sleep(0.1)
        try:
            if log_file.exists():
                log_file.unlink()
            # Clean up test output directory
            test_output = Path("./test_output")
            if test_output.exists():
                import shutil
                shutil.rmtree(test_output)
        except Exception:
            pass  # Ignore cleanup errors
        return True
    except Exception as e:
        print(f"❌ Secret patterns error: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 Testing GitHub reconnaissance module...")
    print()
    
    tests = [
        ("Import Test", test_imports),
        ("Config Test", test_config),
        ("Logger Test", test_logger),
        ("GitHubRecon Class Test", test_github_recon_class),
        ("Secret Patterns Test", test_secret_patterns),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"Running {test_name}...")
        if test_func():
            passed += 1
        print()
    
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The GitHub reconnaissance module is ready to use.")
        print()
        print("📝 Next steps:")
        print("1. Install required tools: ./install_tools.sh (Linux/macOS) or install_tools.bat (Windows)")
        print("2. Set up GitHub API token: export GITHUB_TOKEN=your_token_here")
        print("3. Run a test scan: python -m mjsrecon.core github --targets test-org --github-max-repos 1")
    else:
        print("❌ Some tests failed. Please check the errors above.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 