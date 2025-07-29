# mjsrecon: Modular JavaScript Reconnaissance Suite

A modular, extensible, and automated toolkit for JavaScript reconnaissance, endpoint discovery, and secret analysis across web targets.

## Features

- **Gather** JavaScript URLs from multiple sources (Wayback, gau, katana)
- **Verify** which JS URLs are live using requests library
- **Download** all live JS files (with deduplication)
- **Analyze** JS files for endpoints and secrets (jsluice, SecretFinder, LinkFinder, trufflehog)
- **Fuzz** for additional JS files using wordlists and permutations (ffuf)
- **Deduplicate** JS URLs before downloading using HTTP headers
- **Report** comprehensive statistics and findings
- **GitHub Recon** Search GitHub repositories for secrets and useful data
- **Modular**: Each step is a separate module, easy to extend or replace
- **Independent Operation**: Run modules independently with custom input files
- **Advanced Fuzzing**: Multiple fuzzing modes with fine-grained control
- **Colorful logging** and progress bars for clarity

---

## Requirements

- **Python 3.7+**
- **External tools** (must be in your PATH):
  - [waybackurls](https://github.com/tomnomnom/waybackurls)
  - [gau](https://github.com/lc/gau)
  - [katana](https://github.com/projectdiscovery/katana)
  - [ffuf](https://github.com/ffuf/ffuf)
  - [jsluice](https://github.com/BishopFox/jsluice)
  - [trufflehog](https://github.com/trufflesecurity/trufflehog)
  - [gitleaks](https://github.com/gitleaks/gitleaks) (for GitHub recon)
  - Python scripts: `secretfinder.py`, `linkfinder.py` (should be in the `mjsrecon` directory)
- **Python packages**:
  - `aiohttp`
  - `tqdm`
  - `requests`
  - `PyGithub`
  - `gitpython`

Install Python dependencies:
```sh
pip install -r requirements.txt
```

---

## Installation

1. **Clone the repository** and ensure all external tools are installed and in your PATH.
2. Place `secretfinder.py` and `linkfinder.py` in the `mjsrecon` directory.
3. (Optional) Create a virtual environment and install Python dependencies.
4. (Optional) Set up GitHub API token for higher rate limits: `export GITHUB_TOKEN=your_token_here`

---

## Usage

Run the tool using the module syntax:

```sh
python -m mjsrecon.core [commands] [options]
```

### **Commands**

- `gather`      : Gather JS URLs from waybackurls, gau, katana
- `verify`      : Verify which JS URLs are live
- `deduplicate` : Deduplicate JS URLs using HTTP headers
- `download`    : Download all live JS files
- `analyze`     : Analyze JS files for endpoints and secrets
- `fuzz`        : Fuzz for additional JS files using ffuf
- `report`      : Generate comprehensive statistics report
- `github`      : Search GitHub repositories for secrets and useful data

You can chain commands, e.g.:
```sh
python -m mjsrecon.core gather verify deduplicate download analyze fuzz report --targets example.com
```

#### Running Multiple Commands in Sequence

You can specify multiple commands in a single run, and they will be executed in the order given.  
For example, the following will run `gather`, then `verify`, then `download` for the same targets:

```sh
python -m mjsrecon.core gather verify download --targets example.com
```

Each step will use the output of the previous step automatically.

#### Independent Module Operation

Each module can be run independently with custom input files using the `--independent` flag:

```sh
# Gather JS URLs for targets
python -m mjsrecon.core gather --independent --input example.com

# Verify URLs from a custom file
python -m mjsrecon.core verify --independent --input my_urls.txt

# Download JS files from a list of URLs
python -m mjsrecon.core download --independent --input live_urls.txt

# Analyze JS files from a directory
python -m mjsrecon.core analyze --independent --input js_files/

# Fuzz with wordlist only
python -m mjsrecon.core fuzz --independent --input urls.txt --fuzz-mode wordlist --fuzz-wordlist wordlist.txt

# Fuzz with permutation only
python -m mjsrecon.core fuzz --independent --input urls.txt --fuzz-mode permutation

# Fuzz with both modes
python -m mjsrecon.core fuzz --independent --input urls.txt --fuzz-mode both --fuzz-wordlist wordlist.txt

# Generate report for analysis results
python -m mjsrecon.core report --independent --input analysis_results/

# GitHub reconnaissance for organizations/users
python -m mjsrecon.core github --independent --input targets.txt
```

**Logging Options:**
```sh
# Quiet mode - only show warnings and errors
python -m mjsrecon.core github --targets company-name -q

# Verbose mode - show debug information
python -m mjsrecon.core github --targets company-name -v

# Normal mode - show info, warnings, and errors (default)
python -m mjsrecon.core github --targets company-name
```

**Advanced Fuzzing Examples:**
```sh
# Wordlist fuzzing with custom settings
python -m mjsrecon.core fuzz --targets example.com --fuzz-mode wordlist --fuzz-wordlist custom_wordlist.txt --fuzz-threads 20 --fuzz-timeout 60

# Permutation fuzzing only
python -m mjsrecon.core fuzz --targets example.com --fuzz-mode permutation --fuzz-extensions js,min.js

# Both modes with custom status codes
python -m mjsrecon.core fuzz --targets example.com --fuzz-mode both --fuzz-wordlist wordlist.txt --fuzz-status-codes 200,403,401,404

# Fuzzing with large wordlists (no timeout)
python -m mjsrecon.core fuzz --targets example.com --fuzz-mode wordlist --fuzz-wordlist large_wordlist.txt --fuzz-no-timeout

# High-performance fuzzing with custom settings
python -m mjsrecon.core fuzz --targets example.com --fuzz-mode both --fuzz-wordlist wordlist.txt --fuzz-threads 50 --fuzz-timeout 120 --fuzz-no-timeout

# Independent fuzzing with custom output
python -m mjsrecon.core fuzz --independent --input urls.txt --fuzz-mode wordlist --fuzz-wordlist wordlist.txt --output fuzzing_results/
```

**GitHub Reconnaissance Examples:**
```sh
# Basic GitHub reconnaissance for a company
python -m mjsrecon.core github --targets company-name

# GitHub reconnaissance with custom token
python -m mjsrecon.core github --targets company-name --github-token your_token_here

# Limit repositories to analyze
python -m mjsrecon.core github --targets company-name --github-max-repos 5

# Use specific scanning tools only
python -m mjsrecon.core github --targets company-name --github-scan-tools trufflehog

# Skip cloning repositories (API-only mode)
python -m mjsrecon.core github --targets company-name --github-skip-clone

# Multiple targets
python -m mjsrecon.core github --targets company1,company2,username1

# Independent mode with custom input
python -m mjsrecon.core github --independent --input github_targets.txt
```

**Using a custom input file for a step:**
```sh
python -m mjsrecon.core verify --input my_js_urls.txt --targets example.com
```

---

## GitHub Reconnaissance Module

The GitHub reconnaissance module (`github`) is a powerful tool for discovering secrets, sensitive data, and useful information in GitHub repositories related to your targets.

### Features

- **Repository Discovery**: Search for repositories by organization, user, or keywords
- **Secret Scanning**: Use multiple tools (TruffleHog, GitLeaks, custom patterns)
- **Organization Analysis**: Get detailed information about GitHub organizations
- **User Analysis**: Analyze GitHub users and their repositories
- **Content Analysis**: Categorize and analyze repository content
- **Commit History**: Extract recent commit information
- **Issues & PRs**: Search for issues and pull requests
- **Rate Limiting**: Automatic handling of GitHub API rate limits
- **Comprehensive Reporting**: Generate detailed reports in multiple formats

### Secret Patterns Detected

- **API Keys**: Various API key formats (32-45 characters)
- **AWS Keys**: Access keys and secret keys
- **Google Keys**: API keys and OAuth tokens
- **Database Connections**: MySQL, PostgreSQL, MongoDB connection strings
- **Private Keys**: RSA, DSA, EC private keys
- **Passwords**: Hardcoded passwords in configuration files

### Tools Used

- **TruffleHog**: Advanced secret scanning with entropy analysis
- **GitLeaks**: Comprehensive secret detection with rule-based scanning
- **Custom Patterns**: Regex-based scanning for specific patterns
- **Git Commands**: For repository cloning and commit analysis

### Output Structure

```
output/
└── github_recon/
    ├── repositories.json          # All discovered repositories
    ├── secrets_found.json         # All secrets found
    ├── useful_data.json           # Repository analysis data
    ├── organizations.json         # Organization information
    ├── users.json                 # User information
    ├── summary_report.md          # Human-readable summary
    └── cloned_repos/              # Temporarily cloned repositories
```

### Configuration Options

- `--github-token`: GitHub API token for higher rate limits
- `--github-max-repos`: Maximum repositories to analyze per target (default: 10)
- `--github-scan-tools`: Secret scanning tools to use (trufflehog, gitleaks, custom, all)
- `--github-skip-clone`: Skip cloning repositories (API-only mode)

### Best Practices

1. **Use GitHub Token**: Set up a GitHub personal access token for higher rate limits
2. **Limit Scope**: Use `--github-max-repos` to control analysis scope
3. **Tool Selection**: Choose specific tools based on your needs
4. **Cleanup**: The module automatically cleans up cloned repositories
5. **Rate Limiting**: The module handles rate limits automatically

---

## Output

Results are stored in the output directory (default: `./output`), organized by target and step.  
Each step writes its results to files and directories as defined in `mjsrecon/utils.py` (`CONFIG['files']` and `CONFIG['dirs']`).

**Independent mode output:**
- When using `--independent`, output files are saved to the specified `--output` directory or next to the input file
- Reports are generated in both text and JSON formats for easy parsing

**Fuzzing output:**
- `ffuf_results/`: Raw ffuf output files
- `all_fuzzing_results.txt`: All discovered JS URLs
- `fuzzing_summary.json`: Detailed statistics and findings
- Separate files for wordlist and permutation results

**GitHub reconnaissance output:**
- `github_recon/`: All GitHub reconnaissance results
- `repositories.json`: Discovered repositories with metadata
- `secrets_found.json`: All secrets found with details
- `useful_data.json`: Repository content analysis
- `summary_report.md`: Human-readable summary report

---

## Extending

- Add new modules for additional analysis or processing steps.
- Replace or extend any step by editing the corresponding module in `mjsrecon/`.
- Each module supports both integrated and independent operation modes.
- Customize fuzzing behavior by modifying ffuf parameters and wordlists.
- Extend GitHub reconnaissance with additional secret patterns or tools.

---

## Troubleshooting

**Common Issues:**

1. **Module not found errors**: Ensure you're running from the correct directory and all dependencies are installed.

2. **External tool errors**: Verify all required tools are in your PATH and properly installed.

3. **Permission errors**: Ensure you have write permissions to the output directory.

4. **Network timeouts**: Adjust timeout values in `CONFIG['timeouts']` if needed.

5. **Fuzzing errors**: 
   - Ensure ffuf is installed and in PATH
   - Check that wordlist file exists and is readable
   - Verify target URLs are accessible
   - Adjust `--fuzz-threads` and `--fuzz-timeout` for network conditions

6. **GitHub reconnaissance errors**:
   - Ensure TruffleHog and GitLeaks are installed and in PATH
   - Check GitHub API rate limits (use token for higher limits)
   - Verify target names are valid GitHub organizations/users
   - Ensure sufficient disk space for repository cloning

**Debug Mode:**
Enable debug logging by setting the log level in the Logger class.

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Authors

- Original concept and implementation
- Modular refactoring and enhancements