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
  - Python scripts: `secretfinder.py`, `linkfinder.py` (should be in the `mjsrecon` directory)
- **Python packages**:
  - `aiohttp`
  - `tqdm`
  - `requests`

Install Python dependencies:
```sh
pip install -r requirements.txt
```

---

## Installation

1. **Clone the repository** and ensure all external tools are installed and in your PATH.
2. Place `secretfinder.py` and `linkfinder.py` in the `mjsrecon` directory.
3. (Optional) Create a virtual environment and install Python dependencies.

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

# Deduplicate URLs from a file
python -m mjsrecon.core deduplicate --independent --input all_urls.txt

# Fuzz URLs from a file
python -m mjsrecon.core fuzz --independent --input urls.txt --fuzz-mode wordlist --fuzz-wordlist wordlist.txt

# Generate report for a directory
python -m mjsrecon.core report --independent --input analysis_results/
```

### **Options**

- `-t, --targets`    : Comma-separated list of target domains (e.g. `example.com,example.org`)
- `-o, --output`     : Output directory (default: `./output`)
- `-d, --depth`      : Katana crawl depth (default: 5)
- `--input`          : Input file/directory for the current command (overrides default)
- `--independent`    : Run module independently with custom input files

#### **Fuzzing Options**

- `--fuzz-mode`        : Fuzzing mode: `wordlist`, `permutation`, `both`, or `off` (default: `off`)
- `--fuzz-wordlist`    : Custom wordlist file for fuzzing (required if fuzz-mode is wordlist or both)
- `--fuzz-extensions`  : File extensions to fuzz (default: `js`)
- `--fuzz-status-codes`: HTTP status codes to consider valid (default: `200,403,401`)
- `--fuzz-threads`     : Number of concurrent fuzzing threads (default: `10`)
- `--fuzz-timeout`     : Timeout for each fuzzing request in seconds (default: `30`)

---

## Workflow

### 1. **Gather**
Finds all possible JS URLs for each target using waybackurls, gau, and katana.

### 2. **Verify**
Checks which JS URLs are live using requests library.

### 3. **Deduplicate**
Removes duplicate JS URLs using HTTP headers (ETag, Content-Length, Last-Modified).

### 4. **Download**
Downloads all live JS files, deduplicating by content hash.

### 5. **Analyze**
Analyzes all downloaded JS files for endpoints and secrets using jsluice, SecretFinder, LinkFinder, and trufflehog.

### 6. **Fuzz**
Fuzzes for additional JS files using ffuf with multiple modes:
- **Wordlist Mode**: Uses custom wordlist to discover JS files
- **Permutation Mode**: Generates permutations from existing JS filenames
- **Both Mode**: Combines wordlist and permutation fuzzing
- **Off Mode**: Skips fuzzing entirely

### 7. **Report**
Generates comprehensive statistics and findings report.

---

## Example Usage

**Full workflow:**
```sh
python -m mjsrecon.core gather verify deduplicate download analyze fuzz report --targets example.com
```

**Step-by-step:**
```sh
python -m mjsrecon.core gather --targets example.com
python -m mjsrecon.core verify --targets example.com
python -m mjsrecon.core deduplicate --targets example.com
python -m mjsrecon.core download --targets example.com
python -m mjsrecon.core analyze --targets example.com
python -m mjsrecon.core fuzz --targets example.com --fuzz-mode both --fuzz-wordlist wordlist.txt
python -m mjsrecon.core report --targets example.com
```

**Independent module usage:**
```sh
# Gather JS URLs for targets
python -m mjsrecon.core gather --independent --input targets.txt

# Verify URLs from a custom file
python -m mjsrecon.core verify --independent --input urls.txt

# Download JS files from verified URLs
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
```

**Advanced Fuzzing Examples:**
```sh
# Wordlist fuzzing with custom settings
python -m mjsrecon.core fuzz --targets example.com --fuzz-mode wordlist --fuzz-wordlist custom_wordlist.txt --fuzz-threads 20 --fuzz-timeout 60

# Permutation fuzzing only
python -m mjsrecon.core fuzz --targets example.com --fuzz-mode permutation --fuzz-extensions js,min.js

# Both modes with custom status codes
python -m mjsrecon.core fuzz --targets example.com --fuzz-mode both --fuzz-wordlist wordlist.txt --fuzz-status-codes 200,403,401,404

# Independent fuzzing with custom output
python -m mjsrecon.core fuzz --independent --input urls.txt --fuzz-mode wordlist --fuzz-wordlist wordlist.txt --output fuzzing_results/
```

**Using a custom input file for a step:**
```sh
python -m mjsrecon.core verify --input my_js_urls.txt --targets example.com
```

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

---

## Extending

- Add new modules for additional analysis or processing steps.
- Replace or extend any step by editing the corresponding module in `mjsrecon/`.
- Each module supports both integrated and independent operation modes.
- Customize fuzzing behavior by modifying ffuf parameters and wordlists.

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

**Debug Mode:**
Enable debug logging by setting the log level in the Logger class.

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Authors

- Original concept and implementation
- Modular refactoring and enhancements