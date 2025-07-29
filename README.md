# mjsrecon: Modular JavaScript Reconnaissance Suite

A modular, extensible, and automated toolkit for JavaScript reconnaissance, endpoint discovery, and secret analysis across web targets.

## Features

- **Gather** JavaScript URLs from multiple sources (Wayback, gau, katana)
- **Verify** which JS URLs are live using httpx
- **Download** all live JS files (with deduplication)
- **Analyze** JS files for endpoints and secrets (jsluice, SecretFinder, LinkFinder, trufflehog)
- **Fuzz** for additional JS files using wordlists and permutations (ffuf)
- **Modular**: Each step is a separate module, easy to extend or replace
- **Colorful logging** and progress bars for clarity

---

## Requirements

- **Python 3.7+**
- **External tools** (must be in your PATH):
  - [waybackurls](https://github.com/tomnomnom/waybackurls)
  - [gau](https://github.com/lc/gau)
  - [katana](https://github.com/projectdiscovery/katana)
  - [httpx](https://github.com/projectdiscovery/httpx)
  - [ffuf](https://github.com/ffuf/ffuf)
  - [jsluice](https://github.com/BishopFox/jsluice)
  - [trufflehog](https://github.com/trufflesecurity/trufflehog)
  - Python scripts: `secretfinder.py`, `linkfinder.py` (should be in the `mjsrecon` directory)
- **Python packages**:
  - `aiohttp`
  - `tqdm`

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

- `gather`   : Gather JS URLs from waybackurls, gau, katana
- `verify`   : Verify which JS URLs are live
- `download` : Download all live JS files
- `analyze`  : Analyze JS files for endpoints and secrets
- `fuzz`     : Fuzz for additional JS files using ffuf

You can chain commands, e.g.:
```sh
python -m mjsrecon.core gather verify download --targets example.com
```

#### Running Multiple Commands in Sequence

You can specify multiple commands in a single run, and they will be executed in the order given.  
For example, the following will run `gather`, then `verify`, then `download` for the same targets:

```sh
python -m mjsrecon.core gather verify download --targets example.com
```

Each step will use the output of the previous step automatically.

### **Options**

- `-t, --targets`   : Comma-separated list of target domains (e.g. `example.com,example.org`)
- `-f, --file`      : File with target domains (one per line)
- `-o, --output`    : Output directory (default: `js_recon_output`)
- `-d, --depth`     : Katana crawl depth (default: 5)
- `--ffuf-wordlist` : Wordlist for ffuf JS bruteforce (for fuzz)
- `--ffuf-mode`     : ffuf fuzzing mode: `off`, `fuzz`, `permutation`, `both` (default: `off`)
- `--url-list`      : File containing a list of URLs to run fuzzing on (for fuzz-only mode)
- `--input`         : Input file for the current command (overrides default for that step)

---

## Workflow

### 1. **Gather**
Finds all possible JS URLs for each target using waybackurls, gau, and katana.

### 2. **Verify**
Checks which JS URLs are live using httpx.

### 3. **Download**
Downloads all live JS files, deduplicating by hash.

### 4. **Analyze**
Analyzes all downloaded JS files for endpoints and secrets using jsluice, SecretFinder, LinkFinder, and trufflehog.

### 5. **Fuzz**
Fuzzes for additional JS files using ffuf, with both wordlist and permutation-based approaches.

---

## Example Usage

**Step-by-step:**
```sh
python -m mjsrecon.core gather --targets example.com
python -m mjsrecon.core verify --targets example.com
python -m mjsrecon.core download --targets example.com
python -m mjsrecon.core analyze --targets example.com
```

**Fuzzing:**
```sh
python -m mjsrecon.core fuzz --targets example.com --ffuf-wordlist mywordlist.txt --ffuf-mode both
```

**Using a custom input file for a step:**
```sh
python -m mjsrecon.core verify --input my_js_urls.txt --targets example.com
```

---

## Output

Results are stored in the output directory (default: `js_recon_output`), organized by target and step.  
Each step writes its results to files and directories as defined in `mjsrecon/utils.py` (`CONFIG['files']` and `CONFIG['dirs']`).

---

## Extending

- Add new modules for additional analysis or processing steps.
- Replace or extend any step by editing the corresponding module in `mjsrecon/`.

---

## Troubleshooting

- Ensure all required external tools are installed and in your PATH.
- Check the log file in the output directory for detailed error messages.
- Use the `--input` option to provide custom input files for any step.

---

## License

MIT License

---

## Authors

- Original monolithic script: [Your Name/Handle]
- Modularization: [Your Name/Handle]