import os
from pathlib import Path
from urllib.parse import urlparse

CONFIG = {
    'tools': {
        'required': ["waybackurls", "gau", "katana", "httpx"],
        'full_mode': ["jsluice", "python3", "trufflehog"],
        'python_tools': {
            'secretfinder': os.path.abspath(os.path.join(os.path.dirname(__file__), "secretfinder.py")),
            'linkfinder': os.path.abspath(os.path.join(os.path.dirname(__file__), "linkfinder.py"))
        }
    },
    'timeouts': {
        'command': 300,
        'download': 30,
        'analysis': 30
    },
    'excluded_extensions': {'.css', '.png', '.jpg', '.jpeg', '.svg', '.ico', '.gif', '.woff', '.woff2', '.swf'},
    
    'results_dirs': [
        "jsluice", "secretfinder", "linkfinder", "trufflehog"        
    ],
    'prefixes': [
        '', 'app', 'lib', 'test', 'spec', 'src', 'dist', 'build', 'vendor', 'node', 'client', 'server', 'common',
        'utils', 'core', 'api', 'config', 'polyfill', 'plugin', 'module', 'feature', 'mock', 'temp', 'backup', 'dev',
        'prod', 'stage', 'local', 'global', 'init', '_', 'is', 'has', 'are', 'get', 'set', 'fetch', 'calculate',
        'compute', 'apply', 'push', 'post', 'render', 'start', 'stop', 'on', 'handle', 'create', 'update', 'delete'
    ],
    'suffixes': [
        'js', 'minjs', 'bundlejs', 'map', 'testjs', 'specjs', 'modulejs', 'mjs', 'cjs', 'nodejs', 'v1js', 'v2js',
        'debugjs', 'prodjs', 'devjs', 'bak', 'backup', 'tmp', 'temp', 'old', 'orig', 'copy', 'save', 'gz', 'zip',
        'tar', 'tgz', 'es6js', 'jsx', 'private', 'test', 'spec', 'min', 'dev', 'prod', 'v1', 'v2', 'const', 'enum',
        'config', 'utils', 'api', 'handler', 'module', 'cache'
    ],
    'separators': ['', '-', '_', '.'],
    'default_url_scheme': 'https://',
    'ffuf': {
        'raw_suffix': '_raw.txt',
        'filtered_suffix': '_filtered.txt',
        'results_dir': 'ffuf_results',
        'http_status_codes': '200,403,401',
        'output_format': 'json',
        'fuzz_word': 'FUZZ'
    },
    'dirs': {
        'results': 'results',
        'js_files': 'js_files',
        'ffuf_results': 'ffuf_results',
        'jsluice': 'jsluice',
        'secretfinder': 'secretfinder',
        'linkfinder': 'linkfinder',
        'trufflehog': 'trufflehog',
    },
    'files': {
        'wayback_raw': 'js_urls_wayback_raw.txt',
        'gau_raw': 'js_urls_gau_raw.txt',
        'katana_raw': 'js_urls_katana.txt',
        'all_js': 'all_js_urls.txt',
        'live_js': 'live_js_urls.txt',
        'deduplicated_js': 'deduplicated_js_urls.txt',
        'permutation_wordlist': 'permutation_wordlist.txt',
        'original_urls': 'original_urls.txt',
        'fuzzing_all': 'js_urls_fuzzing_all.txt',
        'fuzzing_new': 'js_urls_fuzzing_new.txt',
        'jsluice_urls': 'jsluice_urls.txt',
    },
    'max_concurrent_downloads': 10,
    'analysis_threads': 5,
}

def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)

def extract_js_filenames_from_urls(urls):
    js_filenames = []
    for url in urls:
        try:
            parsed = urlparse(url)
            filename = parsed.path.split('/')[-1]
            if filename and '.' in filename:
                js_filenames.append(filename)
        except:
            continue
    return js_filenames

def group_urls_by_directory(urls):
    url_groups = {}
    for url in urls:
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path
            if not path or path == '/':
                continue
            dir_path = '/'.join(path.split('/')[:-1])
            if not dir_path:
                dir_path = '/'
            if dir_path not in url_groups:
                url_groups[dir_path] = base_url
        except:
            continue
    return url_groups

def generate_js_permutations(js_filenames):
    permutations = set()
    prefixes = CONFIG['prefixes']
    suffixes = CONFIG['suffixes']
    separators = CONFIG['separators']
    for filename in js_filenames:
        base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
        for prefix in prefixes[:50]:
            if prefix:
                for sep in separators:
                    permutations.add(f"{prefix}{sep}{base_name}")
                    permutations.add(f"{base_name}{sep}{prefix}")
        for suffix in suffixes[:50]:
            if suffix:
                for sep in separators:
                    permutations.add(f"{base_name}{sep}{suffix}")
                    permutations.add(f"{suffix}{sep}{base_name}")
        permutations.add(base_name)
    return permutations