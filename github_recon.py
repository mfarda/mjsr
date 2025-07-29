#!/usr/bin/env python3
"""
GitHub Reconnaissance Module for mjsrecon
Searches for secrets, sensitive data, and useful information in GitHub repositories
"""

import os
import json
import time
import asyncio
import aiohttp
import subprocess
import tempfile
import shutil
from pathlib import Path
from urllib.parse import urlparse, quote
from typing import List, Dict, Set, Optional, Tuple
import re
from datetime import datetime, timedelta
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import hashlib

class GitHubRecon:
    def __init__(self, args, config, logger):
        self.args = args
        self.config = config
        self.logger = logger
        self.output_dir = Path(args.output)
        self.github_dir = self.output_dir / "github_recon"
        self.github_dir.mkdir(exist_ok=True)
        
        # GitHub API configuration
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.github_api_base = "https://api.github.com"
        self.github_search_base = "https://api.github.com/search"
        
        # Rate limiting
        self.rate_limit_remaining = 5000
        self.rate_limit_reset = 0
        
        # Results storage
        self.repositories = []
        self.secrets_found = []
        self.useful_data = []
        self.organizations = []
        self.users = []
        
        # Tools configuration
        self.tools = {
            'trufflehog': self._check_tool('trufflehog'),
            'gitleaks': self._check_tool('gitleaks'),
            'gitrob': self._check_tool('gitrob'),
            'repo-supervisor': self._check_tool('repo-supervisor'),
            'git-secrets': self._check_tool('git-secrets')
        }
        
        # Secret patterns
        self.secret_patterns = {
            'api_keys': [
                r'[aA][pP][iI][-_]?[kK][eE][yY].*[\'"][0-9a-zA-Z]{32,45}[\'"]',
                r'[aA][pP][iI][-_]?[tT][oO][kK][eE][nN].*[\'"][0-9a-zA-Z]{32,45}[\'"]',
                r'[sS][eE][cC][rR][eE][tT].*[\'"][0-9a-zA-Z]{32,45}[\'"]',
            ],
            'aws_keys': [
                r'AKIA[0-9A-Z]{16}',
                r'aws_access_key_id.*[\'"][0-9A-Z]{20}[\'"]',
                r'aws_secret_access_key.*[\'"][0-9A-Za-z/+=]{40}[\'"]',
            ],
            'google_keys': [
                r'AIza[0-9A-Za-z\-_]{35}',
                r'ya29\.[0-9A-Za-z\-_]+',
            ],
            'database_connections': [
                r'mysql://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:[0-9]+/[a-zA-Z0-9._-]+',
                r'postgresql://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:[0-9]+/[a-zA-Z0-9._-]+',
                r'mongodb://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:[0-9]+/[a-zA-Z0-9._-]+',
            ],
            'private_keys': [
                r'-----BEGIN PRIVATE KEY-----',
                r'-----BEGIN RSA PRIVATE KEY-----',
                r'-----BEGIN DSA PRIVATE KEY-----',
                r'-----BEGIN EC PRIVATE KEY-----',
            ],
            'passwords': [
                r'[pP][aA][sS][sS][wW][oO][rR][dD].*[\'"][^\'"]{8,}[\'"]',
                r'[pP][wW][dD].*[\'"][^\'"]{8,}[\'"]',
            ]
        }

    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available in PATH"""
        try:
            subprocess.run([tool_name, '--version'], 
                         capture_output=True, check=True, timeout=5)
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _make_github_request(self, url: str, headers: Dict = None) -> Dict:
        """Make a GitHub API request with rate limiting"""
        if headers is None:
            headers = {}
        
        if self.github_token:
            headers['Authorization'] = f'token {self.github_token}'
        
        headers['Accept'] = 'application/vnd.github.v3+json'
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            
            # Handle rate limiting
            if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers:
                self.rate_limit_remaining = int(response.headers['X-RateLimit-Remaining'])
                self.rate_limit_reset = int(response.headers['X-RateLimit-Reset'])
                
                if self.rate_limit_remaining == 0:
                    reset_time = datetime.fromtimestamp(self.rate_limit_reset)
                    wait_time = (reset_time - datetime.now()).total_seconds()
                    if wait_time > 0:
                        self.logger.log('WARN', f'Rate limit exceeded. Waiting {wait_time:.0f} seconds...')
                        time.sleep(wait_time)
                        return self._make_github_request(url, headers)
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.logger.log('ERROR', f'GitHub API request failed: {e}')
            return {}

    def search_repositories(self, target: str) -> List[Dict]:
        """Search for repositories related to the target"""
        self.logger.log('INFO', f'Searching for repositories related to: {target}')
        
        repositories = []
        search_queries = [
            f'"{target}"',
            f'org:{target}',
            f'user:{target}',
            f'{target}',
            f'"{target}" language:javascript',
            f'"{target}" language:python',
            f'"{target}" language:go',
            f'"{target}" language:java'
        ]
        
        for query in search_queries:
            try:
                url = f"{self.github_search_base}/repositories?q={quote(query)}&sort=updated&order=desc&per_page=100"
                results = self._make_github_request(url)
                
                if 'items' in results:
                    for repo in results['items']:
                        repo_info = {
                            'name': repo['full_name'],
                            'description': repo.get('description', ''),
                            'url': repo['html_url'],
                            'clone_url': repo['clone_url'],
                            'ssh_url': repo['ssh_url'],
                            'language': repo.get('language', ''),
                            'stars': repo['stargazers_count'],
                            'forks': repo['forks_count'],
                            'updated_at': repo['updated_at'],
                            'created_at': repo['created_at'],
                            'size': repo['size'],
                            'default_branch': repo['default_branch'],
                            'topics': repo.get('topics', []),
                            'search_query': query
                        }
                        repositories.append(repo_info)
                        
                # Respect rate limits
                time.sleep(1)
                
            except Exception as e:
                self.logger.log('ERROR', f'Error searching repositories with query "{query}": {e}')
                continue
        
        # Remove duplicates
        seen = set()
        unique_repos = []
        for repo in repositories:
            if repo['name'] not in seen:
                seen.add(repo['name'])
                unique_repos.append(repo)
        
        self.logger.log('SUCCESS', f'Found {len(unique_repos)} unique repositories')
        return unique_repos

    def get_organization_info(self, org_name: str) -> Dict:
        """Get detailed information about an organization"""
        self.logger.log('INFO', f'Getting organization info for: {org_name}')
        
        url = f"{self.github_api_base}/orgs/{org_name}"
        org_info = self._make_github_request(url)
        
        if org_info:
            # Get organization repositories
            repos_url = f"{self.github_api_base}/orgs/{org_name}/repos?per_page=100"
            repos = self._make_github_request(repos_url)
            
            # Get organization members
            members_url = f"{self.github_api_base}/orgs/{org_name}/members?per_page=100"
            members = self._make_github_request(members_url)
            
            org_data = {
                'name': org_info.get('login', org_name),
                'description': org_info.get('description', ''),
                'url': org_info.get('html_url', ''),
                'avatar_url': org_info.get('avatar_url', ''),
                'public_repos': org_info.get('public_repos', 0),
                'total_private_repos': org_info.get('total_private_repos', 0),
                'followers': org_info.get('followers', 0),
                'following': org_info.get('following', 0),
                'created_at': org_info.get('created_at', ''),
                'updated_at': org_info.get('updated_at', ''),
                'location': org_info.get('location', ''),
                'email': org_info.get('email', ''),
                'blog': org_info.get('blog', ''),
                'twitter_username': org_info.get('twitter_username', ''),
                'repositories': repos if isinstance(repos, list) else [],
                'members': members if isinstance(members, list) else []
            }
            
            return org_data
        
        return {}

    def get_user_info(self, username: str) -> Dict:
        """Get detailed information about a user"""
        self.logger.log('INFO', f'Getting user info for: {username}')
        
        url = f"{self.github_api_base}/users/{username}"
        user_info = self._make_github_request(url)
        
        if user_info:
            # Get user repositories
            repos_url = f"{self.github_api_base}/users/{username}/repos?per_page=100"
            repos = self._make_github_request(repos_url)
            
            # Get user organizations
            orgs_url = f"{self.github_api_base}/users/{username}/orgs?per_page=100"
            orgs = self._make_github_request(orgs_url)
            
            user_data = {
                'username': user_info.get('login', username),
                'name': user_info.get('name', ''),
                'email': user_info.get('email', ''),
                'bio': user_info.get('bio', ''),
                'url': user_info.get('html_url', ''),
                'avatar_url': user_info.get('avatar_url', ''),
                'public_repos': user_info.get('public_repos', 0),
                'public_gists': user_info.get('public_gists', 0),
                'followers': user_info.get('followers', 0),
                'following': user_info.get('following', 0),
                'created_at': user_info.get('created_at', ''),
                'updated_at': user_info.get('updated_at', ''),
                'location': user_info.get('location', ''),
                'blog': user_info.get('blog', ''),
                'twitter_username': user_info.get('twitter_username', ''),
                'company': user_info.get('company', ''),
                'repositories': repos if isinstance(repos, list) else [],
                'organizations': orgs if isinstance(orgs, list) else []
            }
            
            return user_data
        
        return {}

    def clone_repository(self, repo_url: str, repo_name: str) -> Optional[Path]:
        """Clone a repository for analysis"""
        try:
            clone_dir = self.github_dir / "cloned_repos" / repo_name.replace('/', '_')
            clone_dir.mkdir(parents=True, exist_ok=True)
            
            if clone_dir.exists() and any(clone_dir.iterdir()):
                self.logger.log('INFO', f'Repository {repo_name} already cloned, skipping...')
                return clone_dir
            
            self.logger.log('INFO', f'Cloning repository: {repo_name}')
            
            # Use shallow clone for faster download
            cmd = ['git', 'clone', '--depth', '1', repo_url, str(clone_dir)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                self.logger.log('SUCCESS', f'Successfully cloned {repo_name}')
                return clone_dir
            else:
                self.logger.log('ERROR', f'Failed to clone {repo_name}: {result.stderr}')
                return None
                
        except subprocess.TimeoutExpired:
            self.logger.log('ERROR', f'Timeout cloning repository: {repo_name}')
            return None
        except Exception as e:
            self.logger.log('ERROR', f'Error cloning repository {repo_name}: {e}')
            return None

    def scan_with_trufflehog(self, repo_path: Path) -> List[Dict]:
        """Scan repository with TruffleHog"""
        secrets = []
        
        if not self.tools['trufflehog']:
            self.logger.log('WARN', 'TruffleHog not found, skipping TruffleHog scan')
            return secrets
        
        try:
            self.logger.log('INFO', f'Scanning {repo_path.name} with TruffleHog')
            
            cmd = ['trufflehog', '--json', str(repo_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            secret_data = json.loads(line)
                            secrets.append({
                                'tool': 'trufflehog',
                                'file': secret_data.get('path', ''),
                                'line': secret_data.get('line', ''),
                                'commit': secret_data.get('commit', ''),
                                'secret': secret_data.get('raw', ''),
                                'reason': secret_data.get('reason', ''),
                                'repo': repo_path.name
                            })
                        except json.JSONDecodeError:
                            continue
            
            self.logger.log('SUCCESS', f'TruffleHog found {len(secrets)} secrets in {repo_path.name}')
            
        except subprocess.TimeoutExpired:
            self.logger.log('ERROR', f'TruffleHog scan timeout for {repo_path.name}')
        except Exception as e:
            self.logger.log('ERROR', f'Error running TruffleHog on {repo_path.name}: {e}')
        
        return secrets

    def scan_with_gitleaks(self, repo_path: Path) -> List[Dict]:
        """Scan repository with GitLeaks"""
        secrets = []
        
        if not self.tools['gitleaks']:
            self.logger.log('WARN', 'GitLeaks not found, skipping GitLeaks scan')
            return secrets
        
        try:
            self.logger.log('INFO', f'Scanning {repo_path.name} with GitLeaks')
            
            cmd = ['gitleaks', 'detect', '--source', str(repo_path), '--report-format', 'json', '--report-path', '/dev/stdout']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0 and result.stdout:
                try:
                    leaks_data = json.loads(result.stdout)
                    for leak in leaks_data:
                        secrets.append({
                            'tool': 'gitleaks',
                            'file': leak.get('File', ''),
                            'line': leak.get('Line', ''),
                            'commit': leak.get('Commit', ''),
                            'secret': leak.get('Secret', ''),
                            'rule': leak.get('Rule', ''),
                            'repo': repo_path.name
                        })
                except json.JSONDecodeError:
                    pass
            
            self.logger.log('SUCCESS', f'GitLeaks found {len(secrets)} secrets in {repo_path.name}')
            
        except subprocess.TimeoutExpired:
            self.logger.log('ERROR', f'GitLeaks scan timeout for {repo_path.name}')
        except Exception as e:
            self.logger.log('ERROR', f'Error running GitLeaks on {repo_path.name}: {e}')
        
        return secrets

    def scan_with_custom_patterns(self, repo_path: Path) -> List[Dict]:
        """Scan repository with custom secret patterns"""
        secrets = []
        
        try:
            self.logger.log('INFO', f'Scanning {repo_path.name} with custom patterns')
            
            for file_path in repo_path.rglob('*'):
                if file_path.is_file() and file_path.stat().st_size < 10 * 1024 * 1024:  # Skip files > 10MB
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern_type, patterns in self.secret_patterns.items():
                            for pattern in patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                                for match in matches:
                                    line_num = content[:match.start()].count('\n') + 1
                                    line_content = content.split('\n')[line_num - 1] if line_num <= len(content.split('\n')) else ''
                                    
                                    secrets.append({
                                        'tool': 'custom_patterns',
                                        'pattern_type': pattern_type,
                                        'file': str(file_path.relative_to(repo_path)),
                                        'line': line_num,
                                        'line_content': line_content.strip(),
                                        'secret': match.group(0),
                                        'repo': repo_path.name
                                    })
                    except Exception as e:
                        continue
            
            self.logger.log('SUCCESS', f'Custom patterns found {len(secrets)} secrets in {repo_path.name}')
            
        except Exception as e:
            self.logger.log('ERROR', f'Error scanning {repo_path.name} with custom patterns: {e}')
        
        return secrets

    def analyze_repository_content(self, repo_path: Path) -> Dict:
        """Analyze repository content for useful data"""
        analysis = {
            'config_files': [],
            'dependency_files': [],
            'documentation': [],
            'scripts': [],
            'interesting_files': [],
            'file_types': {},
            'total_files': 0,
            'total_size': 0
        }
        
        try:
            for file_path in repo_path.rglob('*'):
                if file_path.is_file():
                    analysis['total_files'] += 1
                    analysis['total_size'] += file_path.stat().st_size
                    
                    file_ext = file_path.suffix.lower()
                    analysis['file_types'][file_ext] = analysis['file_types'].get(file_ext, 0) + 1
                    
                    relative_path = str(file_path.relative_to(repo_path))
                    
                    # Categorize files
                    if any(config in relative_path.lower() for config in ['config', 'conf', '.env', 'settings']):
                        analysis['config_files'].append(relative_path)
                    elif any(dep in relative_path.lower() for dep in ['package.json', 'requirements.txt', 'pom.xml', 'build.gradle', 'go.mod']):
                        analysis['dependency_files'].append(relative_path)
                    elif any(doc in relative_path.lower() for doc in ['readme', 'docs', 'documentation', '.md']):
                        analysis['documentation'].append(relative_path)
                    elif any(script in relative_path.lower() for script in ['.sh', '.py', '.js', '.php', '.rb']):
                        analysis['scripts'].append(relative_path)
                    elif any(interesting in relative_path.lower() for interesting in ['backup', 'dump', 'test', 'example', 'sample']):
                        analysis['interesting_files'].append(relative_path)
            
        except Exception as e:
            self.logger.log('ERROR', f'Error analyzing repository content: {e}')
        
        return analysis

    def get_commit_history(self, repo_path: Path, max_commits: int = 100) -> List[Dict]:
        """Get recent commit history"""
        commits = []
        
        try:
            cmd = ['git', 'log', '--pretty=format:%H|%an|%ae|%ad|%s', '--date=iso', '-n', str(max_commits)]
            result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if '|' in line:
                        parts = line.split('|', 4)
                        if len(parts) == 5:
                            commits.append({
                                'hash': parts[0],
                                'author_name': parts[1],
                                'author_email': parts[2],
                                'date': parts[3],
                                'message': parts[4]
                            })
            
        except Exception as e:
            self.logger.log('ERROR', f'Error getting commit history: {e}')
        
        return commits

    def search_issues_and_prs(self, repo_name: str) -> Dict:
        """Search for issues and pull requests"""
        results = {'issues': [], 'pull_requests': []}
        
        try:
            # Search for issues
            issues_url = f"{self.github_search_base}/issues?q=repo:{repo_name}&per_page=100"
            issues = self._make_github_request(issues_url)
            
            if 'items' in issues:
                for issue in issues['items']:
                    if 'pull_request' not in issue:  # It's an issue, not a PR
                        results['issues'].append({
                            'number': issue['number'],
                            'title': issue['title'],
                            'body': issue.get('body', ''),
                            'state': issue['state'],
                            'created_at': issue['created_at'],
                            'updated_at': issue['updated_at'],
                            'user': issue['user']['login'],
                            'labels': [label['name'] for label in issue.get('labels', [])]
                        })
            
            # Search for pull requests
            prs_url = f"{self.github_search_base}/issues?q=repo:{repo_name}+is:pr&per_page=100"
            prs = self._make_github_request(prs_url)
            
            if 'items' in prs:
                for pr in prs['items']:
                    results['pull_requests'].append({
                        'number': pr['number'],
                        'title': pr['title'],
                        'body': pr.get('body', ''),
                        'state': pr['state'],
                        'created_at': pr['created_at'],
                        'updated_at': pr['updated_at'],
                        'user': pr['user']['login'],
                        'labels': [label['name'] for label in pr.get('labels', [])],
                        'merged': pr.get('pull_request', {}).get('merged_at') is not None
                    })
            
        except Exception as e:
            self.logger.log('ERROR', f'Error searching issues and PRs for {repo_name}: {e}')
        
        return results

    def save_results(self):
        """Save all results to files"""
        try:
            # Save repositories
            with open(self.github_dir / 'repositories.json', 'w') as f:
                json.dump(self.repositories, f, indent=2)
            
            # Save secrets
            with open(self.github_dir / 'secrets_found.json', 'w') as f:
                json.dump(self.secrets_found, f, indent=2)
            
            # Save useful data
            with open(self.github_dir / 'useful_data.json', 'w') as f:
                json.dump(self.useful_data, f, indent=2)
            
            # Save organizations
            with open(self.github_dir / 'organizations.json', 'w') as f:
                json.dump(self.organizations, f, indent=2)
            
            # Save users
            with open(self.github_dir / 'users.json', 'w') as f:
                json.dump(self.users, f, indent=2)
            
            # Generate summary report
            self.generate_summary_report()
            
            self.logger.log('SUCCESS', f'All results saved to {self.github_dir}')
            
        except Exception as e:
            self.logger.log('ERROR', f'Error saving results: {e}')

    def generate_summary_report(self):
        """Generate a summary report"""
        report_path = self.github_dir / 'summary_report.md'
        
        with open(report_path, 'w') as f:
            f.write('# GitHub Reconnaissance Summary Report\n\n')
            f.write(f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n\n')
            
            f.write('## Overview\n\n')
            f.write(f'- **Total Repositories Found**: {len(self.repositories)}\n')
            f.write(f'- **Total Secrets Found**: {len(self.secrets_found)}\n')
            f.write(f'- **Organizations Analyzed**: {len(self.organizations)}\n')
            f.write(f'- **Users Analyzed**: {len(self.users)}\n\n')
            
            if self.secrets_found:
                f.write('## Secrets Found\n\n')
                f.write('| Tool | Repository | File | Line | Secret Type |\n')
                f.write('|------|------------|------|------|-------------|\n')
                
                for secret in self.secrets_found:
                    f.write(f"| {secret.get('tool', 'N/A')} | {secret.get('repo', 'N/A')} | {secret.get('file', 'N/A')} | {secret.get('line', 'N/A')} | {secret.get('pattern_type', secret.get('reason', 'N/A'))} |\n")
                f.write('\n')
            
            if self.repositories:
                f.write('## Top Repositories\n\n')
                f.write('| Repository | Stars | Forks | Language | Description |\n')
                f.write('|------------|-------|-------|----------|-------------|\n')
                
                # Sort by stars
                top_repos = sorted(self.repositories, key=lambda x: x.get('stars', 0), reverse=True)[:10]
                for repo in top_repos:
                    f.write(f"| [{repo['name']}]({repo['url']}) | {repo.get('stars', 0)} | {repo.get('forks', 0)} | {repo.get('language', 'N/A')} | {repo.get('description', 'N/A')[:50]}... |\n")
                f.write('\n')

def run(args, config, logger):
    """Main function to run GitHub reconnaissance"""
    logger.log('INFO', 'Starting GitHub reconnaissance module')
    
    # Initialize GitHub recon
    github_recon = GitHubRecon(args, config, logger)
    
    # Get targets
    targets = args.targets if hasattr(args, 'targets') and args.targets else []
    
    if not targets:
        logger.log('ERROR', 'No targets provided for GitHub reconnaissance')
        return
    
    # Process each target
    for target in targets:
        logger.log('INFO', f'Processing target: {target}')
        
        # Search for repositories
        repositories = github_recon.search_repositories(target)
        github_recon.repositories.extend(repositories)
        
        # Get organization info if it looks like an org
        if '/' not in target and len(target) > 0:
            org_info = github_recon.get_organization_info(target)
            if org_info:
                github_recon.organizations.append(org_info)
        
        # Get user info if it looks like a user
        if '/' not in target and len(target) > 0:
            user_info = github_recon.get_user_info(target)
            if user_info:
                github_recon.users.append(user_info)
        
        # Clone and analyze repositories (limit to top 10 to avoid rate limits)
        top_repos = sorted(repositories, key=lambda x: x.get('stars', 0), reverse=True)[:10]
        
        for repo in top_repos:
            repo_name = repo['name']
            clone_url = repo['clone_url']
            
            # Clone repository
            repo_path = github_recon.clone_repository(clone_url, repo_name)
            if not repo_path:
                continue
            
            # Scan for secrets
            trufflehog_secrets = github_recon.scan_with_trufflehog(repo_path)
            gitleaks_secrets = github_recon.scan_with_gitleaks(repo_path)
            custom_secrets = github_recon.scan_with_custom_patterns(repo_path)
            
            github_recon.secrets_found.extend(trufflehog_secrets)
            github_recon.secrets_found.extend(gitleaks_secrets)
            github_recon.secrets_found.extend(custom_secrets)
            
            # Analyze repository content
            content_analysis = github_recon.analyze_repository_content(repo_path)
            
            # Get commit history
            commit_history = github_recon.get_commit_history(repo_path)
            
            # Search issues and PRs
            issues_prs = github_recon.search_issues_and_prs(repo_name)
            
            # Store useful data
            useful_data = {
                'repository': repo_name,
                'content_analysis': content_analysis,
                'commit_history': commit_history,
                'issues_and_prs': issues_prs
            }
            github_recon.useful_data.append(useful_data)
            
            # Clean up cloned repository to save space
            try:
                shutil.rmtree(repo_path)
            except Exception as e:
                logger.log('WARN', f'Could not clean up {repo_path}: {e}')
    
    # Save all results
    github_recon.save_results()
    
    logger.log('SUCCESS', 'GitHub reconnaissance completed successfully')
