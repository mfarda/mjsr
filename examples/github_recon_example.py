#!/usr/bin/env python3
"""
Example script demonstrating how to use the GitHub reconnaissance module
"""

import sys
import os
from pathlib import Path

# Add the parent directory to the path so we can import mjsrecon
sys.path.insert(0, str(Path(__file__).parent.parent))

from mjsrecon.github_recon import GitHubRecon
from mjsrecon.utils import CONFIG
from mjsrecon.logger import Logger

def main():
    """Example usage of the GitHub reconnaissance module"""
    
    # Example targets (organizations, users, or keywords)
    targets = [
        "example-org",      # GitHub organization
        "example-user",     # GitHub user
        "example-project"   # Keyword search
    ]
    
    # Setup
    output_dir = "./github_recon_example_output"
    log_file = Path(output_dir) / "github_recon.log"
    
    # Create a simple args object
    class Args:
        def __init__(self):
            self.output = output_dir
            self.targets = targets
            self.github_token = os.getenv('GITHUB_TOKEN')
            self.github_max_repos = 5  # Limit to 5 repos per target
            self.github_scan_tools = 'all'
            self.github_skip_clone = False
    
    args = Args()
    
    # Setup logger
    logger = Logger(log_file)
    
    # Initialize GitHub reconnaissance
    github_recon = GitHubRecon(args, CONFIG, logger)
    
    print("🔍 Starting GitHub reconnaissance example...")
    print(f"Targets: {', '.join(targets)}")
    print(f"Output directory: {output_dir}")
    print()
    
    # Process each target
    for target in targets:
        print(f"📋 Processing target: {target}")
        
        # Search for repositories
        repositories = github_recon.search_repositories(target)
        github_recon.repositories.extend(repositories)
        
        print(f"   Found {len(repositories)} repositories")
        
        # Get organization info if it looks like an org
        if '/' not in target and len(target) > 0:
            org_info = github_recon.get_organization_info(target)
            if org_info:
                github_recon.organizations.append(org_info)
                print(f"   Organization info: {org_info.get('name', target)}")
        
        # Get user info if it looks like a user
        if '/' not in target and len(target) > 0:
            user_info = github_recon.get_user_info(target)
            if user_info:
                github_recon.users.append(user_info)
                print(f"   User info: {user_info.get('username', target)}")
        
        # Clone and analyze top repositories (limit to avoid rate limits)
        top_repos = sorted(repositories, key=lambda x: x.get('stars', 0), reverse=True)[:3]
        
        for repo in top_repos:
            repo_name = repo['name']
            clone_url = repo['clone_url']
            
            print(f"   🔍 Analyzing repository: {repo_name}")
            
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
            
            print(f"      Found {len(trufflehog_secrets)} secrets with TruffleHog")
            print(f"      Found {len(gitleaks_secrets)} secrets with GitLeaks")
            print(f"      Found {len(custom_secrets)} secrets with custom patterns")
            
            # Analyze repository content
            content_analysis = github_recon.analyze_repository_content(repo_path)
            
            # Get commit history
            commit_history = github_recon.get_commit_history(repo_path, max_commits=10)
            
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
            
            print(f"      Repository analysis complete")
            
            # Clean up cloned repository to save space
            try:
                import shutil
                shutil.rmtree(repo_path)
                print(f"      Cleaned up cloned repository")
            except Exception as e:
                print(f"      Warning: Could not clean up {repo_path}: {e}")
        
        print()
    
    # Save all results
    github_recon.save_results()
    
    print("✅ GitHub reconnaissance completed!")
    print(f"📊 Summary:")
    print(f"   - Total repositories found: {len(github_recon.repositories)}")
    print(f"   - Total secrets found: {len(github_recon.secrets_found)}")
    print(f"   - Organizations analyzed: {len(github_recon.organizations)}")
    print(f"   - Users analyzed: {len(github_recon.users)}")
    print(f"📁 Results saved to: {output_dir}")
    print(f"📄 Summary report: {output_dir}/github_recon/summary_report.md")

if __name__ == "__main__":
    main() 