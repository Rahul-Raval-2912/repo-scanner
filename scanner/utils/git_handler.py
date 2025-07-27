import os
import tempfile
import shutil
from git import Repo, GitCommandError
from typing import Optional, Tuple, List, Dict
from datetime import datetime

class GitHandler:
    def __init__(self):
        self.temp_dirs = []
    
    def clone_repository(self, repo_url: str, deep_scan: bool = False) -> Tuple[Optional[str], Optional[str]]:
        """
        Clone a Git repository to a temporary directory.
        Returns (temp_dir_path, error_message)
        """
        try:
            # Create temporary directory
            temp_dir = tempfile.mkdtemp(prefix='repoguardian_')
            self.temp_dirs.append(temp_dir)
            
            # Clone the repository (full history for deep scan)
            if deep_scan:
                Repo.clone_from(repo_url, temp_dir)
            else:
                Repo.clone_from(repo_url, temp_dir, depth=1)
            
            return temp_dir, None
            
        except GitCommandError as e:
            error_msg = f"Git clone failed: {str(e)}"
            return None, error_msg
        except Exception as e:
            error_msg = f"Unexpected error during clone: {str(e)}"
            return None, error_msg
    
    def cleanup_temp_dirs(self):
        """Clean up all temporary directories created by this handler."""
        for temp_dir in self.temp_dirs:
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except Exception as e:
                print(f"Error cleaning up {temp_dir}: {e}")
        
        self.temp_dirs.clear()
    
    def get_commit_history(self, repo_path: str, max_commits: int = 100) -> List[Dict]:
        """
        Get commit history for deep scanning.
        Returns list of commit information.
        """
        try:
            repo = Repo(repo_path)
            commits = []
            
            for i, commit in enumerate(repo.iter_commits()):
                if i >= max_commits:
                    break
                    
                commits.append({
                    'hash': commit.hexsha,
                    'message': commit.message.strip(),
                    'author': str(commit.author),
                    'date': datetime.fromtimestamp(commit.committed_date),
                    'files': list(commit.stats.files.keys())
                })
            
            return commits
            
        except Exception as e:
            print(f"Error getting commit history: {e}")
            return []
    
    def checkout_commit(self, repo_path: str, commit_hash: str) -> bool:
        """
        Checkout a specific commit.
        Returns True if successful, False otherwise.
        """
        try:
            repo = Repo(repo_path)
            repo.git.checkout(commit_hash)
            return True
        except Exception as e:
            print(f"Error checking out commit {commit_hash}: {e}")
            return False
    
    def __del__(self):
        """Cleanup when the object is destroyed."""
        self.cleanup_temp_dirs()
