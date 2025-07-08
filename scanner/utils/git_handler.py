import os
import tempfile
import shutil
from git import Repo, GitCommandError
from typing import Optional, Tuple

class GitHandler:
    def __init__(self):
        self.temp_dirs = []
    
    def clone_repository(self, repo_url: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Clone a Git repository to a temporary directory.
        Returns (temp_dir_path, error_message)
        """
        try:
            # Create temporary directory
            temp_dir = tempfile.mkdtemp(prefix='repoguardian_')
            self.temp_dirs.append(temp_dir)
            
            # Clone the repository
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
    
    def __del__(self):
        """Cleanup when the object is destroyed."""
        self.cleanup_temp_dirs()
