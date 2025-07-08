import os
import tempfile
import zipfile
import shutil
from typing import Optional, Tuple

class ZipHandler:
    def __init__(self):
        self.temp_dirs = []
    
    def extract_zip(self, zip_file_path: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract a ZIP file to a temporary directory.
        Returns (temp_dir_path, error_message)
        """
        try:
            # Create temporary directory
            temp_dir = tempfile.mkdtemp(prefix='repoguardian_zip_')
            self.temp_dirs.append(temp_dir)
            
            # Extract the ZIP file
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                # Security check: prevent zip bombs and path traversal
                self._validate_zip_file(zip_ref)
                zip_ref.extractall(temp_dir)
            
            return temp_dir, None
            
        except zipfile.BadZipFile:
            error_msg = "Invalid ZIP file format"
            return None, error_msg
        except Exception as e:
            error_msg = f"Error extracting ZIP file: {str(e)}"
            return None, error_msg
    
    def _validate_zip_file(self, zip_ref: zipfile.ZipFile):
        """Validate ZIP file for security issues."""
        total_size = 0
        max_size = 500 * 1024 * 1024  # 500MB limit
        
        for file_info in zip_ref.infolist():
            # Check for path traversal
            if '..' in file_info.filename or file_info.filename.startswith('/'):
                raise ValueError(f"Unsafe path in ZIP: {file_info.filename}")
            
            # Check total uncompressed size
            total_size += file_info.file_size
            if total_size > max_size:
                raise ValueError("ZIP file too large when uncompressed")
    
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
