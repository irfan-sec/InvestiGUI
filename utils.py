"""
Utility functions for InvestiGUI
"""

import os
import hashlib
import json
from datetime import datetime, timedelta
import tempfile
import shutil


def calculate_file_hash(file_path, algorithm='sha256'):
    """Calculate hash of a file.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use ('md5', 'sha1', 'sha256')
        
    Returns:
        Hex digest of the file hash
    """
    try:
        hasher = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
                
        return hasher.hexdigest()
        
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {e}")
        return None


def format_file_size(size_bytes):
    """Format file size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    if size_bytes == 0:
        return "0 B"
        
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = int(size_bytes.bit_length() / 10) if size_bytes > 0 else 0
    i = min(i, len(size_names) - 1)
    
    return f"{size_bytes / (1024 ** i):.1f} {size_names[i]}"


def format_timestamp(timestamp_str, output_format='%Y-%m-%d %H:%M:%S'):
    """Format timestamp string to specified format.
    
    Args:
        timestamp_str: Input timestamp string
        output_format: Output format string
        
    Returns:
        Formatted timestamp string
    """
    try:
        # Try parsing ISO format first
        if 'T' in timestamp_str:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        else:
            # Try other common formats
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%m/%d/%Y %H:%M:%S',
                '%d/%m/%Y %H:%M:%S',
                '%Y-%m-%d',
                '%m/%d/%Y',
                '%d/%m/%Y'
            ]
            
            dt = None
            for fmt in formats:
                try:
                    dt = datetime.strptime(timestamp_str, fmt)
                    break
                except ValueError:
                    continue
                    
            if dt is None:
                return timestamp_str  # Return original if parsing fails
                
        return dt.strftime(output_format)
        
    except Exception as e:
        print(f"Error formatting timestamp '{timestamp_str}': {e}")
        return timestamp_str


def safe_create_directory(directory_path):
    """Safely create directory if it doesn't exist.
    
    Args:
        directory_path: Path to directory to create
        
    Returns:
        True if successful, False otherwise
    """
    try:
        os.makedirs(directory_path, exist_ok=True)
        return True
    except Exception as e:
        print(f"Error creating directory {directory_path}: {e}")
        return False


def safe_copy_file(source_path, destination_path):
    """Safely copy a file with error handling.
    
    Args:
        source_path: Source file path
        destination_path: Destination file path
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Create destination directory if needed
        dest_dir = os.path.dirname(destination_path)
        if dest_dir:
            safe_create_directory(dest_dir)
            
        shutil.copy2(source_path, destination_path)
        return True
        
    except Exception as e:
        print(f"Error copying file from {source_path} to {destination_path}: {e}")
        return False


def create_temp_copy(file_path):
    """Create a temporary copy of a file.
    
    Args:
        file_path: Path to source file
        
    Returns:
        Path to temporary copy, or None if failed
    """
    try:
        # Create temporary file with same extension
        _, ext = os.path.splitext(file_path)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as temp_file:
            shutil.copy2(file_path, temp_file.name)
            return temp_file.name
            
    except Exception as e:
        print(f"Error creating temp copy of {file_path}: {e}")
        return None


def cleanup_temp_file(temp_path):
    """Clean up temporary file.
    
    Args:
        temp_path: Path to temporary file
    """
    try:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
    except Exception as e:
        print(f"Error cleaning up temp file {temp_path}: {e}")


def validate_file_path(file_path, must_exist=True, extensions=None):
    """Validate file path.
    
    Args:
        file_path: Path to validate
        must_exist: Whether file must exist
        extensions: List of allowed extensions (e.g., ['.txt', '.log'])
        
    Returns:
        True if valid, False otherwise
    """
    try:
        if not file_path:
            return False
            
        if must_exist and not os.path.exists(file_path):
            return False
            
        if extensions:
            _, ext = os.path.splitext(file_path.lower())
            if ext not in [e.lower() for e in extensions]:
                return False
                
        return True
        
    except Exception as e:
        print(f"Error validating file path {file_path}: {e}")
        return False


def parse_size_string(size_str):
    """Parse size string (e.g., '1.5 GB') to bytes.
    
    Args:
        size_str: Size string to parse
        
    Returns:
        Size in bytes, or None if parsing fails
    """
    try:
        size_str = size_str.strip().upper()
        
        # Size multipliers
        multipliers = {
            'B': 1,
            'KB': 1024,
            'MB': 1024 ** 2,
            'GB': 1024 ** 3,
            'TB': 1024 ** 4
        }
        
        # Extract number and unit
        parts = size_str.split()
        if len(parts) != 2:
            return None
            
        number, unit = parts
        if unit not in multipliers:
            return None
            
        return int(float(number) * multipliers[unit])
        
    except Exception as e:
        print(f"Error parsing size string '{size_str}': {e}")
        return None


def sanitize_filename(filename):
    """Sanitize filename for safe filesystem usage.
    
    Args:
        filename: Filename to sanitize
        
    Returns:
        Sanitized filename
    """
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    
    for char in invalid_chars:
        filename = filename.replace(char, '_')
        
    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')
    
    # Ensure filename is not empty
    if not filename:
        filename = 'unknown'
        
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        max_name_len = 255 - len(ext)
        filename = name[:max_name_len] + ext
        
    return filename


def load_json_file(file_path):
    """Safely load JSON file.
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        Parsed JSON data, or None if failed
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON file {file_path}: {e}")
        return None


def save_json_file(data, file_path, indent=2):
    """Safely save data to JSON file.
    
    Args:
        data: Data to save
        file_path: Path to save to
        indent: JSON indentation
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Create directory if needed
        directory = os.path.dirname(file_path)
        if directory:
            safe_create_directory(directory)
            
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, default=str)
            
        return True
        
    except Exception as e:
        print(f"Error saving JSON file {file_path}: {e}")
        return False


def get_file_info(file_path):
    """Get comprehensive file information.
    
    Args:
        file_path: Path to file
        
    Returns:
        Dictionary with file information
    """
    try:
        stat = os.stat(file_path)
        
        return {
            'path': file_path,
            'name': os.path.basename(file_path),
            'size': stat.st_size,
            'size_formatted': format_file_size(stat.st_size),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
            'extension': os.path.splitext(file_path)[1].lower(),
            'is_file': os.path.isfile(file_path),
            'is_directory': os.path.isdir(file_path)
        }
        
    except Exception as e:
        print(f"Error getting file info for {file_path}: {e}")
        return None


def find_files_by_pattern(root_directory, pattern, max_results=1000):
    """Find files matching pattern.
    
    Args:
        root_directory: Root directory to search
        pattern: Filename pattern (supports wildcards)
        max_results: Maximum number of results
        
    Returns:
        List of matching file paths
    """
    import fnmatch
    
    matches = []
    
    try:
        for root, dirs, files in os.walk(root_directory):
            for filename in files:
                if fnmatch.fnmatch(filename.lower(), pattern.lower()):
                    matches.append(os.path.join(root, filename))
                    
                    if len(matches) >= max_results:
                        return matches
                        
    except Exception as e:
        print(f"Error searching for files with pattern '{pattern}' in {root_directory}: {e}")
        
    return matches


def estimate_processing_time(file_size_bytes, processing_rate_mb_per_second=10):
    """Estimate processing time for a file.
    
    Args:
        file_size_bytes: File size in bytes
        processing_rate_mb_per_second: Processing rate in MB/s
        
    Returns:
        Estimated time in seconds
    """
    try:
        size_mb = file_size_bytes / (1024 * 1024)
        return max(1, int(size_mb / processing_rate_mb_per_second))
    except:
        return 60  # Default estimate


def truncate_string(text, max_length=100, suffix='...'):
    """Truncate string to maximum length.
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        Truncated string
    """
    if not text or len(text) <= max_length:
        return text
        
    return text[:max_length - len(suffix)] + suffix


def detect_encoding(file_path):
    """Detect file encoding.
    
    Args:
        file_path: Path to file
        
    Returns:
        Detected encoding or 'utf-8' as default
    """
    try:
        import chardet
        
        with open(file_path, 'rb') as f:
            raw_data = f.read(10000)  # Read first 10KB
            result = chardet.detect(raw_data)
            return result.get('encoding', 'utf-8')
            
    except ImportError:
        # chardet not available, try common encodings
        encodings = ['utf-8', 'ascii', 'latin1', 'cp1252']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    f.read(1000)  # Try reading first 1KB
                    return encoding
            except UnicodeDecodeError:
                continue
                
    except Exception as e:
        print(f"Error detecting encoding for {file_path}: {e}")
        
    return 'utf-8'  # Default fallback


def create_backup(file_path, backup_dir=None):
    """Create backup of a file.
    
    Args:
        file_path: File to backup
        backup_dir: Directory for backup (optional)
        
    Returns:
        Path to backup file, or None if failed
    """
    try:
        if not os.path.exists(file_path):
            return None
            
        # Create backup filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.basename(file_path)
        name, ext = os.path.splitext(filename)
        backup_filename = f"{name}_backup_{timestamp}{ext}"
        
        # Determine backup directory
        if backup_dir:
            safe_create_directory(backup_dir)
            backup_path = os.path.join(backup_dir, backup_filename)
        else:
            backup_path = os.path.join(os.path.dirname(file_path), backup_filename)
            
        # Copy file
        if safe_copy_file(file_path, backup_path):
            return backup_path
            
    except Exception as e:
        print(f"Error creating backup of {file_path}: {e}")
        
    return None