"""
Browser artifacts extraction module
"""

import os
import sqlite3
import json
from datetime import datetime, timezone
from urllib.parse import urlparse


class BrowserArtifacts:
    """Class for extracting browser-related artifacts."""
    
    def __init__(self):
        self.supported_browsers = ['chrome', 'firefox', 'edge', 'safari']
        
    def extract_history(self, source_path):
        """Extract browser history from various sources.
        
        Args:
            source_path: Path to disk image, directory, or browser profile
            
        Returns:
            List of browser history artifacts
        """
        artifacts = []
        
        try:
            if os.path.isfile(source_path):
                # Single file - might be a database
                artifacts.extend(self._extract_from_file(source_path))
            elif os.path.isdir(source_path):
                # Directory - search for browser data
                artifacts.extend(self._extract_from_directory(source_path))
            else:
                print(f"Invalid source path: {source_path}")
                
        except Exception as e:
            print(f"Error extracting browser history: {e}")
            
        return artifacts
        
    def _extract_from_directory(self, directory):
        """Extract browser history from directory structure."""
        artifacts = []
        
        # Search for common browser database files
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Chrome/Chromium history
                if file.lower() == 'history' or file.lower() == 'history.db':
                    artifacts.extend(self._extract_chrome_history(file_path))
                    
                # Firefox places database
                elif file.lower() == 'places.sqlite':
                    artifacts.extend(self._extract_firefox_history(file_path))
                    
                # Edge history
                elif 'webdata' in file.lower() or 'history' in file.lower():
                    artifacts.extend(self._extract_chrome_history(file_path))  # Edge uses Chromium
                    
        return artifacts
        
    def _extract_from_file(self, file_path):
        """Extract history from a single database file."""
        artifacts = []
        
        try:
            # Try as Chrome/Edge history database
            artifacts.extend(self._extract_chrome_history(file_path))
            
            # If that fails, try Firefox
            if not artifacts:
                artifacts.extend(self._extract_firefox_history(file_path))
                
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")
            
        return artifacts
        
    def _extract_chrome_history(self, db_path):
        """Extract history from Chrome/Chromium/Edge database."""
        artifacts = []
        
        try:
            # Create a copy to work with (avoid locking issues)
            import shutil
            import tempfile
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_file:
                shutil.copy2(db_path, temp_file.name)
                temp_db_path = temp_file.name
                
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            # Query for URLs and visits
            query = """
            SELECT urls.url, urls.title, urls.visit_count, urls.last_visit_time,
                   visits.visit_time, visits.visit_duration
            FROM urls 
            LEFT JOIN visits ON urls.id = visits.url
            ORDER BY urls.last_visit_time DESC
            LIMIT 1000
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for row in rows:
                url, title, visit_count, last_visit_time, visit_time, duration = row
                
                # Convert Chrome timestamp (microseconds since 1601) to datetime
                if visit_time:
                    timestamp = self._chrome_timestamp_to_datetime(visit_time)
                elif last_visit_time:
                    timestamp = self._chrome_timestamp_to_datetime(last_visit_time)
                else:
                    timestamp = "Unknown"
                    
                domain = urlparse(url).netloc if url else "Unknown"
                
                artifact = {
                    'type': 'Browser History',
                    'timestamp': timestamp.isoformat() if hasattr(timestamp, 'isoformat') else str(timestamp),
                    'source': f'Chrome/Edge - {os.path.basename(db_path)}',
                    'description': f'Visited: {title or url}',
                    'details': f'URL: {url}, Domain: {domain}, Visits: {visit_count}, Duration: {duration or 0}ms',
                    'url': url,
                    'title': title,
                    'domain': domain,
                    'visit_count': visit_count
                }
                
                artifacts.append(artifact)
                
            conn.close()
            os.unlink(temp_db_path)  # Clean up temp file
            
        except Exception as e:
            print(f"Error extracting Chrome history from {db_path}: {e}")
            
        return artifacts
        
    def _extract_firefox_history(self, db_path):
        """Extract history from Firefox places.sqlite database."""
        artifacts = []
        
        try:
            # Create a copy to work with
            import shutil
            import tempfile
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_file:
                shutil.copy2(db_path, temp_file.name)
                temp_db_path = temp_file.name
                
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            # Query for URLs and visits
            query = """
            SELECT moz_places.url, moz_places.title, moz_places.visit_count,
                   moz_places.last_visit_date, moz_historyvisits.visit_date
            FROM moz_places 
            LEFT JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
            ORDER BY moz_places.last_visit_date DESC
            LIMIT 1000
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for row in rows:
                url, title, visit_count, last_visit_date, visit_date = row
                
                # Convert Firefox timestamp (microseconds since 1970) to datetime
                if visit_date:
                    timestamp = datetime.fromtimestamp(visit_date / 1000000, tz=timezone.utc)
                elif last_visit_date:
                    timestamp = datetime.fromtimestamp(last_visit_date / 1000000, tz=timezone.utc)
                else:
                    timestamp = "Unknown"
                    
                domain = urlparse(url).netloc if url else "Unknown"
                
                artifact = {
                    'type': 'Browser History',
                    'timestamp': timestamp.isoformat() if hasattr(timestamp, 'isoformat') else str(timestamp),
                    'source': f'Firefox - {os.path.basename(db_path)}',
                    'description': f'Visited: {title or url}',
                    'details': f'URL: {url}, Domain: {domain}, Visits: {visit_count}',
                    'url': url,
                    'title': title,
                    'domain': domain,
                    'visit_count': visit_count
                }
                
                artifacts.append(artifact)
                
            conn.close()
            os.unlink(temp_db_path)  # Clean up temp file
            
        except Exception as e:
            print(f"Error extracting Firefox history from {db_path}: {e}")
            
        return artifacts
        
    def _chrome_timestamp_to_datetime(self, timestamp):
        """Convert Chrome timestamp to datetime object.
        
        Chrome stores timestamps as microseconds since January 1, 1601.
        """
        try:
            # Chrome epoch starts at 1601-01-01, Unix epoch at 1970-01-01
            # Difference is 11644473600 seconds
            unix_timestamp = (timestamp / 1000000) - 11644473600
            return datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
        except (ValueError, OSError):
            return "Invalid timestamp"
            
    def extract_bookmarks(self, source_path):
        """Extract browser bookmarks."""
        artifacts = []
        
        try:
            if os.path.isdir(source_path):
                # Search for bookmark files
                for root, dirs, files in os.walk(source_path):
                    for file in files:
                        if file.lower() == 'bookmarks':
                            file_path = os.path.join(root, file)
                            artifacts.extend(self._extract_chrome_bookmarks(file_path))
                            
        except Exception as e:
            print(f"Error extracting bookmarks: {e}")
            
        return artifacts
        
    def _extract_chrome_bookmarks(self, bookmarks_path):
        """Extract Chrome bookmarks from JSON file."""
        artifacts = []
        
        try:
            with open(bookmarks_path, 'r', encoding='utf-8') as f:
                bookmarks_data = json.load(f)
                
            # Recursively extract bookmarks
            def extract_bookmark_folder(folder, folder_name=""):
                for item in folder.get('children', []):
                    if item.get('type') == 'url':
                        artifact = {
                            'type': 'Browser Bookmark',
                            'timestamp': datetime.now().isoformat(),  # Bookmarks don't have timestamps
                            'source': f'Chrome Bookmarks - {os.path.basename(bookmarks_path)}',
                            'description': f'Bookmarked: {item.get("name", "Unnamed")}',
                            'details': f'URL: {item.get("url", "")}, Folder: {folder_name}',
                            'url': item.get('url', ''),
                            'title': item.get('name', ''),
                            'folder': folder_name
                        }
                        artifacts.append(artifact)
                    elif item.get('type') == 'folder':
                        extract_bookmark_folder(item, item.get('name', 'Unnamed Folder'))
                        
            # Extract from bookmark bar and other folders
            roots = bookmarks_data.get('roots', {})
            if 'bookmark_bar' in roots:
                extract_bookmark_folder(roots['bookmark_bar'], 'Bookmark Bar')
            if 'other' in roots:
                extract_bookmark_folder(roots['other'], 'Other Bookmarks')
                
        except Exception as e:
            print(f"Error extracting Chrome bookmarks from {bookmarks_path}: {e}")
            
        return artifacts