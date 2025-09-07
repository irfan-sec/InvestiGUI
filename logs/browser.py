"""
Browser log parsing module
"""

import os
import json
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse
import tempfile
import shutil


class BrowserLogParser:
    """Class for parsing browser-related logs and history."""
    
    def __init__(self):
        self.browser_paths = {
            'chrome': {
                'windows': r'%LOCALAPPDATA%\Google\Chrome\User Data\Default',
                'linux': '~/.config/google-chrome/Default',
                'macos': '~/Library/Application Support/Google/Chrome/Default'
            },
            'firefox': {
                'windows': r'%APPDATA%\Mozilla\Firefox\Profiles',
                'linux': '~/.mozilla/firefox',
                'macos': '~/Library/Application Support/Firefox/Profiles'
            },
            'edge': {
                'windows': r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default',
                'linux': '~/.config/microsoft-edge/Default',
                'macos': '~/Library/Application Support/Microsoft Edge/Default'
            }
        }
        
    def parse_log(self, log_path, filters=None):
        """Parse browser log or database file.
        
        Args:
            log_path: Path to browser log, database, or directory
            filters: Dictionary with filtering options
            
        Returns:
            List of parsed browser events
        """
        events = []
        
        try:
            if not os.path.exists(log_path):
                print(f"Browser log path not found: {log_path}")
                return events
                
            if os.path.isfile(log_path):
                events.extend(self._parse_browser_file(log_path, filters))
            elif os.path.isdir(log_path):
                events.extend(self._parse_browser_directory(log_path, filters))
                
        except Exception as e:
            print(f"Error parsing browser logs from {log_path}: {e}")
            
        return events
        
    def _parse_browser_directory(self, directory, filters):
        """Parse browser data from a directory."""
        events = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                events.extend(self._parse_browser_file(file_path, filters))
                
        return events
        
    def _parse_browser_file(self, file_path, filters):
        """Parse individual browser file."""
        events = []
        
        try:
            filename = os.path.basename(file_path).lower()
            
            # Chrome/Edge history database
            if filename in ['history', 'history.db']:
                events.extend(self._parse_chrome_history_log(file_path, filters))
                
            # Chrome/Edge downloads
            elif filename == 'downloads':
                events.extend(self._parse_chrome_downloads(file_path, filters))
                
            # Chrome/Edge login data
            elif filename == 'login data':
                events.extend(self._parse_chrome_login_data(file_path, filters))
                
            # Firefox places database
            elif filename == 'places.sqlite':
                events.extend(self._parse_firefox_places_log(file_path, filters))
                
            # Browser console logs
            elif filename.endswith('.log') and any(browser in file_path.lower() 
                                                 for browser in ['chrome', 'firefox', 'edge']):
                events.extend(self._parse_browser_console_log(file_path, filters))
                
            # Browser crash logs
            elif 'crash' in filename.lower() and filename.endswith('.dmp'):
                events.extend(self._parse_browser_crash_log(file_path, filters))
                
        except Exception as e:
            print(f"Error parsing browser file {file_path}: {e}")
            
        return events
        
    def _parse_chrome_history_log(self, db_path, filters):
        """Parse Chrome history database as log events."""
        events = []
        
        try:
            # Create temporary copy to avoid locking
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_file:
                shutil.copy2(db_path, temp_file.name)
                temp_db_path = temp_file.name
                
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            # Query for visits with detailed information
            query = """
            SELECT urls.url, urls.title, urls.visit_count, urls.typed_count,
                   visits.visit_time, visits.visit_duration, visits.transition,
                   urls.last_visit_time
            FROM urls 
            LEFT JOIN visits ON urls.id = visits.url
            ORDER BY visits.visit_time DESC
            LIMIT 1000
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for row in rows:
                url, title, visit_count, typed_count, visit_time, duration, transition, last_visit = row
                
                # Convert Chrome timestamp to datetime
                if visit_time:
                    timestamp = self._chrome_timestamp_to_datetime(visit_time)
                elif last_visit:
                    timestamp = self._chrome_timestamp_to_datetime(last_visit)
                else:
                    timestamp = datetime.now()
                    
                # Apply date filters
                if self._passes_date_filter(timestamp, filters):
                    domain = urlparse(url).netloc if url else "Unknown"
                    
                    # Determine event type based on transition
                    transition_types = {
                        0: 'Link Click',
                        1: 'Typed URL', 
                        2: 'Auto Bookmark',
                        3: 'Auto Subframe',
                        4: 'Manual Subframe',
                        5: 'Generated',
                        6: 'Start Page',
                        7: 'Form Submit',
                        8: 'Reload'
                    }
                    
                    transition_type = transition_types.get(transition or 0, 'Unknown')
                    
                    event = {
                        'type': 'Browser Navigation',
                        'timestamp': timestamp.isoformat() if hasattr(timestamp, 'isoformat') else str(timestamp),
                        'level': 'INFO',
                        'source': f'Chrome History - {os.path.basename(db_path)}',
                        'event_id': f'nav_{visit_time or last_visit}',
                        'message': f'Navigated to {title or url}',
                        'url': url,
                        'title': title,
                        'domain': domain,
                        'visit_count': visit_count,
                        'typed_count': typed_count,
                        'transition': transition_type,
                        'duration': duration or 0,
                        'description': f'Visited: {title or domain}',
                        'details': f'URL: {url}, Visits: {visit_count}, Typed: {typed_count}, Transition: {transition_type}, Duration: {duration or 0}ms'
                    }
                    
                    events.append(event)
                    
            conn.close()
            os.unlink(temp_db_path)
            
        except Exception as e:
            print(f"Error parsing Chrome history log {db_path}: {e}")
            
        return events
        
    def _parse_chrome_downloads(self, db_path, filters):
        """Parse Chrome downloads database."""
        events = []
        
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_file:
                shutil.copy2(db_path, temp_file.name)
                temp_db_path = temp_file.name
                
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            query = """
            SELECT url, target_path, start_time, end_time, received_bytes, 
                   total_bytes, state, danger_type, interrupt_reason
            FROM downloads 
            ORDER BY start_time DESC
            LIMIT 500
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for row in rows:
                url, target_path, start_time, end_time, received_bytes, total_bytes, state, danger_type, interrupt_reason = row
                
                start_timestamp = self._chrome_timestamp_to_datetime(start_time) if start_time else datetime.now()
                
                if self._passes_date_filter(start_timestamp, filters):
                    # Determine download status
                    status_map = {0: 'In Progress', 1: 'Complete', 2: 'Cancelled', 3: 'Interrupted'}
                    status = status_map.get(state, 'Unknown')
                    
                    level = 'WARNING' if danger_type > 0 or interrupt_reason > 0 else 'INFO'
                    
                    event = {
                        'type': 'Browser Download',
                        'timestamp': start_timestamp.isoformat() if hasattr(start_timestamp, 'isoformat') else str(start_timestamp),
                        'level': level,
                        'source': f'Chrome Downloads - {os.path.basename(db_path)}',
                        'event_id': f'download_{start_time}',
                        'message': f'Downloaded {os.path.basename(target_path or url)}',
                        'url': url,
                        'target_path': target_path,
                        'status': status,
                        'received_bytes': received_bytes or 0,
                        'total_bytes': total_bytes or 0,
                        'danger_type': danger_type,
                        'interrupt_reason': interrupt_reason,
                        'description': f'Download: {os.path.basename(target_path or url)}',
                        'details': f'URL: {url}, Path: {target_path}, Status: {status}, Size: {received_bytes}/{total_bytes} bytes'
                    }
                    
                    events.append(event)
                    
            conn.close()
            os.unlink(temp_db_path)
            
        except Exception as e:
            print(f"Error parsing Chrome downloads {db_path}: {e}")
            
        return events
        
    def _parse_firefox_places_log(self, db_path, filters):
        """Parse Firefox places database as log events.""" 
        events = []
        
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_file:
                shutil.copy2(db_path, temp_file.name)
                temp_db_path = temp_file.name
                
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            query = """
            SELECT moz_places.url, moz_places.title, moz_places.visit_count,
                   moz_historyvisits.visit_date, moz_historyvisits.visit_type
            FROM moz_places
            LEFT JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
            ORDER BY moz_historyvisits.visit_date DESC
            LIMIT 1000
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            for row in rows:
                url, title, visit_count, visit_date, visit_type = row
                
                # Convert Firefox timestamp (microseconds since epoch)
                if visit_date:
                    timestamp = datetime.fromtimestamp(visit_date / 1000000, tz=timezone.utc)
                else:
                    timestamp = datetime.now()
                    
                if self._passes_date_filter(timestamp, filters):
                    domain = urlparse(url).netloc if url else "Unknown"
                    
                    # Firefox visit types
                    visit_types = {
                        1: 'Link',
                        2: 'Typed',
                        3: 'Bookmark',
                        4: 'Embed',
                        5: 'Redirect Permanent',
                        6: 'Redirect Temporary',
                        7: 'Download',
                        8: 'Framed Link'
                    }
                    
                    visit_type_name = visit_types.get(visit_type or 1, 'Unknown')
                    
                    event = {
                        'type': 'Browser Navigation',
                        'timestamp': timestamp.isoformat(),
                        'level': 'INFO',
                        'source': f'Firefox History - {os.path.basename(db_path)}',
                        'event_id': f'nav_ff_{visit_date}',
                        'message': f'Navigated to {title or url}',
                        'url': url,
                        'title': title,
                        'domain': domain,
                        'visit_count': visit_count,
                        'visit_type': visit_type_name,
                        'description': f'Visited: {title or domain}',
                        'details': f'URL: {url}, Visits: {visit_count}, Type: {visit_type_name}'
                    }
                    
                    events.append(event)
                    
            conn.close()
            os.unlink(temp_db_path)
            
        except Exception as e:
            print(f"Error parsing Firefox places log {db_path}: {e}")
            
        return events
        
    def _parse_browser_console_log(self, log_path, filters):
        """Parse browser console log files."""
        events = []
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                        
                    # Try to parse console log format
                    # Example: [1234:5678:0101/123045.123:INFO:console.cc(123)] "Console message"
                    import re
                    console_pattern = r'^\[(\d+):(\d+):(\d+)/(\d+)\.(\d+):(\w+):([^\]]+)\] (.*)$'
                    match = re.match(console_pattern, line)
                    
                    if match:
                        pid, tid, date, time, ms, level, source, message = match.groups()
                        
                        # Parse timestamp
                        timestamp = datetime.now()  # Simplified - would parse from date/time in real implementation
                        
                        if self._passes_date_filter(timestamp, filters):
                            event = {
                                'type': 'Browser Console',
                                'timestamp': timestamp.isoformat(),
                                'level': level.upper() if level.upper() in ['INFO', 'WARNING', 'ERROR', 'DEBUG'] else 'INFO',
                                'source': f'Browser Console - {os.path.basename(log_path)}',
                                'event_id': f'console_{line_num}',
                                'message': message.strip('"'),
                                'process_id': pid,
                                'thread_id': tid,
                                'source_file': source,
                                'description': f'Console: {message.strip('"')[:50]}...' if len(message) > 50 else f'Console: {message.strip('"')}',
                                'details': f'PID: {pid}, TID: {tid}, Source: {source}, Level: {level}'
                            }
                            
                            events.append(event)
                    else:
                        # Generic log entry
                        if self._passes_date_filter(datetime.now(), filters):
                            event = {
                                'type': 'Browser Log',
                                'timestamp': datetime.now().isoformat(),
                                'level': 'INFO',
                                'source': f'Browser Log - {os.path.basename(log_path)}',
                                'event_id': f'log_{line_num}',
                                'message': line,
                                'description': f'Log: {line[:50]}...' if len(line) > 50 else line,
                                'details': f'Line: {line_num}, Raw: {line}'
                            }
                            
                            events.append(event)
                            
        except Exception as e:
            print(f"Error parsing browser console log {log_path}: {e}")
            
        return events
        
    def _parse_browser_crash_log(self, crash_path, filters):
        """Parse browser crash dump information."""
        events = []
        
        try:
            # For demonstration, create sample crash event
            # Real implementation would parse minidump files
            
            mod_time = datetime.fromtimestamp(os.path.getmtime(crash_path))
            
            if self._passes_date_filter(mod_time, filters):
                event = {
                    'type': 'Browser Crash',
                    'timestamp': mod_time.isoformat(),
                    'level': 'ERROR',
                    'source': f'Browser Crash - {os.path.basename(crash_path)}',
                    'event_id': f'crash_{int(mod_time.timestamp())}',
                    'message': f'Browser crashed: {os.path.basename(crash_path)}',
                    'crash_file': crash_path,
                    'file_size': os.path.getsize(crash_path),
                    'description': f'Crash: {os.path.basename(crash_path)}',
                    'details': f'Crash file: {crash_path}, Size: {os.path.getsize(crash_path)} bytes, Time: {mod_time.isoformat()}'
                }
                
                events.append(event)
                
        except Exception as e:
            print(f"Error parsing browser crash log {crash_path}: {e}")
            
        return events
        
    def _chrome_timestamp_to_datetime(self, timestamp):
        """Convert Chrome timestamp to datetime."""
        try:
            # Chrome timestamps are microseconds since January 1, 1601
            unix_timestamp = (timestamp / 1000000) - 11644473600
            return datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
        except (ValueError, OSError):
            return datetime.now()
            
    def _passes_date_filter(self, timestamp, filters):
        """Check if timestamp passes date filters."""
        if not filters or ('start_date' not in filters and 'end_date' not in filters):
            return True
            
        try:
            if hasattr(timestamp, 'replace'):
                # timestamp is datetime object
                event_time = timestamp
            else:
                # timestamp is string
                event_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                
            if 'start_date' in filters and 'end_date' in filters:
                return filters['start_date'] <= event_time <= filters['end_date']
                
        except Exception:
            pass
            
        return True