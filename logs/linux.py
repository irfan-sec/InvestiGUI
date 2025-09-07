"""
Linux system log parsing module
"""

import os
import re
from datetime import datetime, timezone, timedelta


class LinuxLogParser:
    """Class for parsing Linux system logs (syslog, auth.log, etc.)."""
    
    def __init__(self):
        self.log_patterns = {
            'syslog': re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)(?:\[(\d+)\])?: (.*)$'),
            'auth': re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)(?:\[(\d+)\])?: (.*)$'),
            'apache': re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\d+)'),
            'nginx': re.compile(r'^(\S+) - \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\d+)'),
            'kernel': re.compile(r'^\[(\s*\d+\.\d+)\] (.*)$')
        }
        
        self.severity_mapping = {
            'emerg': 'CRITICAL',
            'alert': 'CRITICAL', 
            'crit': 'CRITICAL',
            'err': 'ERROR',
            'error': 'ERROR',
            'warn': 'WARNING',
            'warning': 'WARNING',
            'notice': 'INFO',
            'info': 'INFO',
            'debug': 'DEBUG'
        }
        
    def parse_log(self, log_path, filters=None):
        """Parse Linux log file.
        
        Args:
            log_path: Path to log file
            filters: Dictionary with filtering options
            
        Returns:
            List of parsed log events
        """
        events = []
        
        try:
            if not os.path.exists(log_path):
                print(f"Log file not found: {log_path}")
                return events
                
            # Determine log type from filename
            log_type = self._detect_log_type(log_path)
            
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                        
                    event = self._parse_line(line, log_type, log_path, line_num)
                    if event:
                        # Apply filters
                        if self._passes_filters(event, filters):
                            events.append(event)
                            
                        # Limit number of events
                        if filters and 'max_events' in filters and len(events) >= filters['max_events']:
                            break
                            
        except Exception as e:
            print(f"Error parsing Linux log {log_path}: {e}")
            
        return events
        
    def _detect_log_type(self, log_path):
        """Detect log type from file path."""
        path_lower = log_path.lower()
        
        if 'auth' in path_lower:
            return 'auth'
        elif 'apache' in path_lower or 'httpd' in path_lower:
            return 'apache'
        elif 'nginx' in path_lower:
            return 'nginx'
        elif 'kernel' in path_lower or 'dmesg' in path_lower:
            return 'kernel'
        elif any(x in path_lower for x in ['syslog', 'messages', 'system']):
            return 'syslog'
        else:
            return 'syslog'  # Default
            
    def _parse_line(self, line, log_type, log_path, line_num):
        """Parse a single log line."""
        try:
            pattern = self.log_patterns.get(log_type, self.log_patterns['syslog'])
            match = pattern.match(line)
            
            if not match:
                # Try other patterns if primary doesn't match
                for alt_type, alt_pattern in self.log_patterns.items():
                    if alt_type != log_type:
                        alt_match = alt_pattern.match(line)
                        if alt_match:
                            match = alt_match
                            log_type = alt_type
                            break
                            
            if match:
                return self._create_event_from_match(match, log_type, log_path, line_num, line)
            else:
                # Create generic event for unmatched lines
                return self._create_generic_event(line, log_path, line_num)
                
        except Exception as e:
            print(f"Error parsing line {line_num} in {log_path}: {e}")
            return None
            
    def _create_event_from_match(self, match, log_type, log_path, line_num, original_line):
        """Create event from regex match."""
        if log_type in ['syslog', 'auth']:
            timestamp_str, hostname, process, pid, message = match.groups()
            timestamp = self._parse_syslog_timestamp(timestamp_str)
            
            # Extract severity from message
            level = self._extract_severity(message)
            
            event = {
                'type': 'Linux System Log',
                'timestamp': timestamp,
                'level': level,
                'source': f'Linux Log - {os.path.basename(log_path)}',
                'event_id': f'{log_type}_{line_num}',
                'message': message,
                'hostname': hostname,
                'process': process,
                'pid': pid,
                'log_type': log_type,
                'description': f'{process}: {message[:50]}...' if len(message) > 50 else f'{process}: {message}',
                'details': f'Host: {hostname}, Process: {process}, PID: {pid}, Type: {log_type}'
            }
            
        elif log_type in ['apache', 'nginx']:
            ip, timestamp_str, request, status, size = match.groups()
            timestamp = self._parse_web_timestamp(timestamp_str)
            
            # Determine level based on status code
            status_code = int(status)
            if status_code >= 500:
                level = 'ERROR'
            elif status_code >= 400:
                level = 'WARNING'
            else:
                level = 'INFO'
                
            event = {
                'type': 'Web Server Log',
                'timestamp': timestamp,
                'level': level,
                'source': f'{log_type.title()} Log - {os.path.basename(log_path)}',
                'event_id': f'{log_type}_{line_num}',
                'message': f'{request} -> {status}',
                'client_ip': ip,
                'request': request,
                'status_code': status,
                'response_size': size,
                'log_type': log_type,
                'description': f'Web request: {request.split()[1] if len(request.split()) > 1 else request}',
                'details': f'IP: {ip}, Status: {status}, Size: {size}, Request: {request}'
            }
            
        elif log_type == 'kernel':
            timestamp_str, message = match.groups()
            timestamp = self._parse_kernel_timestamp(timestamp_str)
            
            # Extract severity from kernel message
            level = self._extract_kernel_severity(message)
            
            event = {
                'type': 'Kernel Log',
                'timestamp': timestamp,
                'level': level,
                'source': f'Kernel Log - {os.path.basename(log_path)}',
                'event_id': f'kernel_{line_num}',
                'message': message,
                'kernel_time': timestamp_str,
                'log_type': log_type,
                'description': f'Kernel: {message[:50]}...' if len(message) > 50 else f'Kernel: {message}',
                'details': f'Kernel Time: {timestamp_str}, Level: {level}'
            }
            
        else:
            return self._create_generic_event(original_line, log_path, line_num)
            
        return event
        
    def _create_generic_event(self, line, log_path, line_num):
        """Create generic event for unparsed lines."""
        return {
            'type': 'Generic Log Entry',
            'timestamp': datetime.now().isoformat(),
            'level': 'INFO',
            'source': f'Linux Log - {os.path.basename(log_path)}',
            'event_id': f'generic_{line_num}',
            'message': line,
            'log_type': 'generic',
            'description': f'Log entry: {line[:50]}...' if len(line) > 50 else line,
            'details': f'Line: {line_num}, Raw: {line}'
        }
        
    def _parse_syslog_timestamp(self, timestamp_str):
        """Parse syslog timestamp (e.g., 'Jan 15 10:30:45')."""
        try:
            # Add current year if not present
            current_year = datetime.now().year
            full_timestamp = f"{current_year} {timestamp_str}"
            
            dt = datetime.strptime(full_timestamp, "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            return datetime.now().isoformat()
            
    def _parse_web_timestamp(self, timestamp_str):
        """Parse web server timestamp (e.g., '01/Jan/2024:10:30:45 +0000')."""
        try:
            # Remove timezone info for parsing
            timestamp_clean = timestamp_str.split()[0]
            dt = datetime.strptime(timestamp_clean, "%d/%b/%Y:%H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            return datetime.now().isoformat()
            
    def _parse_kernel_timestamp(self, timestamp_str):
        """Parse kernel timestamp (seconds since boot)."""
        try:
            seconds = float(timestamp_str.strip())
            # For demonstration, use current time minus the boot time offset
            # In real implementation, you'd calculate from system boot time
            boot_time = datetime.now() - timedelta(seconds=seconds)
            return boot_time.isoformat()
        except ValueError:
            return datetime.now().isoformat()
            
    def _extract_severity(self, message):
        """Extract severity level from message."""
        message_lower = message.lower()
        
        for keyword, level in self.severity_mapping.items():
            if keyword in message_lower:
                return level
                
        # Check for common error patterns
        if any(word in message_lower for word in ['error', 'failed', 'failure', 'cannot', 'unable']):
            return 'ERROR'
        elif any(word in message_lower for word in ['warning', 'warn', 'deprecated']):
            return 'WARNING'
        else:
            return 'INFO'
            
    def _extract_kernel_severity(self, message):
        """Extract severity from kernel message."""
        message_lower = message.lower()
        
        if any(word in message_lower for word in ['panic', 'oops', 'bug', 'fatal']):
            return 'CRITICAL'
        elif any(word in message_lower for word in ['error', 'failed', 'corruption']):
            return 'ERROR'  
        elif any(word in message_lower for word in ['warning', 'deprecated']):
            return 'WARNING'
        else:
            return 'INFO'
            
    def _passes_filters(self, event, filters):
        """Check if event passes the applied filters."""
        if not filters:
            return True
            
        try:
            # Date filter
            if 'start_date' in filters and 'end_date' in filters:
                event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                if not (filters['start_date'] <= event_time <= filters['end_date']):
                    return False
                    
            # Level filter
            if 'min_level' in filters and filters['min_level'] != 'All':
                level_priority = {'DEBUG': 0, 'INFO': 1, 'WARNING': 2, 'ERROR': 3, 'CRITICAL': 4}
                event_priority = level_priority.get(event['level'], 1)
                min_priority = level_priority.get(filters['min_level'], 1)
                if event_priority < min_priority:
                    return False
                    
            return True
            
        except Exception as e:
            print(f"Error applying filters: {e}")
            return True
            
    def analyze_auth_logs(self, events):
        """Analyze authentication-related log entries."""
        auth_events = [e for e in events if e.get('log_type') == 'auth']
        
        analysis = {
            'total_auth_events': len(auth_events),
            'successful_logins': len([e for e in auth_events if 'accepted' in e.get('message', '').lower()]),
            'failed_logins': len([e for e in auth_events if any(word in e.get('message', '').lower() 
                                                             for word in ['failed', 'invalid', 'authentication failure'])]),
            'sudo_commands': len([e for e in auth_events if 'sudo' in e.get('process', '').lower()]),
            'unique_users': len(set(self._extract_username(e.get('message', '')) 
                                  for e in auth_events if self._extract_username(e.get('message', ''))))
        }
        
        return analysis
        
    def _extract_username(self, message):
        """Extract username from authentication message."""
        # Common patterns for usernames in auth logs
        patterns = [
            r'user (\w+)',
            r'for (\w+) from',
            r'(\w+):.*session'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message.lower())
            if match:
                return match.group(1)
                
        return None
        
    def get_log_statistics(self, events):
        """Get statistics about parsed log events."""
        if not events:
            return {}
            
        stats = {
            'total_events': len(events),
            'events_by_level': {},
            'events_by_type': {},
            'events_by_source': {},
            'time_range': {
                'start': min(e['timestamp'] for e in events),
                'end': max(e['timestamp'] for e in events)
            }
        }
        
        # Count by level
        for event in events:
            level = event.get('level', 'Unknown')
            stats['events_by_level'][level] = stats['events_by_level'].get(level, 0) + 1
            
        # Count by log type
        for event in events:
            log_type = event.get('log_type', 'Unknown')
            stats['events_by_type'][log_type] = stats['events_by_type'].get(log_type, 0) + 1
            
        # Count by source
        for event in events:
            source = event.get('source', 'Unknown')
            stats['events_by_source'][source] = stats['events_by_source'].get(source, 0) + 1
            
        return stats