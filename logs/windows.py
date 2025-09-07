"""
Windows Event Log parsing module
"""

import os
from datetime import datetime, timezone
import struct
import xml.etree.ElementTree as ET


class WindowsLogParser:
    """Class for parsing Windows Event Logs (.evtx files)."""
    
    def __init__(self):
        self.event_id_descriptions = {
            4624: "Successful Logon",
            4625: "Failed Logon",
            4634: "Account Logoff",
            4648: "Logon with Explicit Credentials",
            4720: "User Account Created",
            4726: "User Account Deleted",
            4728: "User Added to Security Group",
            4732: "User Added to Local Group",
            4756: "User Added to Universal Security Group",
            7034: "Service Crashed Unexpectedly",
            7035: "Service Control Manager",
            7036: "Service Start/Stop",
            1074: "System Shutdown/Restart",
            6005: "Event Log Service Started",
            6006: "Event Log Service Stopped",
            6008: "Unexpected Shutdown",
            20001: "USB Device Connected",
            20003: "USB Device Disconnected"
        }
        
    def parse_log(self, log_path, filters=None):
        """Parse Windows Event Log file.
        
        Args:
            log_path: Path to .evtx file
            filters: Dictionary with filtering options
            
        Returns:
            List of parsed log events
        """
        events = []
        
        try:
            if not os.path.exists(log_path):
                print(f"Log file not found: {log_path}")
                return events
                
            # For demonstration, create sample Windows events
            # In a real implementation, you'd use a library like python-evtx
            events = self._create_sample_events(log_path, filters)
            
        except Exception as e:
            print(f"Error parsing Windows log {log_path}: {e}")
            
        return events
        
    def _create_sample_events(self, log_path, filters):
        """Create sample Windows events for demonstration."""
        events = []
        
        # Sample event data
        sample_events = [
            {
                'event_id': 4624,
                'level': 'INFO',
                'timestamp': datetime.now().replace(hour=8, minute=30).isoformat(),
                'source': 'Microsoft-Windows-Security-Auditing',
                'message': 'An account was successfully logged on. Subject: User001, Logon Type: 2 (Interactive)'
            },
            {
                'event_id': 4625,
                'level': 'WARNING',
                'timestamp': datetime.now().replace(hour=9, minute=15).isoformat(),
                'source': 'Microsoft-Windows-Security-Auditing',
                'message': 'An account failed to log on. Account Name: attacker, Failure Reason: Unknown user name or bad password'
            },
            {
                'event_id': 7036,
                'level': 'INFO',
                'timestamp': datetime.now().replace(hour=10, minute=45).isoformat(),
                'source': 'Service Control Manager',
                'message': 'The Windows Update service entered the running state'
            },
            {
                'event_id': 1074,
                'level': 'INFO',
                'timestamp': datetime.now().replace(hour=17, minute=0).isoformat(),
                'source': 'User32',
                'message': 'The process winlogon.exe has initiated the restart of computer for the following reason: Operating System: Service pack (Planned)'
            },
            {
                'event_id': 20001,
                'level': 'INFO',
                'timestamp': datetime.now().replace(hour=14, minute=20).isoformat(),
                'source': 'Microsoft-Windows-USB-USBHUB',
                'message': 'USB device connected: Kingston DataTraveler 3.0 USB Device'
            },
            {
                'event_id': 4720,
                'level': 'INFO',
                'timestamp': datetime.now().replace(hour=11, minute=5).isoformat(),
                'source': 'Microsoft-Windows-Security-Auditing',
                'message': 'A user account was created. New Account: testuser, Created by: administrator'
            }
        ]
        
        # Apply filters if provided
        if filters:
            filtered_events = []
            for event in sample_events:
                # Apply date filters
                if 'start_date' in filters and 'end_date' in filters:
                    event_time = datetime.fromisoformat(event['timestamp'])
                    if not (filters['start_date'] <= event_time <= filters['end_date']):
                        continue
                        
                # Apply level filter
                if 'min_level' in filters and filters['min_level'] != 'All':
                    level_priority = {'DEBUG': 0, 'INFO': 1, 'WARNING': 2, 'ERROR': 3}
                    event_priority = level_priority.get(event['level'], 1)
                    min_priority = level_priority.get(filters['min_level'], 1)
                    if event_priority < min_priority:
                        continue
                        
                filtered_events.append(event)
                
            sample_events = filtered_events
            
        # Limit number of events
        if filters and 'max_events' in filters:
            sample_events = sample_events[:filters['max_events']]
            
        # Convert to standard format
        for event in sample_events:
            parsed_event = {
                'type': 'Windows Event Log',
                'timestamp': event['timestamp'],
                'level': event['level'],
                'source': f"Windows Event Log - {os.path.basename(log_path)}",
                'event_id': event['event_id'],
                'message': event['message'],
                'description': self.event_id_descriptions.get(event['event_id'], f"Event ID {event['event_id']}"),
                'details': f"Event ID: {event['event_id']}, Source: {event['source']}, Level: {event['level']}"
            }
            events.append(parsed_event)
            
        return events
        
    def parse_evtx_file(self, evtx_path):
        """Parse .evtx file using binary format.
        
        This is a simplified demonstration. Real .evtx parsing requires
        complex binary format handling.
        """
        events = []
        
        try:
            with open(evtx_path, 'rb') as f:
                # Read file header
                header = f.read(4096)
                
                # Check for EVTX signature
                if header[:8] != b'ElfFile\x00':
                    print(f"Invalid EVTX file signature in {evtx_path}")
                    return events
                    
                # For demonstration, return sample events
                # Real implementation would parse chunks and records
                events = self._create_sample_events(evtx_path, None)
                
        except Exception as e:
            print(f"Error parsing EVTX file {evtx_path}: {e}")
            
        return events
        
    def extract_event_details(self, event_xml):
        """Extract details from Windows Event XML."""
        try:
            root = ET.fromstring(event_xml)
            
            # Extract basic information
            system = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}System')
            event_data = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
            
            details = {}
            
            if system is not None:
                for child in system:
                    tag = child.tag.split('}')[-1]  # Remove namespace
                    if child.text:
                        details[tag] = child.text
                    elif child.attrib:
                        details[tag] = child.attrib
                        
            if event_data is not None:
                for data in event_data:
                    name = data.get('Name', f'Data{len(details)}')
                    details[name] = data.text or ''
                    
            return details
            
        except Exception as e:
            print(f"Error parsing event XML: {e}")
            return {}
            
    def get_common_event_types(self):
        """Get list of common Windows event types for filtering."""
        return {
            'Security': [4624, 4625, 4634, 4648, 4720, 4726, 4728, 4732],
            'System': [1074, 6005, 6006, 6008, 7034, 7035, 7036],
            'Application': [1000, 1001, 1002],
            'USB': [20001, 20003]
        }
        
    def format_event_message(self, event_id, event_data):
        """Format event message based on event ID and data."""
        messages = {
            4624: "Successful logon for user {TargetUserName} from {IpAddress}",
            4625: "Failed logon attempt for user {TargetUserName} from {IpAddress}",
            4634: "User {TargetUserName} logged off",
            1074: "System restart initiated by {SubjectUserName}",
            7036: "Service {param1} changed state to {param2}"
        }
        
        template = messages.get(event_id, f"Event ID {event_id} occurred")
        
        try:
            return template.format(**event_data)
        except KeyError:
            return template
            
    def analyze_logon_events(self, events):
        """Analyze logon-related events for patterns."""
        logon_events = [e for e in events if e.get('event_id') in [4624, 4625, 4634, 4648]]
        
        analysis = {
            'total_logons': len([e for e in logon_events if e.get('event_id') == 4624]),
            'failed_logons': len([e for e in logon_events if e.get('event_id') == 4625]),
            'logoffs': len([e for e in logon_events if e.get('event_id') == 4634]),
            'explicit_logons': len([e for e in logon_events if e.get('event_id') == 4648])
        }
        
        return analysis