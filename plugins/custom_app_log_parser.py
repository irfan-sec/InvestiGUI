"""
Example Custom Log Parser Plugin
Demonstrates how to create custom log parsers.
"""

import os
import re
from datetime import datetime
from typing import List, Dict
from plugin_manager import LogParserPlugin


class CustomApplicationLogParser(LogParserPlugin):
    """Example plugin for parsing custom application logs."""
    
    def get_plugin_info(self) -> Dict:
        return {
            'name': 'Custom Application Log Parser',
            'version': '1.0.0',
            'description': 'Parses custom application log files',
            'author': 'InvestiGUI Team',
            'category': 'Log Parser',
            'supported_log_types': self.get_supported_log_types()
        }
    
    def initialize(self) -> bool:
        """Initialize the plugin."""
        return True
    
    def execute(self, data) -> Dict:
        """Execute the plugin."""
        if isinstance(data, str):
            return {'events': self.parse_logs(data)}
        return {'error': 'Invalid data type'}
    
    def cleanup(self) -> None:
        """Clean up resources."""
        pass
    
    def parse_logs(self, log_path: str) -> List[Dict]:
        """Parse custom application logs."""
        events = []
        
        if not os.path.exists(log_path):
            return events
        
        try:
            # Simulate parsing custom log format
            sample_events = [
                {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'Application Event',
                    'source': 'Custom Application Log Parser',
                    'description': 'User authentication successful',
                    'details': {
                        'username': 'john.doe',
                        'source_ip': '192.168.1.100',
                        'session_id': 'sess_12345'
                    },
                    'severity': 'Info'
                },
                {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'Application Error',
                    'source': 'Custom Application Log Parser',
                    'description': 'Database connection failed',
                    'details': {
                        'error_code': 'DB_CONN_001',
                        'database': 'app_database',
                        'retry_count': 3
                    },
                    'severity': 'High'
                }
            ]
            
            events.extend(sample_events)
            
        except Exception as e:
            events.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'Parser Error',
                'source': 'Custom Application Log Parser',
                'description': f'Failed to parse log: {str(e)}',
                'severity': 'Medium'
            })
        
        return events
    
    def get_supported_log_types(self) -> List[str]:
        """Return supported log types."""
        return ['custom_app.log', 'application.log', '.app']
