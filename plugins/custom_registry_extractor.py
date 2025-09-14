"""
Example Custom Artifact Extractor Plugin
Demonstrates how to create custom artifact extractors.
"""

import os
import json
from datetime import datetime
from typing import List, Dict
from plugin_manager import ArtifactExtractorPlugin


class CustomRegistryExtractor(ArtifactExtractorPlugin):
    """Example plugin for extracting custom registry artifacts."""
    
    def get_plugin_info(self) -> Dict:
        return {
            'name': 'Custom Registry Extractor',
            'version': '1.0.0',
            'description': 'Extracts custom registry artifacts from Windows systems',
            'author': 'InvestiGUI Team',
            'category': 'Artifact Extractor',
            'supported_formats': self.get_supported_formats()
        }
    
    def initialize(self) -> bool:
        """Initialize the plugin."""
        return True
    
    def execute(self, data) -> Dict:
        """Execute the plugin."""
        if isinstance(data, str):
            return {'artifacts': self.extract_artifacts(data)}
        return {'error': 'Invalid data type'}
    
    def cleanup(self) -> None:
        """Clean up resources."""
        pass
    
    def extract_artifacts(self, source_path: str) -> List[Dict]:
        """Extract custom registry artifacts."""
        artifacts = []
        
        # Simulate custom registry extraction
        sample_artifacts = [
            {
                'timestamp': datetime.now().isoformat(),
                'type': 'Registry Key',
                'source': 'Custom Registry Extractor',
                'description': 'Custom startup program detected',
                'details': {
                    'key_path': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'value_name': 'CustomApp',
                    'value_data': 'C:\\Custom\\app.exe',
                    'last_modified': datetime.now().isoformat()
                },
                'severity': 'Medium'
            },
            {
                'timestamp': datetime.now().isoformat(),
                'type': 'Registry Key',
                'source': 'Custom Registry Extractor',
                'description': 'Custom uninstall entry found',
                'details': {
                    'key_path': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\CustomSoftware',
                    'display_name': 'Custom Software v1.0',
                    'install_date': '20241201',
                    'publisher': 'Custom Publisher'
                },
                'severity': 'Info'
            }
        ]
        
        artifacts.extend(sample_artifacts)
        return artifacts
    
    def get_supported_formats(self) -> List[str]:
        """Return supported file formats."""
        return ['.reg', '.hiv', '.dat']
