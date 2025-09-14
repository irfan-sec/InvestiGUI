"""
Artifact extraction modules for InvestiGUI v2.0.0

This package contains modules for extracting various types of digital artifacts:
- browser.py: Browser history and artifacts
- usb.py: USB device history and connections  
- wifi.py: WiFi network profiles and connections
- files.py: File system artifacts and recent files
- memory.py: Memory dump analysis and artifacts (NEW)
- network.py: Network packet analysis and artifacts (NEW)
"""

from .browser import BrowserArtifacts
from .usb import USBArtifacts
from .wifi import WiFiArtifacts
from .files import FileArtifacts
from .memory import MemoryArtifacts, analyze_memory_dump_artifacts
from .network import NetworkAnalyzer, analyze_network_artifacts

__all__ = [
    'BrowserArtifacts',
    'USBArtifacts', 
    'WiFiArtifacts',
    'FileArtifacts',
    'MemoryArtifacts',
    'NetworkAnalyzer',
    'analyze_memory_dump_artifacts',
    'analyze_network_artifacts'
]

# Version info
__version__ = '2.0.0'

# Supported artifact types
ARTIFACT_TYPES = {
    'browser': 'Browser History and Artifacts',
    'usb': 'USB Device History', 
    'wifi': 'WiFi Network Profiles',
    'files': 'File System Artifacts',
    'memory': 'Memory Dump Analysis',
    'network': 'Network Packet Analysis'
}

def get_available_extractors():
    """Get list of available artifact extractors."""
    return list(ARTIFACT_TYPES.keys())

def get_extractor_description(extractor_type):
    """Get description for an extractor type."""
    return ARTIFACT_TYPES.get(extractor_type, 'Unknown extractor type')