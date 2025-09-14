"""
Plugin Architecture for InvestiGUI
Extensible plugin system for custom analyzers and tools.
"""

import os
import sys
import json
import importlib
import importlib.util
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Optional, Any, Callable
import inspect


class PluginInterface(ABC):
    """Abstract base class for InvestiGUI plugins."""
    
    @abstractmethod
    def get_plugin_info(self) -> Dict:
        """Return plugin metadata information."""
        pass
    
    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the plugin. Return True if successful."""
        pass
    
    @abstractmethod
    def execute(self, data: Any) -> Dict:
        """Execute the plugin with provided data."""
        pass
    
    @abstractmethod
    def cleanup(self) -> None:
        """Clean up resources when plugin is unloaded."""
        pass


class ArtifactExtractorPlugin(PluginInterface):
    """Base class for artifact extraction plugins."""
    
    @abstractmethod
    def extract_artifacts(self, source_path: str) -> List[Dict]:
        """Extract artifacts from the given source path."""
        pass
    
    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Return list of supported file formats."""
        pass


class LogParserPlugin(PluginInterface):
    """Base class for log parser plugins."""
    
    @abstractmethod
    def parse_logs(self, log_path: str) -> List[Dict]:
        """Parse logs from the given path."""
        pass
    
    @abstractmethod
    def get_supported_log_types(self) -> List[str]:
        """Return list of supported log types."""
        pass


class AnalysisPlugin(PluginInterface):
    """Base class for analysis plugins."""
    
    @abstractmethod
    def analyze_data(self, timeline_data: List[Dict], artifacts: Dict) -> Dict:
        """Analyze the provided data and return results."""
        pass


class PluginManager:
    """Manager for loading and executing plugins."""
    
    def __init__(self, plugin_directories: List[str] = None):
        if plugin_directories is None:
            plugin_directories = ['plugins', 'custom_plugins']
        
        self.plugin_directories = plugin_directories
        self.loaded_plugins = {}
        self.plugin_registry = {
            'artifact_extractors': {},
            'log_parsers': {},
            'analyzers': {},
            'general': {}
        }
        
        # Create plugin directories if they don't exist
        for directory in self.plugin_directories:
            os.makedirs(directory, exist_ok=True)
            
        # Create example plugins
        self._create_example_plugins()
    
    def load_plugins(self) -> Dict:
        """Load all plugins from plugin directories."""
        load_results = {
            'loaded': [],
            'failed': [],
            'total_found': 0
        }
        
        for plugin_dir in self.plugin_directories:
            if not os.path.exists(plugin_dir):
                continue
                
            # Look for Python files in plugin directory
            for file_name in os.listdir(plugin_dir):
                if file_name.endswith('.py') and not file_name.startswith('__'):
                    plugin_path = os.path.join(plugin_dir, file_name)
                    load_results['total_found'] += 1
                    
                    try:
                        plugin_name = file_name[:-3]  # Remove .py extension
                        plugin = self._load_plugin_from_file(plugin_path, plugin_name)
                        
                        if plugin:
                            self.loaded_plugins[plugin_name] = plugin
                            self._register_plugin(plugin_name, plugin)
                            load_results['loaded'].append(plugin_name)
                            
                    except Exception as e:
                        load_results['failed'].append({
                            'plugin': file_name,
                            'error': str(e)
                        })
        
        return load_results
    
    def _load_plugin_from_file(self, plugin_path: str, plugin_name: str) -> Optional[PluginInterface]:
        """Load a plugin from a Python file."""
        try:
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
            if spec is None:
                return None
                
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Look for plugin class in the module
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, PluginInterface) and 
                    obj != PluginInterface and
                    obj not in [ArtifactExtractorPlugin, LogParserPlugin, AnalysisPlugin]):
                    
                    plugin_instance = obj()
                    if plugin_instance.initialize():
                        return plugin_instance
                    
        except Exception as e:
            print(f"Error loading plugin {plugin_name}: {e}")
            
        return None
    
    def _register_plugin(self, plugin_name: str, plugin: PluginInterface) -> None:
        """Register a plugin in the appropriate category."""
        if isinstance(plugin, ArtifactExtractorPlugin):
            self.plugin_registry['artifact_extractors'][plugin_name] = plugin
        elif isinstance(plugin, LogParserPlugin):
            self.plugin_registry['log_parsers'][plugin_name] = plugin
        elif isinstance(plugin, AnalysisPlugin):
            self.plugin_registry['analyzers'][plugin_name] = plugin
        else:
            self.plugin_registry['general'][plugin_name] = plugin
    
    def get_available_plugins(self) -> Dict:
        """Get information about all available plugins."""
        plugin_info = {}
        
        for category, plugins in self.plugin_registry.items():
            plugin_info[category] = {}
            for plugin_name, plugin in plugins.items():
                try:
                    plugin_info[category][plugin_name] = plugin.get_plugin_info()
                except:
                    plugin_info[category][plugin_name] = {
                        'error': 'Failed to get plugin info'
                    }
        
        return plugin_info
    
    def execute_plugin(self, plugin_name: str, data: Any) -> Dict:
        """Execute a specific plugin with provided data."""
        if plugin_name not in self.loaded_plugins:
            return {
                'error': f'Plugin {plugin_name} not found or not loaded'
            }
        
        try:
            plugin = self.loaded_plugins[plugin_name]
            return plugin.execute(data)
        except Exception as e:
            return {
                'error': f'Plugin execution failed: {str(e)}'
            }
    
    def execute_artifact_extractors(self, source_path: str) -> Dict:
        """Execute all artifact extractor plugins."""
        results = {}
        
        for plugin_name, plugin in self.plugin_registry['artifact_extractors'].items():
            try:
                artifacts = plugin.extract_artifacts(source_path)
                results[plugin_name] = {
                    'success': True,
                    'artifacts': artifacts,
                    'count': len(artifacts) if artifacts else 0
                }
            except Exception as e:
                results[plugin_name] = {
                    'success': False,
                    'error': str(e)
                }
        
        return results
    
    def execute_log_parsers(self, log_path: str) -> Dict:
        """Execute all log parser plugins."""
        results = {}
        
        for plugin_name, plugin in self.plugin_registry['log_parsers'].items():
            try:
                events = plugin.parse_logs(log_path)
                results[plugin_name] = {
                    'success': True,
                    'events': events,
                    'count': len(events) if events else 0
                }
            except Exception as e:
                results[plugin_name] = {
                    'success': False,
                    'error': str(e)
                }
        
        return results
    
    def execute_analyzers(self, timeline_data: List[Dict], artifacts: Dict) -> Dict:
        """Execute all analysis plugins."""
        results = {}
        
        for plugin_name, plugin in self.plugin_registry['analyzers'].items():
            try:
                analysis = plugin.analyze_data(timeline_data, artifacts)
                results[plugin_name] = {
                    'success': True,
                    'analysis': analysis
                }
            except Exception as e:
                results[plugin_name] = {
                    'success': False,
                    'error': str(e)
                }
        
        return results
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a specific plugin."""
        if plugin_name in self.loaded_plugins:
            try:
                plugin = self.loaded_plugins[plugin_name]
                plugin.cleanup()
                
                # Remove from registry
                for category_plugins in self.plugin_registry.values():
                    if plugin_name in category_plugins:
                        del category_plugins[plugin_name]
                        break
                
                del self.loaded_plugins[plugin_name]
                return True
            except Exception as e:
                print(f"Error unloading plugin {plugin_name}: {e}")
        
        return False
    
    def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a specific plugin."""
        # Find the plugin file
        for plugin_dir in self.plugin_directories:
            plugin_path = os.path.join(plugin_dir, f"{plugin_name}.py")
            if os.path.exists(plugin_path):
                # Unload existing plugin
                self.unload_plugin(plugin_name)
                
                # Load plugin again
                try:
                    plugin = self._load_plugin_from_file(plugin_path, plugin_name)
                    if plugin:
                        self.loaded_plugins[plugin_name] = plugin
                        self._register_plugin(plugin_name, plugin)
                        return True
                except Exception as e:
                    print(f"Error reloading plugin {plugin_name}: {e}")
        
        return False
    
    def _create_example_plugins(self) -> None:
        """Create example plugins to demonstrate the system."""
        # Create plugins directory
        plugins_dir = 'plugins'
        os.makedirs(plugins_dir, exist_ok=True)
        
        # Example artifact extractor plugin
        example_artifact_plugin = '''"""
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
                    'key_path': 'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
                    'value_name': 'CustomApp',
                    'value_data': 'C:\\\\Custom\\\\app.exe',
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
                    'key_path': 'HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\CustomSoftware',
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
'''
        
        with open(os.path.join(plugins_dir, 'custom_registry_extractor.py'), 'w') as f:
            f.write(example_artifact_plugin)
        
        # Example log parser plugin
        example_log_plugin = '''"""
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
'''
        
        with open(os.path.join(plugins_dir, 'custom_app_log_parser.py'), 'w') as f:
            f.write(example_log_plugin)
        
        # Example analysis plugin
        example_analysis_plugin = '''"""
Example Custom Analysis Plugin
Demonstrates how to create custom analyzers.
"""

from typing import List, Dict
from datetime import datetime
from plugin_manager import AnalysisPlugin


class CustomThreatHunter(AnalysisPlugin):
    """Example plugin for custom threat hunting analysis."""
    
    def get_plugin_info(self) -> Dict:
        return {
            'name': 'Custom Threat Hunter',
            'version': '1.0.0',
            'description': 'Performs custom threat hunting analysis on forensic data',
            'author': 'InvestiGUI Team',
            'category': 'Analysis Plugin'
        }
    
    def initialize(self) -> bool:
        """Initialize the plugin."""
        self.threat_indicators = [
            'powershell.exe -enc',
            'cmd.exe /c echo',
            'rundll32.exe',
            'regsvr32.exe /s /u',
            'schtasks /create'
        ]
        return True
    
    def execute(self, data) -> Dict:
        """Execute the plugin."""
        if isinstance(data, dict) and 'timeline_data' in data and 'artifacts' in data:
            return self.analyze_data(data['timeline_data'], data['artifacts'])
        return {'error': 'Invalid data format'}
    
    def cleanup(self) -> None:
        """Clean up resources."""
        pass
    
    def analyze_data(self, timeline_data: List[Dict], artifacts: Dict) -> Dict:
        """Perform custom threat hunting analysis."""
        analysis_results = {
            'analysis_timestamp': datetime.now().isoformat(),
            'threats_detected': [],
            'suspicious_patterns': [],
            'risk_score': 0,
            'recommendations': []
        }
        
        # Analyze timeline data for threat indicators
        for event in timeline_data:
            description = event.get('description', '').lower()
            
            for indicator in self.threat_indicators:
                if indicator.lower() in description:
                    analysis_results['threats_detected'].append({
                        'indicator': indicator,
                        'event_timestamp': event.get('timestamp'),
                        'event_description': event.get('description'),
                        'severity': 'High',
                        'confidence': 0.8
                    })
        
        # Analyze for suspicious patterns
        high_severity_events = [e for e in timeline_data if e.get('severity') == 'High']
        if len(high_severity_events) > 10:
            analysis_results['suspicious_patterns'].append({
                'pattern': 'High volume of high-severity events',
                'count': len(high_severity_events),
                'description': 'Unusually high number of high-severity events detected'
            })
        
        # Calculate risk score
        threat_count = len(analysis_results['threats_detected'])
        pattern_count = len(analysis_results['suspicious_patterns'])
        analysis_results['risk_score'] = min((threat_count * 2 + pattern_count) * 10, 100)
        
        # Generate recommendations
        if threat_count > 0:
            analysis_results['recommendations'].append(
                'Immediate investigation of detected threat indicators required'
            )
        
        if analysis_results['risk_score'] > 50:
            analysis_results['recommendations'].append(
                'High risk detected - implement additional monitoring'
            )
        
        return analysis_results
'''
        
        with open(os.path.join(plugins_dir, 'custom_threat_hunter.py'), 'w') as f:
            f.write(example_analysis_plugin)
    
    def get_plugin_statistics(self) -> Dict:
        """Get statistics about loaded plugins."""
        stats = {
            'total_plugins': len(self.loaded_plugins),
            'by_category': {},
            'plugin_details': []
        }
        
        for category, plugins in self.plugin_registry.items():
            stats['by_category'][category] = len(plugins)
        
        for plugin_name, plugin in self.loaded_plugins.items():
            try:
                plugin_info = plugin.get_plugin_info()
                stats['plugin_details'].append({
                    'name': plugin_name,
                    'info': plugin_info
                })
            except:
                stats['plugin_details'].append({
                    'name': plugin_name,
                    'info': {'error': 'Could not retrieve plugin info'}
                })
        
        return stats


# Global plugin manager instance
_plugin_manager = None


def get_plugin_manager() -> PluginManager:
    """Get the global plugin manager instance."""
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager


def initialize_plugin_system() -> Dict:
    """Initialize the plugin system and load all plugins."""
    manager = get_plugin_manager()
    return manager.load_plugins()


def execute_all_plugins(timeline_data: List[Dict], artifacts: Dict, source_paths: List[str] = None) -> Dict:
    """Execute all loaded plugins with the provided data."""
    manager = get_plugin_manager()
    
    results = {
        'artifact_extraction': {},
        'log_parsing': {},
        'analysis': {},
        'execution_timestamp': datetime.now().isoformat()
    }
    
    # Execute artifact extractors if source paths provided
    if source_paths:
        for source_path in source_paths:
            extractor_results = manager.execute_artifact_extractors(source_path)
            results['artifact_extraction'][source_path] = extractor_results
    
    # Execute log parsers if source paths provided
    if source_paths:
        for source_path in source_paths:
            parser_results = manager.execute_log_parsers(source_path)
            results['log_parsing'][source_path] = parser_results
    
    # Execute analyzers
    results['analysis'] = manager.execute_analyzers(timeline_data, artifacts)
    
    return results