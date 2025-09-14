"""
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
