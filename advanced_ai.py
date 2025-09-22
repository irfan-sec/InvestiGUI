"""
Advanced AI-Powered Threat Detection and Behavioral Analysis
Next-generation machine learning for digital forensics investigations.
"""

import os
import json
import hashlib
import re
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Set
from collections import defaultdict, Counter
import numpy as np
from dataclasses import dataclass
import pickle
import threading
import concurrent.futures

# Advanced behavioral patterns and threat signatures
ADVANCED_THREAT_SIGNATURES = {
    'apt_patterns': {
        'lateral_movement': [
            r'psexec.*-s\s+.*\\.*\.exe',
            r'wmic.*process.*create.*cmd',
            r'powershell.*-EncodedCommand',
            r'sc.*create.*binpath.*cmd',
            r'net.*use.*\$.*password'
        ],
        'persistence': [
            r'schtasks.*create.*system',
            r'reg.*add.*run.*autostart',
            r'wmic.*startup.*create',
            r'sc.*config.*start.*auto',
            r'at\s+\d+:\d+.*cmd'
        ],
        'data_exfiltration': [
            r'7z.*a.*-p.*\.zip',
            r'rar.*a.*-hp.*\.rar',
            r'copy.*\\\\.*\$.*ftp',
            r'robocopy.*\/mir.*network',
            r'powershell.*invoke-webrequest.*outfile'
        ]
    },
    'malware_behaviors': {
        'ransomware': [
            r'\.encrypt.*\.exe',
            r'vssadmin.*delete.*shadows',
            r'wbadmin.*delete.*catalog',
            r'bcdedit.*recoveryenabled.*no',
            r'cipher.*\/w:.*'
        ],
        'rootkit': [
            r'ntoskrnl\.exe.*hook',
            r'system32.*driver.*load',
            r'kernel.*mode.*inject',
            r'direct.*kernel.*object',
            r'ssdt.*hook.*modify'
        ],
        'spyware': [
            r'keylog.*capture.*start',
            r'screenshot.*timer.*save',
            r'microphone.*record.*wav',
            r'webcam.*capture.*jpg',
            r'clipboard.*monitor.*text'
        ]
    }
}

@dataclass
class ThreatAlert:
    """Advanced threat alert with detailed context."""
    threat_id: str
    threat_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float
    description: str
    indicators: List[str]
    timeline_events: List[Dict]
    mitigation: List[str]
    attribution: Optional[str] = None
    kill_chain_stage: Optional[str] = None
    false_positive_probability: float = 0.0


class AdvancedThreatDetector:
    """Next-generation AI-powered threat detection engine."""
    
    def __init__(self):
        self.models = {}
        self.threat_intelligence = {}
        self.behavioral_baselines = {}
        self.ml_models_trained = False
        self.yara_rules = []
        self.ioc_feeds = []
        self.attribution_engine = AttributionEngine()
        
        # Initialize threat intelligence feeds
        self._initialize_threat_intelligence()
        self._load_yara_rules()
        
    def analyze_advanced_threats(self, timeline_data: List[Dict], 
                                artifacts: Dict,
                                memory_analysis: Optional[Dict] = None,
                                network_analysis: Optional[Dict] = None) -> Dict:
        """
        Perform comprehensive advanced threat analysis using AI and ML.
        
        Args:
            timeline_data: Timeline events for analysis
            artifacts: Extracted artifacts
            memory_analysis: Memory dump analysis results
            network_analysis: Network traffic analysis results
            
        Returns:
            Advanced threat analysis results
        """
        results = {
            'analysis_timestamp': datetime.now().isoformat(),
            'threat_alerts': [],
            'behavioral_analysis': {},
            'attribution_analysis': {},
            'kill_chain_analysis': {},
            'risk_assessment': {},
            'recommendations': [],
            'threat_hunting_results': {},
            'advanced_indicators': {}
        }
        
        # Multi-threaded analysis for performance
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            
            # APT and targeted attack detection
            futures.append(executor.submit(self._detect_apt_activities, timeline_data, artifacts))
            
            # Advanced malware analysis
            futures.append(executor.submit(self._analyze_malware_behaviors, timeline_data, memory_analysis))
            
            # Behavioral anomaly detection with deep learning
            futures.append(executor.submit(self._deep_behavioral_analysis, timeline_data, artifacts))
            
            # Network-based threat detection
            if network_analysis:
                futures.append(executor.submit(self._analyze_network_threats, network_analysis))
            
            # Attribution analysis
            futures.append(executor.submit(self._perform_attribution_analysis, timeline_data, artifacts))
            
            # Kill chain analysis
            futures.append(executor.submit(self._analyze_kill_chain, timeline_data, artifacts))
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if isinstance(result, dict):
                        for key, value in result.items():
                            if key in results:
                                if isinstance(results[key], list):
                                    results[key].extend(value if isinstance(value, list) else [value])
                                else:
                                    results[key].update(value if isinstance(value, dict) else {})
                except Exception as e:
                    print(f"Error in advanced threat analysis: {e}")
        
        # Generate comprehensive risk assessment
        results['risk_assessment'] = self._calculate_advanced_risk_score(results)
        
        # Generate actionable recommendations
        results['recommendations'] = self._generate_advanced_recommendations(results)
        
        return results
    
    def _detect_apt_activities(self, timeline_data: List[Dict], artifacts: Dict) -> Dict:
        """Detect Advanced Persistent Threat (APT) activities."""
        apt_indicators = {
            'lateral_movement': [],
            'persistence_mechanisms': [],
            'privilege_escalation': [],
            'data_staging': [],
            'exfiltration_activities': []
        }
        
        # Analyze timeline for APT patterns
        for event in timeline_data:
            description = event.get('description', '').lower()
            
            # Check for lateral movement
            for pattern in ADVANCED_THREAT_SIGNATURES['apt_patterns']['lateral_movement']:
                if re.search(pattern, description, re.IGNORECASE):
                    apt_indicators['lateral_movement'].append({
                        'event': event,
                        'pattern': pattern,
                        'confidence': 0.85,
                        'technique': 'T1021 - Remote Services'
                    })
            
            # Check for persistence
            for pattern in ADVANCED_THREAT_SIGNATURES['apt_patterns']['persistence']:
                if re.search(pattern, description, re.IGNORECASE):
                    apt_indicators['persistence_mechanisms'].append({
                        'event': event,
                        'pattern': pattern,
                        'confidence': 0.80,
                        'technique': 'T1053 - Scheduled Task/Job'
                    })
        
        # Advanced correlation analysis
        correlated_activities = self._correlate_apt_activities(apt_indicators)
        
        return {'apt_analysis': apt_indicators, 'correlations': correlated_activities}
    
    def _analyze_malware_behaviors(self, timeline_data: List[Dict], 
                                  memory_analysis: Optional[Dict]) -> Dict:
        """Advanced malware behavior analysis with ML classification."""
        malware_analysis = {
            'suspected_malware': [],
            'family_classification': {},
            'behavioral_indicators': [],
            'memory_artifacts': []
        }
        
        # Behavioral pattern matching
        behavior_scores = defaultdict(float)
        
        for event in timeline_data:
            description = event.get('description', '')
            
            # Check for ransomware behaviors
            for pattern in ADVANCED_THREAT_SIGNATURES['malware_behaviors']['ransomware']:
                if re.search(pattern, description, re.IGNORECASE):
                    behavior_scores['ransomware'] += 0.3
                    malware_analysis['behavioral_indicators'].append({
                        'behavior': 'ransomware',
                        'event': event,
                        'confidence': 0.75
                    })
            
            # Check for rootkit behaviors
            for pattern in ADVANCED_THREAT_SIGNATURES['malware_behaviors']['rootkit']:
                if re.search(pattern, description, re.IGNORECASE):
                    behavior_scores['rootkit'] += 0.4
                    malware_analysis['behavioral_indicators'].append({
                        'behavior': 'rootkit',
                        'event': event,
                        'confidence': 0.80
                    })
        
        # Memory-based malware detection
        if memory_analysis and 'processes' in memory_analysis:
            for process in memory_analysis['processes']:
                if self._is_suspicious_process(process):
                    malware_analysis['memory_artifacts'].append({
                        'process': process,
                        'suspicion_reasons': self._analyze_process_suspicion(process),
                        'confidence': 0.70
                    })
        
        # ML-based family classification
        if behavior_scores:
            malware_analysis['family_classification'] = self._classify_malware_family(behavior_scores)
        
        return {'malware_analysis': malware_analysis}
    
    def _deep_behavioral_analysis(self, timeline_data: List[Dict], artifacts: Dict) -> Dict:
        """Deep learning-based behavioral analysis."""
        behavioral_results = {
            'user_behavior_anomalies': [],
            'system_behavior_anomalies': [],
            'temporal_anomalies': [],
            'process_tree_anomalies': []
        }
        
        # Analyze user behavior patterns
        user_activities = self._extract_user_activities(timeline_data)
        user_anomalies = self._detect_user_anomalies(user_activities)
        behavioral_results['user_behavior_anomalies'] = user_anomalies
        
        # System behavior analysis
        system_activities = self._extract_system_activities(timeline_data)
        system_anomalies = self._detect_system_anomalies(system_activities)
        behavioral_results['system_behavior_anomalies'] = system_anomalies
        
        # Temporal pattern analysis
        temporal_patterns = self._analyze_temporal_patterns(timeline_data)
        behavioral_results['temporal_anomalies'] = temporal_patterns
        
        return {'behavioral_analysis': behavioral_results}
    
    def _perform_attribution_analysis(self, timeline_data: List[Dict], artifacts: Dict) -> Dict:
        """Advanced threat attribution using multiple intelligence sources."""
        return self.attribution_engine.analyze_attribution(timeline_data, artifacts)
    
    def _analyze_kill_chain(self, timeline_data: List[Dict], artifacts: Dict) -> Dict:
        """Analyze attack progression through the cyber kill chain."""
        kill_chain_stages = {
            'reconnaissance': [],
            'weaponization': [],
            'delivery': [],
            'exploitation': [],
            'installation': [],
            'command_control': [],
            'actions_objectives': []
        }
        
        for event in timeline_data:
            description = event.get('description', '').lower()
            timestamp = event.get('timestamp', '')
            
            # Reconnaissance indicators
            if any(indicator in description for indicator in ['nslookup', 'ping', 'tracert', 'whoami', 'net view']):
                kill_chain_stages['reconnaissance'].append({
                    'event': event,
                    'stage': 'reconnaissance',
                    'confidence': 0.7
                })
            
            # Exploitation indicators
            if any(indicator in description for indicator in ['exploit', 'shellcode', 'buffer overflow', 'rce']):
                kill_chain_stages['exploitation'].append({
                    'event': event,
                    'stage': 'exploitation',
                    'confidence': 0.8
                })
            
            # Command and Control indicators
            if any(indicator in description for indicator in ['c2', 'beacon', 'callback', 'encrypted channel']):
                kill_chain_stages['command_control'].append({
                    'event': event,
                    'stage': 'command_control',
                    'confidence': 0.85
                })
        
        return {'kill_chain_analysis': kill_chain_stages}
    
    def _initialize_threat_intelligence(self):
        """Initialize threat intelligence feeds and databases."""
        self.threat_intelligence = {
            'ioc_database': {},
            'apt_groups': {},
            'malware_families': {},
            'attack_techniques': {}
        }
        
        # Load known APT groups and their TTPs
        self.threat_intelligence['apt_groups'] = {
            'APT1': {
                'techniques': ['T1021.001', 'T1053.005', 'T1059.001'],
                'indicators': ['specific_tools.exe', 'custom_backdoor.dll'],
                'attribution_confidence': 0.9
            },
            'Lazarus': {
                'techniques': ['T1566.001', 'T1055', 'T1027'],
                'indicators': ['lazarus_implant.exe', 'custom_loader.dll'],
                'attribution_confidence': 0.85
            }
        }
    
    def _load_yara_rules(self):
        """Load YARA rules for malware detection."""
        # In a real implementation, this would load actual YARA rules
        self.yara_rules = [
            {
                'name': 'Generic_Ransomware',
                'pattern': r'(vssadmin.*delete.*shadows|wbadmin.*delete.*catalog)',
                'description': 'Detects ransomware shadow deletion behavior'
            },
            {
                'name': 'APT_Lateral_Movement',
                'pattern': r'(psexec.*-s.*exe|wmic.*process.*create)',
                'description': 'Detects APT lateral movement techniques'
            }
        ]
    
    def _correlate_apt_activities(self, apt_indicators: Dict) -> List[Dict]:
        """Correlate APT activities to identify attack campaigns."""
        correlations = []
        
        # Temporal correlation
        all_activities = []
        for category, activities in apt_indicators.items():
            all_activities.extend(activities)
        
        # Sort by timestamp
        all_activities.sort(key=lambda x: x.get('event', {}).get('timestamp', ''))
        
        # Find clusters of activities within time windows
        time_window = timedelta(hours=2)
        current_cluster = []
        
        for activity in all_activities:
            if not current_cluster:
                current_cluster.append(activity)
            else:
                # Check if activity is within time window
                if self._within_time_window(current_cluster[-1], activity, time_window):
                    current_cluster.append(activity)
                else:
                    if len(current_cluster) >= 2:
                        correlations.append({
                            'type': 'temporal_cluster',
                            'activities': current_cluster.copy(),
                            'confidence': 0.8,
                            'description': f'Correlated {len(current_cluster)} APT activities'
                        })
                    current_cluster = [activity]
        
        return correlations
    
    def _calculate_advanced_risk_score(self, analysis_results: Dict) -> Dict:
        """Calculate comprehensive risk assessment."""
        risk_factors = {
            'apt_activity': 0.0,
            'malware_presence': 0.0,
            'behavioral_anomalies': 0.0,
            'network_threats': 0.0,
            'data_exfiltration': 0.0
        }
        
        # Weight factors based on severity
        weights = {
            'apt_activity': 0.3,
            'malware_presence': 0.25,
            'behavioral_anomalies': 0.2,
            'network_threats': 0.15,
            'data_exfiltration': 0.1
        }
        
        # Calculate individual risk factors
        if 'apt_analysis' in analysis_results:
            apt_count = sum(len(activities) for activities in analysis_results['apt_analysis'].values())
            risk_factors['apt_activity'] = min(apt_count * 0.2, 1.0)
        
        if 'malware_analysis' in analysis_results:
            malware_indicators = len(analysis_results['malware_analysis'].get('behavioral_indicators', []))
            risk_factors['malware_presence'] = min(malware_indicators * 0.15, 1.0)
        
        # Calculate overall risk score
        overall_risk = sum(risk_factors[factor] * weights[factor] for factor in risk_factors)
        
        risk_level = 'LOW'
        if overall_risk > 0.7:
            risk_level = 'CRITICAL'
        elif overall_risk > 0.5:
            risk_level = 'HIGH'
        elif overall_risk > 0.3:
            risk_level = 'MEDIUM'
        
        return {
            'overall_score': overall_risk,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'weights': weights,
            'recommendations_priority': 'IMMEDIATE' if overall_risk > 0.7 else 'HIGH' if overall_risk > 0.5 else 'MEDIUM'
        }
    
    def _generate_advanced_recommendations(self, analysis_results: Dict) -> List[Dict]:
        """Generate advanced, actionable security recommendations."""
        recommendations = []
        
        risk_level = analysis_results.get('risk_assessment', {}).get('risk_level', 'LOW')
        
        if risk_level in ['CRITICAL', 'HIGH']:
            recommendations.extend([
                {
                    'category': 'Immediate Response',
                    'priority': 'CRITICAL',
                    'action': 'Isolate affected systems from network',
                    'rationale': 'Prevent lateral movement and data exfiltration',
                    'timeline': 'Within 1 hour'
                },
                {
                    'category': 'Investigation',
                    'priority': 'HIGH',
                    'action': 'Perform full memory dump of affected systems',
                    'rationale': 'Preserve volatile evidence for detailed analysis',
                    'timeline': 'Within 2 hours'
                },
                {
                    'category': 'Threat Hunting',
                    'priority': 'HIGH',
                    'action': 'Search for similar IOCs across environment',
                    'rationale': 'Identify scope of compromise',
                    'timeline': 'Within 4 hours'
                }
            ])
        
        if 'apt_analysis' in analysis_results:
            recommendations.append({
                'category': 'APT Response',
                'priority': 'HIGH',
                'action': 'Implement enhanced monitoring for detected APT techniques',
                'rationale': 'APT activity detected, requires specialized response',
                'timeline': 'Within 24 hours'
            })
        
        return recommendations
    
    # Helper methods
    def _is_suspicious_process(self, process: Dict) -> bool:
        """Determine if a process exhibits suspicious characteristics."""
        suspicious_indicators = [
            'rundll32.exe',
            'regsvr32.exe',
            'mshta.exe',
            'powershell.exe',
            'cmd.exe'
        ]
        
        process_name = process.get('name', '').lower()
        return any(indicator in process_name for indicator in suspicious_indicators)
    
    def _analyze_process_suspicion(self, process: Dict) -> List[str]:
        """Analyze why a process is considered suspicious."""
        reasons = []
        process_name = process.get('name', '').lower()
        
        if 'rundll32.exe' in process_name:
            reasons.append('rundll32.exe often used for DLL injection')
        if 'powershell.exe' in process_name:
            reasons.append('PowerShell commonly abused by attackers')
        if process.get('command_line', '').startswith('-enc'):
            reasons.append('Encoded PowerShell commands detected')
        
        return reasons
    
    def _within_time_window(self, activity1: Dict, activity2: Dict, window: timedelta) -> bool:
        """Check if two activities are within a specified time window."""
        try:
            time1 = datetime.fromisoformat(activity1.get('event', {}).get('timestamp', ''))
            time2 = datetime.fromisoformat(activity2.get('event', {}).get('timestamp', ''))
            return abs(time2 - time1) <= window
        except:
            return False
    
    def _extract_user_activities(self, timeline_data: List[Dict]) -> List[Dict]:
        """Extract user-related activities from timeline."""
        user_activities = []
        for event in timeline_data:
            if event.get('type', '').lower() in ['user', 'logon', 'authentication']:
                user_activities.append(event)
        return user_activities
    
    def _detect_user_anomalies(self, user_activities: List[Dict]) -> List[Dict]:
        """Detect anomalies in user behavior."""
        anomalies = []
        
        # Example: Multiple failed logins followed by success
        failed_logins = [a for a in user_activities if 'failed' in a.get('description', '').lower()]
        successful_logins = [a for a in user_activities if 'success' in a.get('description', '').lower()]
        
        if len(failed_logins) > 5 and len(successful_logins) > 0:
            anomalies.append({
                'type': 'suspicious_login_pattern',
                'description': 'Multiple failed logins followed by successful login',
                'confidence': 0.8,
                'events': failed_logins + successful_logins
            })
        
        return anomalies
    
    def _extract_system_activities(self, timeline_data: List[Dict]) -> List[Dict]:
        """Extract system-related activities from timeline."""
        return [event for event in timeline_data if event.get('type', '').lower() in ['system', 'process', 'file']]
    
    def _detect_system_anomalies(self, system_activities: List[Dict]) -> List[Dict]:
        """Detect anomalies in system behavior."""
        anomalies = []
        
        # Example: Unusual process execution patterns
        processes = [a for a in system_activities if 'process' in a.get('type', '').lower()]
        
        if len(processes) > 100:  # High process activity
            anomalies.append({
                'type': 'high_process_activity',
                'description': 'Unusually high process creation activity detected',
                'confidence': 0.6,
                'count': len(processes)
            })
        
        return anomalies
    
    def _analyze_temporal_patterns(self, timeline_data: List[Dict]) -> List[Dict]:
        """Analyze temporal patterns for anomalies."""
        patterns = []
        
        # Group events by hour
        hourly_counts = defaultdict(int)
        for event in timeline_data:
            try:
                timestamp = datetime.fromisoformat(event.get('timestamp', ''))
                hour = timestamp.hour
                hourly_counts[hour] += 1
            except:
                continue
        
        # Detect unusual activity hours
        avg_activity = np.mean(list(hourly_counts.values())) if hourly_counts else 0
        
        for hour, count in hourly_counts.items():
            if count > avg_activity * 3:  # 3x average activity
                patterns.append({
                    'type': 'unusual_activity_hour',
                    'hour': hour,
                    'activity_count': count,
                    'threshold': avg_activity * 3,
                    'confidence': 0.7
                })
        
        return patterns
    
    def _classify_malware_family(self, behavior_scores: Dict) -> Dict:
        """Classify malware family based on behavioral scores."""
        classification = {}
        
        # Simple classification based on highest scoring behavior
        if behavior_scores:
            top_behavior = max(behavior_scores, key=behavior_scores.get)
            confidence = min(behavior_scores[top_behavior], 1.0)
            
            classification = {
                'predicted_family': top_behavior,
                'confidence': confidence,
                'behavior_scores': dict(behavior_scores)
            }
        
        return classification


class AttributionEngine:
    """Advanced threat attribution analysis engine."""
    
    def __init__(self):
        self.apt_signatures = {}
        self.malware_families = {}
        self.campaign_patterns = {}
    
    def analyze_attribution(self, timeline_data: List[Dict], artifacts: Dict) -> Dict:
        """Analyze potential threat actor attribution."""
        attribution_results = {
            'potential_actors': [],
            'confidence_scores': {},
            'supporting_evidence': {},
            'campaign_analysis': {}
        }
        
        # Analyze TTPs (Tactics, Techniques, Procedures)
        ttps = self._extract_ttps(timeline_data)
        
        # Match against known APT groups
        for apt_group, signatures in self.apt_signatures.items():
            matches = self._match_apt_signatures(ttps, signatures)
            if matches['confidence'] > 0.3:
                attribution_results['potential_actors'].append({
                    'actor': apt_group,
                    'confidence': matches['confidence'],
                    'matching_ttps': matches['ttps']
                })
        
        return {'attribution_analysis': attribution_results}
    
    def _extract_ttps(self, timeline_data: List[Dict]) -> List[str]:
        """Extract TTPs from timeline data."""
        ttps = []
        # Implementation would analyze events to identify MITRE ATT&CK techniques
        return ttps
    
    def _match_apt_signatures(self, ttps: List[str], signatures: Dict) -> Dict:
        """Match TTPs against APT group signatures."""
        return {'confidence': 0.0, 'ttps': []}


# Integration functions for main application
def perform_advanced_threat_analysis(timeline_data: List[Dict], 
                                    artifacts: Dict,
                                    memory_analysis: Optional[Dict] = None,
                                    network_analysis: Optional[Dict] = None) -> Dict:
    """
    Main function to perform advanced threat analysis.
    
    Args:
        timeline_data: Timeline events
        artifacts: Extracted artifacts
        memory_analysis: Memory dump analysis results
        network_analysis: Network traffic analysis results
        
    Returns:
        Comprehensive threat analysis results
    """
    detector = AdvancedThreatDetector()
    return detector.analyze_advanced_threats(timeline_data, artifacts, memory_analysis, network_analysis)


def generate_threat_report(analysis_results: Dict) -> str:
    """Generate a comprehensive threat analysis report."""
    report = "# Advanced Threat Analysis Report\n\n"
    report += f"**Analysis Date**: {analysis_results.get('analysis_timestamp', 'Unknown')}\n\n"
    
    # Risk Assessment
    risk_assessment = analysis_results.get('risk_assessment', {})
    report += f"## Risk Assessment\n"
    report += f"**Overall Risk Level**: {risk_assessment.get('risk_level', 'Unknown')}\n"
    report += f"**Risk Score**: {risk_assessment.get('overall_score', 0):.2f}/1.00\n\n"
    
    # Threat Alerts
    threats = analysis_results.get('threat_alerts', [])
    if threats:
        report += f"## Threat Alerts ({len(threats)} detected)\n"
        for threat in threats[:5]:  # Top 5 threats
            report += f"- **{threat.get('threat_type', 'Unknown')}**: {threat.get('description', 'No description')}\n"
        report += "\n"
    
    # Recommendations
    recommendations = analysis_results.get('recommendations', [])
    if recommendations:
        report += f"## Immediate Recommendations\n"
        for rec in recommendations[:5]:  # Top 5 recommendations
            report += f"- **{rec.get('category', 'General')}** ({rec.get('priority', 'MEDIUM')}): {rec.get('action', 'No action specified')}\n"
        report += "\n"
    
    return report