"""
Machine Learning and Anomaly Detection Module
Advanced ML-based analysis for detecting suspicious patterns and anomalies.
"""

import os
import json
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from collections import defaultdict, Counter
import re
import hashlib

# Try to import numpy, fallback if not available
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    # Create basic numpy-like functions for compatibility
    class _NumpyCompat:
        @staticmethod
        def mean(data):
            return sum(data) / len(data) if data else 0
        
        @staticmethod  
        def std(data):
            if not data:
                return 0
            mean_val = sum(data) / len(data)
            variance = sum((x - mean_val) ** 2 for x in data) / len(data)
            return variance ** 0.5
    
    np = _NumpyCompat()


class AnomalyDetector:
    """Machine learning-based anomaly detection for digital forensics."""
    
    def __init__(self):
        self.models_trained = False
        self.baseline_patterns = {}
        self.anomaly_threshold = 0.3
        self.feature_weights = {
            'temporal': 0.3,
            'frequency': 0.25,
            'pattern': 0.25,
            'context': 0.2
        }
        
    def analyze_timeline_anomalies(self, timeline_data: List[Dict]) -> Dict:
        """
        Analyze timeline data for anomalies using ML techniques.
        
        Args:
            timeline_data: List of timeline events
            
        Returns:
            Dictionary containing anomaly analysis results
        """
        if not timeline_data:
            return {'error': 'No timeline data provided'}
        
        results = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_events': len(timeline_data),
            'anomalies_detected': [],
            'pattern_analysis': {},
            'behavioral_analysis': {},
            'risk_scoring': {},
            'recommendations': []
        }
        
        # Extract features from timeline data
        features = self._extract_features(timeline_data)
        
        # Detect temporal anomalies
        temporal_anomalies = self._detect_temporal_anomalies(timeline_data, features)
        results['anomalies_detected'].extend(temporal_anomalies)
        
        # Detect frequency anomalies
        frequency_anomalies = self._detect_frequency_anomalies(timeline_data, features)
        results['anomalies_detected'].extend(frequency_anomalies)
        
        # Detect pattern anomalies
        pattern_anomalies = self._detect_pattern_anomalies(timeline_data, features)
        results['anomalies_detected'].extend(pattern_anomalies)
        
        # Analyze behavioral patterns
        results['behavioral_analysis'] = self._analyze_behavioral_patterns(timeline_data, features)
        
        # Generate risk scores
        results['risk_scoring'] = self._calculate_risk_scores(timeline_data, results['anomalies_detected'])
        
        # Generate recommendations
        results['recommendations'] = self._generate_ml_recommendations(results)
        
        return results
    
    def _extract_features(self, timeline_data: List[Dict]) -> Dict:
        """Extract features from timeline data for ML analysis."""
        features = {
            'temporal_features': {},
            'frequency_features': {},
            'text_features': {},
            'categorical_features': {}
        }
        
        # Temporal features
        timestamps = []
        for event in timeline_data:
            try:
                timestamp = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
                timestamps.append(timestamp)
            except:
                continue
        
        if timestamps:
            features['temporal_features'] = {
                'time_range': (min(timestamps), max(timestamps)),
                'duration_hours': (max(timestamps) - min(timestamps)).total_seconds() / 3600,
                'events_per_hour': len(timestamps) / max(1, (max(timestamps) - min(timestamps)).total_seconds() / 3600),
                'hour_distribution': self._get_hour_distribution(timestamps),
                'day_distribution': self._get_day_distribution(timestamps),
                'time_gaps': self._calculate_time_gaps(timestamps)
            }
        
        # Frequency features
        event_types = [event.get('type', 'Unknown') for event in timeline_data]
        sources = [event.get('source', 'Unknown') for event in timeline_data]
        severities = [event.get('severity', 'Info') for event in timeline_data]
        
        features['frequency_features'] = {
            'event_type_counts': Counter(event_types),
            'source_counts': Counter(sources),
            'severity_counts': Counter(severities),
            'unique_event_types': len(set(event_types)),
            'unique_sources': len(set(sources))
        }
        
        # Text features
        descriptions = [event.get('description', '') for event in timeline_data]
        features['text_features'] = {
            'description_lengths': [len(desc) for desc in descriptions],
            'common_keywords': self._extract_keywords(descriptions),
            'suspicious_patterns': self._find_suspicious_text_patterns(descriptions)
        }
        
        # Categorical features
        features['categorical_features'] = {
            'has_high_severity': any(sev in ['Critical', 'High'] for sev in severities),
            'multiple_sources': len(set(sources)) > 1,
            'network_activity': any('network' in etype.lower() for etype in event_types),
            'file_activity': any('file' in etype.lower() for etype in event_types)
        }
        
        return features
    
    def _detect_temporal_anomalies(self, timeline_data: List[Dict], features: Dict) -> List[Dict]:
        """Detect temporal anomalies in the timeline."""
        anomalies = []
        
        temporal_features = features.get('temporal_features', {})
        
        # Detect unusual time patterns
        hour_dist = temporal_features.get('hour_distribution', {})
        if hour_dist:
            # Check for significant after-hours activity (10 PM - 6 AM)
            after_hours_count = sum(count for hour, count in hour_dist.items() 
                                  if hour < 6 or hour > 22)
            total_events = sum(hour_dist.values())
            after_hours_ratio = after_hours_count / total_events if total_events > 0 else 0
            
            if after_hours_ratio > 0.3:  # More than 30% after hours
                anomalies.append({
                    'type': 'Temporal Anomaly',
                    'subtype': 'After Hours Activity',
                    'description': f'Unusual amount of after-hours activity detected ({after_hours_ratio:.1%} of events)',
                    'severity': 'Medium',
                    'confidence': min(after_hours_ratio * 2, 1.0),
                    'details': {
                        'after_hours_events': after_hours_count,
                        'total_events': total_events,
                        'ratio': after_hours_ratio
                    }
                })
        
        # Detect unusual event clustering
        time_gaps = temporal_features.get('time_gaps', [])
        if time_gaps:
            avg_gap = np.mean(time_gaps)
            std_gap = np.std(time_gaps)
            
            # Look for periods of very high activity (small gaps)
            burst_threshold = avg_gap - 2 * std_gap if std_gap > 0 else avg_gap * 0.1
            burst_count = sum(1 for gap in time_gaps if gap < burst_threshold)
            
            if burst_count > len(time_gaps) * 0.2:  # More than 20% are burst events
                anomalies.append({
                    'type': 'Temporal Anomaly',
                    'subtype': 'Event Bursting',
                    'description': f'Detected {burst_count} periods of unusually high activity',
                    'severity': 'Medium',
                    'confidence': min(burst_count / len(time_gaps) * 2, 1.0),
                    'details': {
                        'burst_events': burst_count,
                        'total_gaps': len(time_gaps),
                        'avg_gap_seconds': avg_gap
                    }
                })
        
        return anomalies
    
    def _detect_frequency_anomalies(self, timeline_data: List[Dict], features: Dict) -> List[Dict]:
        """Detect frequency-based anomalies."""
        anomalies = []
        
        freq_features = features.get('frequency_features', {})
        
        # Detect unusual event type frequencies
        event_type_counts = freq_features.get('event_type_counts', {})
        if event_type_counts:
            total_events = sum(event_type_counts.values())
            
            for event_type, count in event_type_counts.items():
                frequency = count / total_events
                
                # Flag event types that are unusually frequent
                if frequency > 0.5 and 'error' not in event_type.lower():
                    anomalies.append({
                        'type': 'Frequency Anomaly',
                        'subtype': 'Dominant Event Type',
                        'description': f'Event type "{event_type}" represents {frequency:.1%} of all events',
                        'severity': 'Medium',
                        'confidence': min(frequency * 1.5, 1.0),
                        'details': {
                            'event_type': event_type,
                            'count': count,
                            'frequency': frequency
                        }
                    })
        
        # Detect unusual severity distributions
        severity_counts = freq_features.get('severity_counts', {})
        if severity_counts:
            total_events = sum(severity_counts.values())
            critical_ratio = severity_counts.get('Critical', 0) / total_events
            high_ratio = severity_counts.get('High', 0) / total_events
            
            if critical_ratio > 0.1:  # More than 10% critical events
                anomalies.append({
                    'type': 'Frequency Anomaly',
                    'subtype': 'High Critical Event Rate',
                    'description': f'Unusually high rate of critical events ({critical_ratio:.1%})',
                    'severity': 'High',
                    'confidence': min(critical_ratio * 5, 1.0),
                    'details': {
                        'critical_events': severity_counts.get('Critical', 0),
                        'total_events': total_events,
                        'ratio': critical_ratio
                    }
                })
        
        return anomalies
    
    def _detect_pattern_anomalies(self, timeline_data: List[Dict], features: Dict) -> List[Dict]:
        """Detect pattern-based anomalies using text analysis."""
        anomalies = []
        
        text_features = features.get('text_features', {})
        
        # Analyze suspicious text patterns
        suspicious_patterns = text_features.get('suspicious_patterns', [])
        if suspicious_patterns:
            for pattern in suspicious_patterns:
                anomalies.append({
                    'type': 'Pattern Anomaly',
                    'subtype': 'Suspicious Text Pattern',
                    'description': f'Detected suspicious pattern: {pattern["pattern"]}',
                    'severity': pattern.get('severity', 'Medium'),
                    'confidence': pattern.get('confidence', 0.7),
                    'details': pattern
                })
        
        # Analyze description length anomalies
        desc_lengths = text_features.get('description_lengths', [])
        if desc_lengths:
            avg_length = np.mean(desc_lengths)
            std_length = np.std(desc_lengths)
            
            # Find unusually long descriptions
            long_threshold = avg_length + 2 * std_length
            long_descriptions = [l for l in desc_lengths if l > long_threshold]
            
            if len(long_descriptions) > len(desc_lengths) * 0.05:  # More than 5% are unusually long
                anomalies.append({
                    'type': 'Pattern Anomaly',
                    'subtype': 'Unusual Description Length',
                    'description': f'Detected {len(long_descriptions)} events with unusually long descriptions',
                    'severity': 'Low',
                    'confidence': 0.6,
                    'details': {
                        'long_descriptions': len(long_descriptions),
                        'avg_length': avg_length,
                        'threshold': long_threshold
                    }
                })
        
        return anomalies
    
    def _analyze_behavioral_patterns(self, timeline_data: List[Dict], features: Dict) -> Dict:
        """Analyze behavioral patterns in the data."""
        patterns = {
            'user_behavior': {},
            'system_behavior': {},
            'network_behavior': {},
            'file_system_behavior': {}
        }
        
        # Analyze user behavior patterns
        user_events = [e for e in timeline_data if 'user' in e.get('description', '').lower()]
        if user_events:
            patterns['user_behavior'] = {
                'total_user_events': len(user_events),
                'user_activity_ratio': len(user_events) / len(timeline_data),
                'common_user_actions': self._get_common_actions(user_events)
            }
        
        # Analyze system behavior patterns
        system_events = [e for e in timeline_data if any(keyword in e.get('type', '').lower() 
                        for keyword in ['system', 'process', 'service'])]
        if system_events:
            patterns['system_behavior'] = {
                'total_system_events': len(system_events),
                'system_activity_ratio': len(system_events) / len(timeline_data),
                'common_system_events': self._get_common_actions(system_events)
            }
        
        # Analyze network behavior patterns
        network_events = [e for e in timeline_data if 'network' in e.get('type', '').lower()]
        if network_events:
            patterns['network_behavior'] = {
                'total_network_events': len(network_events),
                'network_activity_ratio': len(network_events) / len(timeline_data),
                'network_patterns': self._analyze_network_patterns(network_events)
            }
        
        return patterns
    
    def _calculate_risk_scores(self, timeline_data: List[Dict], anomalies: List[Dict]) -> Dict:
        """Calculate risk scores based on detected anomalies."""
        risk_scores = {
            'overall_risk_score': 0,
            'temporal_risk': 0,
            'frequency_risk': 0,
            'pattern_risk': 0,
            'severity_breakdown': {},
            'confidence_weighted_score': 0
        }
        
        if not anomalies:
            return risk_scores
        
        # Calculate risk by type
        type_scores = defaultdict(float)
        severity_scores = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
        
        total_confidence_weight = 0
        confidence_weighted_sum = 0
        
        for anomaly in anomalies:
            anomaly_type = anomaly.get('subtype', anomaly.get('type', 'Unknown'))
            severity = anomaly.get('severity', 'Medium')
            confidence = anomaly.get('confidence', 0.5)
            
            base_score = severity_scores.get(severity, 4)
            weighted_score = base_score * confidence
            
            type_scores[anomaly_type] += weighted_score
            confidence_weighted_sum += weighted_score
            total_confidence_weight += confidence
        
        # Normalize scores
        if total_confidence_weight > 0:
            risk_scores['confidence_weighted_score'] = min(confidence_weighted_sum / total_confidence_weight, 10)
        
        # Calculate category risks
        temporal_types = ['After Hours Activity', 'Event Bursting']
        frequency_types = ['Dominant Event Type', 'High Critical Event Rate']
        pattern_types = ['Suspicious Text Pattern', 'Unusual Description Length']
        
        risk_scores['temporal_risk'] = min(sum(type_scores[t] for t in temporal_types) / 10, 10)
        risk_scores['frequency_risk'] = min(sum(type_scores[t] for t in frequency_types) / 10, 10)
        risk_scores['pattern_risk'] = min(sum(type_scores[t] for t in pattern_types) / 10, 10)
        
        # Overall risk score
        risk_scores['overall_risk_score'] = min(
            (risk_scores['temporal_risk'] + risk_scores['frequency_risk'] + risk_scores['pattern_risk']) / 3,
            10
        )
        
        # Severity breakdown
        severity_counts = defaultdict(int)
        for anomaly in anomalies:
            severity_counts[anomaly.get('severity', 'Medium')] += 1
        risk_scores['severity_breakdown'] = dict(severity_counts)
        
        return risk_scores
    
    def _generate_ml_recommendations(self, analysis_results: Dict) -> List[Dict]:
        """Generate ML-based recommendations."""
        recommendations = []
        
        risk_score = analysis_results.get('risk_scoring', {}).get('overall_risk_score', 0)
        anomalies = analysis_results.get('anomalies_detected', [])
        
        if risk_score > 7:
            recommendations.append({
                'priority': 'Critical',
                'category': 'Immediate Action',
                'recommendation': 'High-risk anomalies detected - immediate investigation required',
                'details': 'Multiple high-confidence anomalies suggest potential security incident'
            })
        elif risk_score > 4:
            recommendations.append({
                'priority': 'High',
                'category': 'Investigation',
                'recommendation': 'Moderate risk detected - thorough investigation recommended',
                'details': 'Anomaly patterns warrant deeper analysis'
            })
        
        # Specific recommendations based on anomaly types
        anomaly_types = [a.get('subtype', a.get('type', '')) for a in anomalies]
        
        if 'After Hours Activity' in anomaly_types:
            recommendations.append({
                'priority': 'Medium',
                'category': 'Policy Review',
                'recommendation': 'Review after-hours access policies and monitoring',
                'details': 'Unusual after-hours activity detected'
            })
        
        if 'High Critical Event Rate' in anomaly_types:
            recommendations.append({
                'priority': 'High',
                'category': 'System Health',
                'recommendation': 'Investigate system stability and security controls',
                'details': 'Elevated rate of critical events indicates potential issues'
            })
        
        if 'Suspicious Text Pattern' in anomaly_types:
            recommendations.append({
                'priority': 'High',
                'category': 'Threat Hunting',
                'recommendation': 'Conduct targeted threat hunting based on suspicious patterns',
                'details': 'Detected patterns may indicate malicious activity'
            })
        
        return recommendations
    
    # Helper methods
    def _get_hour_distribution(self, timestamps: List[datetime]) -> Dict[int, int]:
        """Get distribution of events by hour of day."""
        hour_counts = defaultdict(int)
        for timestamp in timestamps:
            hour_counts[timestamp.hour] += 1
        return dict(hour_counts)
    
    def _get_day_distribution(self, timestamps: List[datetime]) -> Dict[int, int]:
        """Get distribution of events by day of week."""
        day_counts = defaultdict(int)
        for timestamp in timestamps:
            day_counts[timestamp.weekday()] += 1
        return dict(day_counts)
    
    def _calculate_time_gaps(self, timestamps: List[datetime]) -> List[float]:
        """Calculate time gaps between consecutive events."""
        if len(timestamps) < 2:
            return []
        
        sorted_timestamps = sorted(timestamps)
        gaps = []
        for i in range(1, len(sorted_timestamps)):
            gap = (sorted_timestamps[i] - sorted_timestamps[i-1]).total_seconds()
            gaps.append(gap)
        
        return gaps
    
    def _extract_keywords(self, descriptions: List[str]) -> List[str]:
        """Extract common keywords from descriptions."""
        all_words = []
        for desc in descriptions:
            words = re.findall(r'\b[a-zA-Z]{3,}\b', desc.lower())
            all_words.extend(words)
        
        # Get most common words (excluding common stop words)
        stop_words = {'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'man', 'new', 'now', 'old', 'see', 'two', 'who', 'its', 'said', 'each', 'make', 'most', 'over', 'such', 'very', 'what', 'with'}
        filtered_words = [word for word in all_words if word not in stop_words]
        
        word_counts = Counter(filtered_words)
        return [word for word, count in word_counts.most_common(10)]
    
    def _find_suspicious_text_patterns(self, descriptions: List[str]) -> List[Dict]:
        """Find suspicious patterns in text descriptions."""
        suspicious_patterns = []
        
        # Define suspicious patterns
        patterns = [
            (r'powershell.*-enc', 'Encoded PowerShell', 'High'),
            (r'cmd\.exe.*\/c', 'Command Execution', 'Medium'),
            (r'rundll32.*\.dll', 'DLL Execution', 'Medium'),
            (r'schtasks.*\/create', 'Scheduled Task Creation', 'Medium'),
            (r'reg.*add.*HKCU.*Run', 'Registry Persistence', 'High'),
            (r'net.*user.*\/add', 'User Account Creation', 'Medium'),
            (r'wmic.*process.*call.*create', 'WMI Process Creation', 'Medium')
        ]
        
        for desc in descriptions:
            for pattern, description, severity in patterns:
                if re.search(pattern, desc, re.IGNORECASE):
                    suspicious_patterns.append({
                        'pattern': pattern,
                        'description': description,
                        'severity': severity,
                        'confidence': 0.8,
                        'matched_text': desc
                    })
        
        return suspicious_patterns
    
    def _get_common_actions(self, events: List[Dict]) -> List[str]:
        """Get most common actions from a list of events."""
        descriptions = [event.get('description', '') for event in events]
        keywords = self._extract_keywords(descriptions)
        return keywords[:5]  # Top 5 common actions
    
    def _analyze_network_patterns(self, network_events: List[Dict]) -> Dict:
        """Analyze patterns in network events."""
        patterns = {
            'connection_patterns': [],
            'protocol_distribution': {},
            'suspicious_indicators': []
        }
        
        # Simple analysis of network event descriptions
        for event in network_events:
            desc = event.get('description', '').lower()
            if 'connection' in desc:
                patterns['connection_patterns'].append(desc)
            if any(proto in desc for proto in ['tcp', 'udp', 'http', 'https']):
                # Extract protocol if mentioned
                for proto in ['tcp', 'udp', 'http', 'https']:
                    if proto in desc:
                        patterns['protocol_distribution'][proto] = patterns['protocol_distribution'].get(proto, 0) + 1
        
        return patterns


# Integration function
def perform_anomaly_detection(timeline_data: List[Dict]) -> Dict:
    """
    Perform anomaly detection on timeline data.
    
    Args:
        timeline_data: List of timeline events
        
    Returns:
        Dictionary containing anomaly detection results
    """
    detector = AnomalyDetector()
    return detector.analyze_timeline_anomalies(timeline_data)


def generate_ml_insights(timeline_data: List[Dict], artifacts: Dict) -> Dict:
    """
    Generate machine learning insights from forensic data.
    
    Args:
        timeline_data: Timeline events
        artifacts: Extracted artifacts
        
    Returns:
        Dictionary containing ML insights and recommendations
    """
    detector = AnomalyDetector()
    
    # Perform anomaly detection
    anomaly_results = detector.analyze_timeline_anomalies(timeline_data)
    
    # Additional ML insights
    insights = {
        'anomaly_detection': anomaly_results,
        'data_summary': {
            'total_events': len(timeline_data),
            'total_artifact_types': len(artifacts),
            'analysis_completeness': min(len(timeline_data) / 100, 1.0),  # Completeness score
        },
        'ml_recommendations': anomaly_results.get('recommendations', []),
        'confidence_metrics': {
            'overall_confidence': anomaly_results.get('risk_scoring', {}).get('confidence_weighted_score', 0) / 10,
            'detection_coverage': len(anomaly_results.get('anomalies_detected', [])) / max(1, len(timeline_data) / 10)
        }
    }
    
    return insights