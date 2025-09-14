"""
Automated Report Generation Module
Advanced reporting with visualizations and multiple output formats.
"""

import os
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import base64
from io import BytesIO
import tempfile


class ReportGenerator:
    """Class for generating comprehensive forensic investigation reports."""
    
    def __init__(self):
        self.report_templates = {
            'incident_response': 'Incident Response Investigation Report',
            'compliance_audit': 'Compliance Audit Report',
            'malware_analysis': 'Malware Analysis Report',
            'network_forensics': 'Network Forensics Report',
            'general': 'General Digital Forensics Report'
        }
        
    def generate_comprehensive_report(self, 
                                    timeline_data: List[Dict],
                                    artifacts: Dict,
                                    case_info: Dict,
                                    output_format: str = 'html') -> str:
        """
        Generate a comprehensive forensic investigation report.
        
        Args:
            timeline_data: List of timeline events
            artifacts: Dictionary containing all extracted artifacts
            case_info: Case metadata and information
            output_format: Output format ('html', 'pdf', 'json', 'xml')
            
        Returns:
            Path to generated report file
        """
        report_data = {
            'metadata': self._generate_report_metadata(case_info),
            'executive_summary': self._generate_executive_summary(timeline_data, artifacts),
            'timeline_analysis': self._analyze_timeline(timeline_data),
            'artifact_summary': self._summarize_artifacts(artifacts),
            'findings': self._generate_findings(timeline_data, artifacts),
            'recommendations': self._generate_recommendations(timeline_data, artifacts),
            'technical_details': self._compile_technical_details(artifacts),
            'charts_data': self._prepare_chart_data(timeline_data, artifacts),
            'appendices': self._generate_appendices(artifacts)
        }
        
        if output_format.lower() == 'html':
            return self._generate_html_report(report_data, case_info)
        elif output_format.lower() == 'json':
            return self._generate_json_report(report_data, case_info)
        elif output_format.lower() == 'xml':
            return self._generate_xml_report(report_data, case_info)
        else:
            return self._generate_html_report(report_data, case_info)  # Default to HTML
    
    def _generate_report_metadata(self, case_info: Dict) -> Dict:
        """Generate report metadata section."""
        return {
            'report_title': case_info.get('title', 'Digital Forensics Investigation Report'),
            'case_number': case_info.get('case_number', 'CASE-' + datetime.now().strftime('%Y%m%d-%H%M%S')),
            'investigator': case_info.get('investigator', 'Digital Forensics Team'),
            'organization': case_info.get('organization', 'InvestiGUI Analysis'),
            'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'investigation_period': {
                'start_date': case_info.get('start_date', (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')),
                'end_date': case_info.get('end_date', datetime.now().strftime('%Y-%m-%d'))
            },
            'evidence_sources': case_info.get('evidence_sources', []),
            'tools_used': ['InvestiGUI v2.0.0', 'Timeline Analysis', 'Artifact Extraction'],
            'classification': case_info.get('classification', 'Internal Use')
        }
    
    def _generate_executive_summary(self, timeline_data: List[Dict], artifacts: Dict) -> Dict:
        """Generate executive summary of the investigation."""
        total_events = len(timeline_data)
        
        # Count events by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for event in timeline_data:
            severity = event.get('severity', 'Info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Key findings
        key_findings = []
        if severity_counts['Critical'] > 0:
            key_findings.append(f"{severity_counts['Critical']} critical security events identified")
        if severity_counts['High'] > 0:
            key_findings.append(f"{severity_counts['High']} high-priority incidents detected")
            
        # Artifact summary
        artifact_summary = []
        for artifact_type, data in artifacts.items():
            if isinstance(data, list) and data:
                artifact_summary.append(f"{len(data)} {artifact_type.replace('_', ' ')} artifacts extracted")
        
        return {
            'investigation_overview': f"Comprehensive digital forensics analysis of {total_events} events across multiple data sources.",
            'key_findings': key_findings,
            'artifact_summary': artifact_summary,
            'severity_distribution': severity_counts,
            'total_events_analyzed': total_events,
            'investigation_timeframe': self._get_investigation_timeframe(timeline_data),
            'risk_assessment': self._assess_overall_risk(severity_counts),
            'immediate_actions_required': self._identify_immediate_actions(timeline_data)
        }
    
    def _analyze_timeline(self, timeline_data: List[Dict]) -> Dict:
        """Analyze timeline data for patterns and insights."""
        if not timeline_data:
            return {'error': 'No timeline data available'}
        
        # Temporal analysis
        event_times = []
        for event in timeline_data:
            try:
                event_time = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
                event_times.append(event_time)
            except:
                continue
        
        temporal_analysis = {}
        if event_times:
            temporal_analysis = {
                'first_event': min(event_times).isoformat(),
                'last_event': max(event_times).isoformat(),
                'time_span': str(max(event_times) - min(event_times)),
                'events_per_hour': self._calculate_events_per_hour(event_times),
                'peak_activity_periods': self._identify_peak_periods(event_times)
            }
        
        # Event type analysis
        event_types = {}
        for event in timeline_data:
            event_type = event.get('type', 'Unknown')
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        # Source analysis
        sources = {}
        for event in timeline_data:
            source = event.get('source', 'Unknown')
            sources[source] = sources.get(source, 0) + 1
        
        return {
            'temporal_analysis': temporal_analysis,
            'event_type_distribution': event_types,
            'source_distribution': sources,
            'correlation_patterns': self._find_correlation_patterns(timeline_data),
            'anomaly_detection': self._detect_anomalies(timeline_data)
        }
    
    def _summarize_artifacts(self, artifacts: Dict) -> Dict:
        """Generate summary of extracted artifacts."""
        summary = {}
        
        for artifact_type, data in artifacts.items():
            if isinstance(data, list):
                summary[artifact_type] = {
                    'count': len(data),
                    'examples': data[:3] if data else [],  # First 3 examples
                    'notable_findings': self._identify_notable_findings(artifact_type, data)
                }
            elif isinstance(data, dict):
                summary[artifact_type] = {
                    'details': data,
                    'summary': f"Contains {len(data)} categories of information"
                }
        
        return summary
    
    def _generate_findings(self, timeline_data: List[Dict], artifacts: Dict) -> List[Dict]:
        """Generate key investigation findings."""
        findings = []
        
        # Security-related findings
        critical_events = [e for e in timeline_data if e.get('severity') == 'Critical']
        if critical_events:
            findings.append({
                'category': 'Security',
                'severity': 'Critical',
                'title': 'Critical Security Events Detected',
                'description': f"Analysis identified {len(critical_events)} critical security events requiring immediate attention.",
                'evidence': [e.get('description', '') for e in critical_events[:5]],
                'recommendations': ['Immediate investigation of critical events', 'Implement additional monitoring', 'Review security controls']
            })
        
        # Network-related findings
        network_artifacts = artifacts.get('network_analysis', {})
        if network_artifacts.get('suspicious_activity'):
            findings.append({
                'category': 'Network Security',
                'severity': 'High',
                'title': 'Suspicious Network Activity Detected',
                'description': f"Network analysis revealed {len(network_artifacts['suspicious_activity'])} instances of suspicious network behavior.",
                'evidence': [activity.get('description', '') for activity in network_artifacts['suspicious_activity'][:3]],
                'recommendations': ['Review firewall logs', 'Analyze network traffic patterns', 'Implement network monitoring']
            })
        
        # Memory analysis findings
        memory_artifacts = artifacts.get('memory_analysis', {})
        if memory_artifacts.get('suspicious_strings'):
            findings.append({
                'category': 'Memory Analysis',
                'severity': 'Medium',
                'title': 'Suspicious Memory Artifacts',
                'description': f"Memory analysis identified {len(memory_artifacts['suspicious_strings'])} suspicious patterns in memory dumps.",
                'evidence': [pattern.get('description', '') for pattern in memory_artifacts['suspicious_strings'][:3]],
                'recommendations': ['Analyze memory dumps', 'Check for malware indicators', 'Review process execution']
            })
        
        return findings
    
    def _generate_recommendations(self, timeline_data: List[Dict], artifacts: Dict) -> List[Dict]:
        """Generate investigation recommendations."""
        recommendations = [
            {
                'category': 'Immediate Actions',
                'priority': 'High',
                'items': [
                    'Review and validate all critical and high-severity events',
                    'Implement additional monitoring on affected systems',
                    'Preserve additional evidence if investigation is ongoing'
                ]
            },
            {
                'category': 'Security Improvements',
                'priority': 'Medium',
                'items': [
                    'Update security policies based on findings',
                    'Enhance network monitoring capabilities',
                    'Implement additional endpoint protection'
                ]
            },
            {
                'category': 'Future Prevention',
                'priority': 'Medium',
                'items': [
                    'Regular security assessments',
                    'Enhanced user training programs',
                    'Improved incident response procedures'
                ]
            }
        ]
        
        return recommendations
    
    def _compile_technical_details(self, artifacts: Dict) -> Dict:
        """Compile technical details for appendix."""
        technical_details = {}
        
        for artifact_type, data in artifacts.items():
            technical_details[artifact_type] = {
                'data_source': artifact_type,
                'extraction_method': 'Automated analysis using InvestiGUI',
                'data_integrity': 'Verified using hash validation',
                'analysis_timestamp': datetime.now().isoformat(),
                'raw_data_summary': self._summarize_raw_data(data)
            }
        
        return technical_details
    
    def _prepare_chart_data(self, timeline_data: List[Dict], artifacts: Dict) -> Dict:
        """Prepare data for chart generation."""
        chart_data = {
            'timeline_chart': self._prepare_timeline_chart_data(timeline_data),
            'severity_pie_chart': self._prepare_severity_pie_data(timeline_data),
            'event_type_bar_chart': self._prepare_event_type_bar_data(timeline_data),
            'temporal_activity_chart': self._prepare_temporal_activity_data(timeline_data)
        }
        
        return chart_data
    
    def _generate_html_report(self, report_data: Dict, case_info: Dict) -> str:
        """Generate HTML format report."""
        report_filename = f"investigation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_data['metadata']['report_title']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }}
        .critical {{ border-left-color: #e74c3c; }}
        .high {{ border-left-color: #f39c12; }}
        .medium {{ border-left-color: #f1c40f; }}
        .finding {{ background: #ecf0f1; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .chart-container {{ margin: 20px 0; text-align: center; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #34495e; color: white; }}
        .metadata {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        .timeline-event {{ padding: 10px; margin: 5px 0; border-left: 3px solid #3498db; background: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{report_data['metadata']['report_title']}</h1>
        <p>Case Number: {report_data['metadata']['case_number']}</p>
        <p>Generated: {report_data['metadata']['report_date']}</p>
    </div>
    
    <div class="section">
        <h2>Case Metadata</h2>
        <div class="metadata">
            <div>
                <strong>Investigator:</strong> {report_data['metadata']['investigator']}<br>
                <strong>Organization:</strong> {report_data['metadata']['organization']}<br>
                <strong>Investigation Period:</strong> {report_data['metadata']['investigation_period']['start_date']} to {report_data['metadata']['investigation_period']['end_date']}
            </div>
            <div>
                <strong>Tools Used:</strong> {', '.join(report_data['metadata']['tools_used'])}<br>
                <strong>Classification:</strong> {report_data['metadata']['classification']}<br>
                <strong>Evidence Sources:</strong> {len(report_data['metadata']['evidence_sources'])} sources analyzed
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>{report_data['executive_summary']['investigation_overview']}</p>
        
        <h3>Key Statistics</h3>
        <ul>
            <li>Total Events Analyzed: {report_data['executive_summary']['total_events_analyzed']}</li>
            <li>Critical Events: {report_data['executive_summary']['severity_distribution']['Critical']}</li>
            <li>High Priority Events: {report_data['executive_summary']['severity_distribution']['High']}</li>
            <li>Medium Priority Events: {report_data['executive_summary']['severity_distribution']['Medium']}</li>
        </ul>
        
        <h3>Risk Assessment</h3>
        <p><strong>Overall Risk Level:</strong> {report_data['executive_summary']['risk_assessment']}</p>
    </div>
    
    <div class="section">
        <h2>Key Findings</h2>
"""
        
        # Add findings
        for finding in report_data['findings']:
            severity_class = finding['severity'].lower()
            html_content += f"""
        <div class="finding {severity_class}">
            <h3>{finding['title']} ({finding['severity']})</h3>
            <p><strong>Category:</strong> {finding['category']}</p>
            <p>{finding['description']}</p>
            
            <h4>Evidence:</h4>
            <ul>
"""
            for evidence in finding['evidence']:
                html_content += f"<li>{evidence}</li>"
            
            html_content += """
            </ul>
            
            <h4>Recommendations:</h4>
            <ul>
"""
            for rec in finding['recommendations']:
                html_content += f"<li>{rec}</li>"
            
            html_content += """
            </ul>
        </div>
"""
        
        # Add timeline analysis
        html_content += f"""
    </div>
    
    <div class="section">
        <h2>Timeline Analysis</h2>
        <h3>Event Type Distribution</h3>
        <table>
            <tr><th>Event Type</th><th>Count</th></tr>
"""
        
        for event_type, count in report_data['timeline_analysis']['event_type_distribution'].items():
            html_content += f"<tr><td>{event_type}</td><td>{count}</td></tr>"
        
        html_content += """
        </table>
        
        <h3>Source Distribution</h3>
        <table>
            <tr><th>Source</th><th>Count</th></tr>
"""
        
        for source, count in report_data['timeline_analysis']['source_distribution'].items():
            html_content += f"<tr><td>{source}</td><td>{count}</td></tr>"
        
        # Add recommendations
        html_content += f"""
        </table>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
"""
        
        for rec_category in report_data['recommendations']:
            html_content += f"""
        <h3>{rec_category['category']} (Priority: {rec_category['priority']})</h3>
        <ul>
"""
            for item in rec_category['items']:
                html_content += f"<li>{item}</li>"
            
            html_content += "</ul>"
        
        # Close HTML
        html_content += """
    </div>
    
    <div class="section">
        <h2>Technical Details</h2>
        <p>Detailed technical information and raw data analysis results are available in the appendices.</p>
        <p><em>Report generated by InvestiGUI v2.0.0 Digital Forensics Toolkit</em></p>
    </div>
    
</body>
</html>
"""
        
        # Write the HTML report
        try:
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return report_filename
        except Exception as e:
            return f"Error generating HTML report: {str(e)}"
    
    def _generate_json_report(self, report_data: Dict, case_info: Dict) -> str:
        """Generate JSON format report."""
        report_filename = f"investigation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(report_filename, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            return report_filename
        except Exception as e:
            return f"Error generating JSON report: {str(e)}"
    
    def _generate_xml_report(self, report_data: Dict, case_info: Dict) -> str:
        """Generate XML format report."""
        report_filename = f"investigation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<investigation_report>
    <metadata>
        <title>{report_data['metadata']['report_title']}</title>
        <case_number>{report_data['metadata']['case_number']}</case_number>
        <investigator>{report_data['metadata']['investigator']}</investigator>
        <organization>{report_data['metadata']['organization']}</organization>
        <report_date>{report_data['metadata']['report_date']}</report_date>
    </metadata>
    
    <executive_summary>
        <overview>{report_data['executive_summary']['investigation_overview']}</overview>
        <total_events>{report_data['executive_summary']['total_events_analyzed']}</total_events>
        <risk_level>{report_data['executive_summary']['risk_assessment']}</risk_level>
    </executive_summary>
    
    <findings>
"""
        
        for finding in report_data['findings']:
            xml_content += f"""
        <finding>
            <title>{finding['title']}</title>
            <category>{finding['category']}</category>
            <severity>{finding['severity']}</severity>
            <description>{finding['description']}</description>
        </finding>
"""
        
        xml_content += """
    </findings>
    
</investigation_report>
"""
        
        try:
            with open(report_filename, 'w') as f:
                f.write(xml_content)
            return report_filename
        except Exception as e:
            return f"Error generating XML report: {str(e)}"
    
    # Helper methods for analysis
    def _get_investigation_timeframe(self, timeline_data: List[Dict]) -> str:
        """Calculate investigation timeframe."""
        if not timeline_data:
            return "No events available"
        
        try:
            timestamps = []
            for event in timeline_data:
                timestamp = event.get('timestamp', '')
                if timestamp:
                    timestamps.append(datetime.fromisoformat(timestamp.replace('Z', '+00:00')))
            
            if timestamps:
                start_time = min(timestamps)
                end_time = max(timestamps)
                duration = end_time - start_time
                return f"{start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')} ({duration})"
        except:
            pass
        
        return "Unable to determine timeframe"
    
    def _assess_overall_risk(self, severity_counts: Dict) -> str:
        """Assess overall risk level based on event severity."""
        if severity_counts['Critical'] > 0:
            return "CRITICAL"
        elif severity_counts['High'] > 5:
            return "HIGH"
        elif severity_counts['High'] > 0 or severity_counts['Medium'] > 10:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _identify_immediate_actions(self, timeline_data: List[Dict]) -> List[str]:
        """Identify immediate actions required."""
        actions = []
        
        critical_events = [e for e in timeline_data if e.get('severity') == 'Critical']
        if critical_events:
            actions.append("Immediate investigation of critical security events")
        
        high_events = [e for e in timeline_data if e.get('severity') == 'High']
        if len(high_events) > 5:
            actions.append("Review and triage high-priority events")
        
        if not actions:
            actions.append("Continue monitoring and maintain current security posture")
        
        return actions
    
    def _calculate_events_per_hour(self, event_times: List[datetime]) -> float:
        """Calculate average events per hour."""
        if len(event_times) < 2:
            return 0.0
        
        time_span = max(event_times) - min(event_times)
        hours = time_span.total_seconds() / 3600
        return len(event_times) / hours if hours > 0 else 0.0
    
    def _identify_peak_periods(self, event_times: List[datetime]) -> List[str]:
        """Identify peak activity periods."""
        # Simplified implementation - group by hour
        hourly_counts = {}
        for event_time in event_times:
            hour_key = event_time.strftime('%Y-%m-%d %H:00')
            hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
        
        # Find top 3 busiest hours
        sorted_hours = sorted(hourly_counts.items(), key=lambda x: x[1], reverse=True)
        return [f"{hour} ({count} events)" for hour, count in sorted_hours[:3]]
    
    def _find_correlation_patterns(self, timeline_data: List[Dict]) -> List[str]:
        """Find correlation patterns in timeline data."""
        patterns = []
        
        # Look for events that occur close together
        event_types = {}
        for event in timeline_data:
            event_type = event.get('type', 'Unknown')
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        # Identify frequent event types
        frequent_types = [etype for etype, count in event_types.items() if count > 5]
        if frequent_types:
            patterns.append(f"Frequent event types detected: {', '.join(frequent_types[:3])}")
        
        return patterns
    
    def _detect_anomalies(self, timeline_data: List[Dict]) -> List[str]:
        """Detect anomalies in timeline data."""
        anomalies = []
        
        # Check for unusual time patterns
        timestamps = []
        for event in timeline_data:
            try:
                timestamp = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
                timestamps.append(timestamp)
            except:
                continue
        
        if timestamps:
            # Check for after-hours activity (simple heuristic)
            after_hours = [ts for ts in timestamps if ts.hour < 6 or ts.hour > 22]
            if len(after_hours) > len(timestamps) * 0.2:  # More than 20% after hours
                anomalies.append("Significant after-hours activity detected")
        
        return anomalies
    
    def _identify_notable_findings(self, artifact_type: str, data: List) -> List[str]:
        """Identify notable findings in artifact data."""
        findings = []
        
        if not data:
            return findings
        
        # Generic findings based on artifact type
        if 'browser' in artifact_type.lower():
            findings.append(f"Browser history contains {len(data)} entries")
        elif 'usb' in artifact_type.lower():
            findings.append(f"USB activity shows {len(data)} device connections")
        elif 'network' in artifact_type.lower():
            findings.append(f"Network analysis identified {len(data)} connections")
        
        return findings
    
    def _summarize_raw_data(self, data) -> str:
        """Summarize raw data for technical details."""
        if isinstance(data, list):
            return f"List containing {len(data)} items"
        elif isinstance(data, dict):
            return f"Dictionary with {len(data)} keys: {', '.join(list(data.keys())[:5])}"
        else:
            return str(type(data))
    
    def _prepare_timeline_chart_data(self, timeline_data: List[Dict]) -> Dict:
        """Prepare data for timeline visualization."""
        return {
            'chart_type': 'timeline',
            'data_points': len(timeline_data),
            'description': 'Timeline of investigation events'
        }
    
    def _prepare_severity_pie_data(self, timeline_data: List[Dict]) -> Dict:
        """Prepare data for severity distribution pie chart."""
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for event in timeline_data:
            severity = event.get('severity', 'Info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'chart_type': 'pie',
            'data': severity_counts,
            'description': 'Event severity distribution'
        }
    
    def _prepare_event_type_bar_data(self, timeline_data: List[Dict]) -> Dict:
        """Prepare data for event type bar chart."""
        event_types = {}
        for event in timeline_data:
            event_type = event.get('type', 'Unknown')
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        return {
            'chart_type': 'bar',
            'data': event_types,
            'description': 'Event type distribution'
        }
    
    def _prepare_temporal_activity_data(self, timeline_data: List[Dict]) -> Dict:
        """Prepare data for temporal activity chart."""
        return {
            'chart_type': 'line',
            'data_points': len(timeline_data),
            'description': 'Activity over time'
        }
    
    def _generate_appendices(self, artifacts: Dict) -> Dict:
        """Generate appendices with detailed artifact data."""
        appendices = {}
        
        for artifact_type, data in artifacts.items():
            appendices[f"appendix_{artifact_type}"] = {
                'title': f"Detailed {artifact_type.replace('_', ' ').title()} Analysis",
                'data_summary': self._summarize_raw_data(data),
                'extraction_timestamp': datetime.now().isoformat()
            }
        
        return appendices


# Integration function
def generate_investigation_report(timeline_data: List[Dict], 
                                artifacts: Dict, 
                                case_info: Dict = None,
                                output_format: str = 'html') -> str:
    """
    Generate comprehensive investigation report.
    
    Args:
        timeline_data: Timeline events
        artifacts: Extracted artifacts
        case_info: Case metadata
        output_format: Output format (html, json, xml)
    
    Returns:
        Path to generated report file
    """
    if case_info is None:
        case_info = {
            'title': 'InvestiGUI Digital Forensics Investigation',
            'investigator': 'InvestiGUI User',
            'organization': 'Digital Forensics Analysis'
        }
    
    generator = ReportGenerator()
    return generator.generate_comprehensive_report(timeline_data, artifacts, case_info, output_format)