"""
Timeline processing and analysis module
"""

from datetime import datetime, timezone
import json
from collections import defaultdict
import re


class TimelineProcessor:
    """Class for processing and analyzing timeline events."""
    
    def __init__(self):
        self.event_types = set()
        self.sources = set()
        
    def process_events(self, events):
        """Process and normalize events for timeline display.
        
        Args:
            events: List of events from various sources
            
        Returns:
            List of processed and normalized events
        """
        processed_events = []
        
        for event in events:
            processed_event = self._normalize_event(event)
            if processed_event:
                processed_events.append(processed_event)
                
        # Sort by timestamp
        processed_events.sort(key=lambda x: self._get_timestamp_for_sort(x), reverse=True)
        
        # Update known types and sources
        self._update_metadata(processed_events)
        
        return processed_events
        
    def _normalize_event(self, event):
        """Normalize an event to standard format."""
        try:
            # Ensure required fields exist
            normalized = {
                'timestamp': event.get('timestamp', datetime.now().isoformat()),
                'type': event.get('type', 'Unknown'),
                'source': event.get('source', 'Unknown'),
                'description': event.get('description', event.get('message', 'No description')),
                'details': event.get('details', ''),
                'level': event.get('level', 'INFO'),
                'event_id': event.get('event_id', ''),
                'raw_data': event  # Keep original event data
            }
            
            # Add additional fields if present
            for key, value in event.items():
                if key not in normalized:
                    normalized[key] = value
                    
            return normalized
            
        except Exception as e:
            print(f"Error normalizing event: {e}")
            return None
            
    def _get_timestamp_for_sort(self, event):
        """Get timestamp for sorting purposes."""
        try:
            timestamp_str = event.get('timestamp', '')
            if timestamp_str:
                # Handle various timestamp formats
                if 'T' in timestamp_str:
                    # ISO format
                    return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                else:
                    # Try parsing as various formats
                    formats = [
                        '%Y-%m-%d %H:%M:%S',
                        '%m/%d/%Y %H:%M:%S',
                        '%d/%m/%Y %H:%M:%S'
                    ]
                    
                    for fmt in formats:
                        try:
                            return datetime.strptime(timestamp_str, fmt)
                        except ValueError:
                            continue
                            
        except Exception as e:
            print(f"Error parsing timestamp for sorting: {e}")
            
        return datetime.min  # Default for unparseable timestamps
        
    def _update_metadata(self, events):
        """Update metadata about available event types and sources."""
        self.event_types.clear()
        self.sources.clear()
        
        for event in events:
            self.event_types.add(event.get('type', 'Unknown'))
            self.sources.add(event.get('source', 'Unknown'))
            
    def filter_events(self, events, start_date=None, end_date=None, event_type=None, 
                     source=None, search_text=None, case_sensitive=False):
        """Filter events based on criteria.
        
        Args:
            events: List of events to filter
            start_date: Start date for filtering
            end_date: End date for filtering
            event_type: Event type to filter by
            source: Source to filter by
            search_text: Text to search for
            case_sensitive: Whether search should be case sensitive
            
        Returns:
            List of filtered events
        """
        filtered_events = []
        
        for event in events:
            if self._event_matches_filters(event, start_date, end_date, event_type, 
                                         source, search_text, case_sensitive):
                filtered_events.append(event)
                
        return filtered_events
        
    def _event_matches_filters(self, event, start_date, end_date, event_type, 
                              source, search_text, case_sensitive):
        """Check if event matches all filter criteria."""
        try:
            # Date filter
            if start_date or end_date:
                event_time = self._get_timestamp_for_sort(event)
                
                if start_date and event_time < start_date:
                    return False
                if end_date and event_time > end_date:
                    return False
                    
            # Type filter
            if event_type and event.get('type') != event_type:
                return False
                
            # Source filter  
            if source and event.get('source') != source:
                return False
                
            # Text search
            if search_text:
                search_fields = [
                    event.get('description', ''),
                    event.get('message', ''),
                    event.get('details', ''),
                    event.get('type', ''),
                    event.get('source', '')
                ]
                
                search_content = ' '.join(str(field) for field in search_fields)
                
                if not case_sensitive:
                    search_text = search_text.lower()
                    search_content = search_content.lower()
                    
                if search_text not in search_content:
                    return False
                    
        except Exception as e:
            print(f"Error applying filters to event: {e}")
            return False
            
        return True
        
    def merge_timelines(self, *timeline_lists):
        """Merge multiple timeline lists into a single chronological timeline.
        
        Args:
            *timeline_lists: Variable number of event lists to merge
            
        Returns:
            Merged and sorted list of events
        """
        merged_events = []
        
        for timeline in timeline_lists:
            if timeline:
                merged_events.extend(timeline)
                
        # Remove duplicates based on unique key
        unique_events = {}
        for event in merged_events:
            # Create unique key from timestamp, type, and source
            key = f"{event.get('timestamp')}_{event.get('type')}_{event.get('source')}_{event.get('event_id', '')}"
            if key not in unique_events:
                unique_events[key] = event
                
        # Sort merged events
        sorted_events = sorted(unique_events.values(), 
                             key=lambda x: self._get_timestamp_for_sort(x), 
                             reverse=True)
        
        return sorted_events
        
    def analyze_timeline(self, events):
        """Analyze timeline for patterns and statistics.
        
        Args:
            events: List of events to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        if not events:
            return {}
            
        analysis = {
            'total_events': len(events),
            'date_range': self._get_date_range(events),
            'event_types': self._analyze_event_types(events),
            'sources': self._analyze_sources(events),
            'temporal_distribution': self._analyze_temporal_distribution(events),
            'activity_patterns': self._analyze_activity_patterns(events),
            'anomalies': self._detect_anomalies(events)
        }
        
        return analysis
        
    def _get_date_range(self, events):
        """Get date range of events."""
        try:
            timestamps = [self._get_timestamp_for_sort(event) for event in events]
            valid_timestamps = [ts for ts in timestamps if ts != datetime.min]
            
            if valid_timestamps:
                return {
                    'start': min(valid_timestamps).isoformat(),
                    'end': max(valid_timestamps).isoformat(),
                    'span_hours': (max(valid_timestamps) - min(valid_timestamps)).total_seconds() / 3600
                }
        except Exception as e:
            print(f"Error calculating date range: {e}")
            
        return {'start': None, 'end': None, 'span_hours': 0}
        
    def _analyze_event_types(self, events):
        """Analyze distribution of event types."""
        type_counts = defaultdict(int)
        
        for event in events:
            event_type = event.get('type', 'Unknown')
            type_counts[event_type] += 1
            
        return dict(sorted(type_counts.items(), key=lambda x: x[1], reverse=True))
        
    def _analyze_sources(self, events):
        """Analyze distribution of event sources."""
        source_counts = defaultdict(int)
        
        for event in events:
            source = event.get('source', 'Unknown')
            source_counts[source] += 1
            
        return dict(sorted(source_counts.items(), key=lambda x: x[1], reverse=True))
        
    def _analyze_temporal_distribution(self, events):
        """Analyze temporal distribution of events."""
        hourly_counts = defaultdict(int)
        daily_counts = defaultdict(int)
        
        for event in events:
            try:
                timestamp = self._get_timestamp_for_sort(event)
                if timestamp != datetime.min:
                    hour_key = timestamp.strftime('%H:00')
                    day_key = timestamp.strftime('%Y-%m-%d')
                    
                    hourly_counts[hour_key] += 1
                    daily_counts[day_key] += 1
                    
            except Exception as e:
                continue
                
        return {
            'hourly': dict(sorted(hourly_counts.items())),
            'daily': dict(sorted(daily_counts.items()))
        }
        
    def _analyze_activity_patterns(self, events):
        """Analyze activity patterns."""
        patterns = {
            'peak_hours': [],
            'quiet_periods': [],
            'event_clusters': []
        }
        
        try:
            # Find peak activity hours
            temporal_dist = self._analyze_temporal_distribution(events)
            hourly = temporal_dist.get('hourly', {})
            
            if hourly:
                max_count = max(hourly.values())
                avg_count = sum(hourly.values()) / len(hourly)
                
                patterns['peak_hours'] = [hour for hour, count in hourly.items() 
                                        if count >= avg_count * 1.5]
                patterns['quiet_periods'] = [hour for hour, count in hourly.items() 
                                           if count <= avg_count * 0.5]
                
        except Exception as e:
            print(f"Error analyzing activity patterns: {e}")
            
        return patterns
        
    def _detect_anomalies(self, events):
        """Detect potential anomalies in the timeline."""
        anomalies = []
        
        try:
            # Check for suspicious login patterns
            anomalies.extend(self._detect_login_anomalies(events))
            
            # Check for unusual file access patterns
            anomalies.extend(self._detect_file_anomalies(events))
            
            # Check for network anomalies
            anomalies.extend(self._detect_network_anomalies(events))
            
        except Exception as e:
            print(f"Error detecting anomalies: {e}")
            
        return anomalies
        
    def _detect_login_anomalies(self, events):
        """Detect suspicious login patterns."""
        anomalies = []
        
        login_events = [e for e in events if 'login' in e.get('type', '').lower() or 
                       'logon' in e.get('message', '').lower()]
        
        failed_logins = [e for e in login_events if 'failed' in e.get('message', '').lower()]
        
        # Check for brute force attempts
        if len(failed_logins) > 10:
            anomalies.append({
                'type': 'Potential Brute Force',
                'description': f'{len(failed_logins)} failed login attempts detected',
                'severity': 'HIGH',
                'events_count': len(failed_logins)
            })
            
        return anomalies
        
    def _detect_file_anomalies(self, events):
        """Detect suspicious file access patterns."""
        anomalies = []
        
        file_events = [e for e in events if 'file' in e.get('type', '').lower()]
        
        # Check for mass file access
        if len(file_events) > 100:
            anomalies.append({
                'type': 'Mass File Access',
                'description': f'{len(file_events)} file access events detected',
                'severity': 'MEDIUM',
                'events_count': len(file_events)
            })
            
        return anomalies
        
    def _detect_network_anomalies(self, events):
        """Detect network-related anomalies.""" 
        anomalies = []
        
        network_events = [e for e in events if any(keyword in e.get('type', '').lower() 
                                                 for keyword in ['browser', 'wifi', 'network'])]
        
        # Check for unusual network activity
        unique_domains = set()
        for event in network_events:
            domain = event.get('domain') or event.get('url', '')
            if domain:
                unique_domains.add(domain)
                
        if len(unique_domains) > 50:
            anomalies.append({
                'type': 'High Network Activity',
                'description': f'Access to {len(unique_domains)} unique domains detected',
                'severity': 'LOW',
                'domains_count': len(unique_domains)
            })
            
        return anomalies
        
    def export_timeline(self, events, format='json'):
        """Export timeline in various formats.
        
        Args:
            events: List of events to export
            format: Export format ('json', 'csv', 'html')
            
        Returns:
            String representation of exported timeline
        """
        if format.lower() == 'json':
            return self._export_json(events)
        elif format.lower() == 'csv':
            return self._export_csv(events)
        elif format.lower() == 'html':
            return self._export_html(events)
        else:
            raise ValueError(f"Unsupported export format: {format}")
            
    def _export_json(self, events):
        """Export timeline as JSON."""
        export_data = {
            'metadata': {
                'export_time': datetime.now().isoformat(),
                'total_events': len(events),
                'date_range': self._get_date_range(events)
            },
            'events': events
        }
        
        return json.dumps(export_data, indent=2, default=str)
        
    def _export_csv(self, events):
        """Export timeline as CSV."""
        import csv
        import io
        
        output = io.StringIO()
        
        if events:
            # Get all unique field names
            fieldnames = set()
            for event in events:
                fieldnames.update(event.keys())
                
            fieldnames = sorted(fieldnames)
            
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for event in events:
                # Convert complex objects to strings
                row = {}
                for field in fieldnames:
                    value = event.get(field, '')
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value)
                    row[field] = str(value)
                writer.writerow(row)
                
        return output.getvalue()
        
    def _export_html(self, events):
        """Export timeline as HTML."""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>InvestiGUI Timeline Export</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 10px; border-radius: 5px; margin-bottom: 20px; }}
                .event {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; border-radius: 5px; }}
                .event-header {{ font-weight: bold; color: #333; }}
                .event-details {{ margin-top: 5px; color: #666; }}
                .timestamp {{ color: #007acc; }}
                .type {{ color: #28a745; }}
                .source {{ color: #6f42c1; }}
                .level-ERROR {{ border-left: 4px solid #dc3545; }}
                .level-WARNING {{ border-left: 4px solid #ffc107; }}
                .level-INFO {{ border-left: 4px solid #007bff; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>InvestiGUI Timeline Export</h1>
                <p>Generated: {export_time}</p>
                <p>Total Events: {total_events}</p>
            </div>
        """
        
        for event in events:
            level_class = f"level-{event.get('level', 'INFO')}"
            
            html_template += f"""
            <div class="event {level_class}">
                <div class="event-header">
                    <span class="timestamp">{event.get('timestamp', 'Unknown')}</span> -
                    <span class="type">{event.get('type', 'Unknown')}</span> -
                    <span class="source">{event.get('source', 'Unknown')}</span>
                </div>
                <div class="event-details">
                    <strong>Description:</strong> {event.get('description', 'No description')}<br>
                    <strong>Details:</strong> {event.get('details', 'No details')}
                </div>
            </div>
            """
            
        html_template += """
        </body>
        </html>
        """
        
        return html_template.format(
            export_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_events=len(events)
        )