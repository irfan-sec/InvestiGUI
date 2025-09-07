"""
Timeline Viewer Tab for InvestiGUI
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QGroupBox, QLabel, QMessageBox, QSplitter,
                             QComboBox, QDateTimeEdit, QLineEdit, QCheckBox)
from PyQt5.QtCore import Qt, QDateTime, QTimer
from PyQt5.QtGui import QFont

from ..widgets import DataTableWidget, ProgressWidget
from timeline import TimelineProcessor


class TimelineTab(QWidget):
    """Tab for timeline viewing and analysis."""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.timeline_processor = TimelineProcessor()
        self.filtered_events = []
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Timeline controls
        controls_group = QGroupBox("Timeline Controls")
        controls_layout = QVBoxLayout(controls_group)
        
        # Refresh and stats
        top_controls_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Refresh Timeline")
        self.refresh_button.clicked.connect(self.refresh_timeline)
        top_controls_layout.addWidget(self.refresh_button)
        
        top_controls_layout.addStretch()
        
        self.stats_label = QLabel("Events: 0")
        top_controls_layout.addWidget(self.stats_label)
        
        controls_layout.addLayout(top_controls_layout)
        
        # Filter controls
        filter_layout = QVBoxLayout()
        
        # Date range filter
        date_filter_layout = QHBoxLayout()
        date_filter_layout.addWidget(QLabel("Date Range:"))
        
        self.filter_start_date = QDateTimeEdit()
        self.filter_start_date.setDateTime(QDateTime.currentDateTime().addDays(-30))
        self.filter_start_date.dateTimeChanged.connect(self.apply_filters)
        date_filter_layout.addWidget(self.filter_start_date)
        
        date_filter_layout.addWidget(QLabel("to"))
        
        self.filter_end_date = QDateTimeEdit()
        self.filter_end_date.setDateTime(QDateTime.currentDateTime())
        self.filter_end_date.dateTimeChanged.connect(self.apply_filters)
        date_filter_layout.addWidget(self.filter_end_date)
        
        date_filter_layout.addStretch()
        filter_layout.addLayout(date_filter_layout)
        
        # Type and source filters
        type_filter_layout = QHBoxLayout()
        
        type_filter_layout.addWidget(QLabel("Type:"))
        self.type_filter_combo = QComboBox()
        self.type_filter_combo.addItem("All Types")
        self.type_filter_combo.currentTextChanged.connect(self.apply_filters)
        type_filter_layout.addWidget(self.type_filter_combo)
        
        type_filter_layout.addWidget(QLabel("Source:"))
        self.source_filter_combo = QComboBox()
        self.source_filter_combo.addItem("All Sources")
        self.source_filter_combo.currentTextChanged.connect(self.apply_filters)
        type_filter_layout.addWidget(self.source_filter_combo)
        
        type_filter_layout.addStretch()
        filter_layout.addLayout(type_filter_layout)
        
        # Text search
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search events...")
        self.search_input.textChanged.connect(self.apply_filters)
        search_layout.addWidget(self.search_input, 1)
        
        self.case_sensitive_check = QCheckBox("Case sensitive")
        self.case_sensitive_check.stateChanged.connect(self.apply_filters)
        search_layout.addWidget(self.case_sensitive_check)
        
        filter_layout.addLayout(search_layout)
        
        controls_layout.addLayout(filter_layout)
        
        layout.addWidget(controls_group)
        
        # Export controls
        export_layout = QHBoxLayout()
        
        self.export_timeline_button = QPushButton("Export Timeline")
        self.export_timeline_button.clicked.connect(self.export_timeline)
        self.export_timeline_button.setEnabled(False)
        export_layout.addWidget(self.export_timeline_button)
        
        export_layout.addStretch()
        
        self.clear_timeline_button = QPushButton("Clear Timeline")
        self.clear_timeline_button.clicked.connect(self.clear_timeline)
        export_layout.addWidget(self.clear_timeline_button)
        
        layout.addLayout(export_layout)
        
        # Timeline display
        timeline_splitter = QSplitter(Qt.Vertical)
        
        # Main timeline table
        table_group = QGroupBox("Timeline Events")
        table_layout = QVBoxLayout(table_group)
        
        self.timeline_table = DataTableWidget()
        table_layout.addWidget(self.timeline_table)
        
        timeline_splitter.addWidget(table_group)
        
        # Event details
        details_group = QGroupBox("Event Details")
        details_layout = QVBoxLayout(details_group)
        
        self.details_text = QLineEdit()
        self.details_text.setReadOnly(True)
        font = QFont("Consolas, Monaco, monospace")
        font.setPointSize(9)
        self.details_text.setFont(font)
        details_layout.addWidget(self.details_text)
        
        timeline_splitter.addWidget(details_group)
        timeline_splitter.setSizes([500, 100])
        
        layout.addWidget(timeline_splitter, 1)
        
        # Connect table selection
        self.timeline_table.itemSelectionChanged.connect(self.show_event_details)
        
        # Auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.auto_refresh)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
        
    def refresh_timeline(self):
        """Refresh the timeline display."""
        if not self.main_window.timeline_data:
            self.timeline_table.clear()
            self.stats_label.setText("Events: 0")
            self.export_timeline_button.setEnabled(False)
            return
            
        # Process timeline data
        processed_events = self.timeline_processor.process_events(
            self.main_window.timeline_data
        )
        
        # Update filter options
        self.update_filter_options(processed_events)
        
        # Apply current filters
        self.apply_filters()
        
    def update_filter_options(self, events):
        """Update the filter combo boxes with available options."""
        # Get unique types and sources
        types = set()
        sources = set()
        
        for event in events:
            event_type = event.get('type', 'Unknown')
            source = event.get('source', 'Unknown')
            types.add(event_type)
            sources.add(source)
            
        # Update type filter
        current_type = self.type_filter_combo.currentText()
        self.type_filter_combo.clear()
        self.type_filter_combo.addItem("All Types")
        for event_type in sorted(types):
            self.type_filter_combo.addItem(event_type)
            
        # Restore selection if possible
        index = self.type_filter_combo.findText(current_type)
        if index >= 0:
            self.type_filter_combo.setCurrentIndex(index)
            
        # Update source filter
        current_source = self.source_filter_combo.currentText()
        self.source_filter_combo.clear()
        self.source_filter_combo.addItem("All Sources")
        for source in sorted(sources):
            self.source_filter_combo.addItem(source)
            
        # Restore selection if possible
        index = self.source_filter_combo.findText(current_source)
        if index >= 0:
            self.source_filter_combo.setCurrentIndex(index)
            
    def apply_filters(self):
        """Apply current filter settings to timeline."""
        if not self.main_window.timeline_data:
            return
            
        # Get filter criteria
        start_date = self.filter_start_date.dateTime().toPyDateTime()
        end_date = self.filter_end_date.dateTime().toPyDateTime()
        type_filter = self.type_filter_combo.currentText()
        source_filter = self.source_filter_combo.currentText()
        search_text = self.search_input.text()
        case_sensitive = self.case_sensitive_check.isChecked()
        
        # Apply filters
        filtered_events = self.timeline_processor.filter_events(
            self.main_window.timeline_data,
            start_date=start_date,
            end_date=end_date,
            event_type=type_filter if type_filter != "All Types" else None,
            source=source_filter if source_filter != "All Sources" else None,
            search_text=search_text,
            case_sensitive=case_sensitive
        )
        
        self.filtered_events = filtered_events
        self.display_timeline(filtered_events)
        
    def display_timeline(self, events):
        """Display events in the timeline table."""
        if not events:
            self.timeline_table.clear()
            self.stats_label.setText("Events: 0")
            self.export_timeline_button.setEnabled(False)
            return
            
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Prepare table data
        headers = ["Timestamp", "Type", "Source", "Description", "Details"]
        table_data = []
        
        for event in sorted_events:
            row = [
                event.get('timestamp', ''),
                event.get('type', ''),
                event.get('source', ''),
                event.get('description', ''),
                event.get('details', '')[:100] + "..." if len(event.get('details', '')) > 100 else event.get('details', '')
            ]
            table_data.append(row)
            
        # Load data into table
        self.timeline_table.load_data(table_data, headers)
        
        # Update stats
        self.stats_label.setText(f"Events: {len(events)} (of {len(self.main_window.timeline_data)})")
        self.export_timeline_button.setEnabled(True)
        
    def show_event_details(self):
        """Show details for selected event."""
        current_row = self.timeline_table.currentRow()
        if current_row >= 0 and current_row < len(self.filtered_events):
            event = self.filtered_events[current_row]
            details = f"Full Details: {event.get('details', 'No details available')}"
            self.details_text.setText(details)
        else:
            self.details_text.setText("")
            
    def export_timeline(self):
        """Export the current timeline."""
        if not self.filtered_events:
            QMessageBox.information(self, "Info", "No timeline events to export.")
            return
            
        from PyQt5.QtWidgets import QFileDialog
        import json
        import csv
        from datetime import datetime
        
        file_path, file_type = QFileDialog.getSaveFileName(
            self,
            "Export Timeline",
            f"timeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "CSV Files (*.csv);;JSON Files (*.json);;HTML Files (*.html)"
        )
        
        if not file_path:
            return
            
        try:
            if file_type.startswith("CSV"):
                self.export_csv(file_path)
            elif file_type.startswith("JSON"):
                self.export_json(file_path)
            elif file_type.startswith("HTML"):
                self.export_html(file_path)
                
            QMessageBox.information(self, "Success", f"Timeline exported to {file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")
            
    def export_csv(self, file_path):
        """Export timeline to CSV."""
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            if self.filtered_events:
                fieldnames = self.filtered_events[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.filtered_events)
                
    def export_json(self, file_path):
        """Export timeline to JSON."""
        with open(file_path, 'w', encoding='utf-8') as jsonfile:
            json.dump(self.filtered_events, jsonfile, indent=2, default=str)
            
    def export_html(self, file_path):
        """Export timeline to HTML."""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>InvestiGUI - Timeline Analysis</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .artifact { background-color: #e8f4fd; }
                .log { background-color: #fff2cc; }
                .error { color: red; }
                .warning { color: orange; }
            </style>
        </head>
        <body>
            <h1>Timeline Analysis Results</h1>
            <p>Generated on: {timestamp}</p>
            <p>Total events: {count}</p>
            
            <table>
                <tr>
                    <th>Timestamp</th>
                    <th>Type</th>
                    <th>Source</th>
                    <th>Description</th>
                    <th>Details</th>
                </tr>
        """
        
        for event in sorted(self.filtered_events, key=lambda x: x.get('timestamp', '')):
            event_type = event.get('type', '').lower()
            row_class = 'artifact' if 'artifact' in event_type else ('log' if 'log' in event_type else '')
            
            html_content += f"""
                <tr class="{row_class}">
                    <td>{event.get('timestamp', '')}</td>
                    <td>{event.get('type', '')}</td>
                    <td>{event.get('source', '')}</td>
                    <td>{event.get('description', '')}</td>
                    <td>{event.get('details', '')}</td>
                </tr>
            """
            
        html_content += """
            </table>
        </body>
        </html>
        """
        
        from datetime import datetime
        html_content = html_content.format(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            count=len(self.filtered_events)
        )
        
        with open(file_path, 'w', encoding='utf-8') as htmlfile:
            htmlfile.write(html_content)
            
    def clear_timeline(self):
        """Clear the current timeline."""
        reply = QMessageBox.question(
            self, 
            'Clear Timeline', 
            'Are you sure you want to clear the timeline? This will remove all artifacts and log events.',
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.main_window.timeline_data.clear()
            self.filtered_events.clear()
            self.timeline_table.clear()
            self.details_text.setText("")
            self.stats_label.setText("Events: 0")
            self.export_timeline_button.setEnabled(False)
            
    def clear_data(self):
        """Clear all data in the tab."""
        self.filtered_events.clear()
        self.timeline_table.clear()
        self.details_text.setText("")
        self.stats_label.setText("Events: 0")
        self.export_timeline_button.setEnabled(False)
        
        # Reset filters
        self.type_filter_combo.setCurrentIndex(0)
        self.source_filter_combo.setCurrentIndex(0)
        self.search_input.clear()
        self.case_sensitive_check.setChecked(False)
        
    def auto_refresh(self):
        """Automatically refresh timeline if data has changed."""
        # Only refresh if we have data and the tab is visible
        if (self.main_window.timeline_data and 
            self.main_window.tabs.currentWidget() == self):
            
            current_count = len(self.main_window.timeline_data)
            displayed_count = len(self.filtered_events)
            
            # Check if we need to refresh (new data might be available)
            if current_count != displayed_count:
                self.refresh_timeline()