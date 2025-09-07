"""
Log Parser Tab for InvestiGUI
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QGroupBox, QCheckBox, QLabel, QMessageBox, 
                             QSplitter, QComboBox, QDateTimeEdit, QSpinBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QDateTime
from PyQt5.QtGui import QFont

from ..widgets import FilePickerWidget, DataTableWidget, LogViewerWidget, ProgressWidget
from logs.windows import WindowsLogParser
from logs.linux import LinuxLogParser
from logs.browser import BrowserLogParser


class LogParsingThread(QThread):
    """Thread for parsing logs in background."""
    
    progress_update = pyqtSignal(int, str)
    events_found = pyqtSignal(list)
    finished_parsing = pyqtSignal(str)
    
    def __init__(self, log_paths, log_types, filters):
        super().__init__()
        self.log_paths = log_paths
        self.log_types = log_types
        self.filters = filters
        self.events = []
        
    def run(self):
        """Run the log parsing."""
        try:
            total_files = len(self.log_paths)
            current = 0
            
            for log_path in self.log_paths:
                current += 1
                self.progress_update.emit(
                    int((current / total_files) * 100),
                    f"Parsing log file: {log_path}"
                )
                
                # Determine parser based on log type or file extension
                parser = self.get_parser(log_path)
                if parser:
                    events = parser.parse_log(log_path, self.filters)
                    self.events.extend(events)
                    
            self.events_found.emit(self.events)
            self.finished_parsing.emit(f"Parsed {len(self.events)} log events successfully")
            
        except Exception as e:
            self.finished_parsing.emit(f"Error during parsing: {str(e)}")
            
    def get_parser(self, log_path):
        """Get appropriate parser for log file."""
        log_path_lower = log_path.lower()
        
        if "Windows" in self.log_types or log_path_lower.endswith('.evtx'):
            return WindowsLogParser()
        elif "Linux" in self.log_types or 'syslog' in log_path_lower or log_path_lower.endswith('.log'):
            return LinuxLogParser()
        elif "Browser" in self.log_types:
            return BrowserLogParser()
        else:
            # Try Linux parser as default
            return LinuxLogParser()


class LogsTab(QWidget):
    """Tab for log parsing functionality."""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.current_events = []
        self.parsing_thread = None
        self.log_paths = []
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Log source selection
        source_group = QGroupBox("Log Sources")
        source_layout = QVBoxLayout(source_group)
        
        # Log type selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Log Type:"))
        
        self.log_type_combo = QComboBox()
        self.log_type_combo.addItems(["Auto-detect", "Windows Event Logs", "Linux System Logs", "Browser Logs"])
        type_layout.addWidget(self.log_type_combo)
        type_layout.addStretch()
        
        source_layout.addLayout(type_layout)
        
        # File/directory picker for logs
        picker_layout = QHBoxLayout()
        
        self.log_file_picker = FilePickerWidget(
            "Log File:", 
            "file",
            "Log Files (*.log *.evtx *.txt);; Windows Event Logs (*.evtx);; All Files (*)"
        )
        self.log_file_picker.file_selected.connect(self.add_log_file)
        picker_layout.addWidget(self.log_file_picker, 1)
        
        self.log_dir_picker = FilePickerWidget("Log Directory:", "directory")
        self.log_dir_picker.file_selected.connect(self.add_log_directory)
        picker_layout.addWidget(self.log_dir_picker, 1)
        
        source_layout.addLayout(picker_layout)
        
        # Selected files list
        files_layout = QHBoxLayout()
        files_layout.addWidget(QLabel("Selected Files:"))
        
        self.clear_files_button = QPushButton("Clear All")
        self.clear_files_button.clicked.connect(self.clear_log_files)
        files_layout.addWidget(self.clear_files_button)
        
        source_layout.addLayout(files_layout)
        
        self.files_table = DataTableWidget()
        self.files_table.setMaximumHeight(100)
        source_layout.addWidget(self.files_table)
        
        layout.addWidget(source_group)
        
        # Filtering options
        filter_group = QGroupBox("Filter Options")
        filter_layout = QVBoxLayout(filter_group)
        
        # Date range
        date_layout = QHBoxLayout()
        date_layout.addWidget(QLabel("Date Range:"))
        
        self.start_date = QDateTimeEdit()
        self.start_date.setDateTime(QDateTime.currentDateTime().addDays(-7))
        date_layout.addWidget(self.start_date)
        
        date_layout.addWidget(QLabel("to"))
        
        self.end_date = QDateTimeEdit()
        self.end_date.setDateTime(QDateTime.currentDateTime())
        date_layout.addWidget(self.end_date)
        
        date_layout.addStretch()
        filter_layout.addLayout(date_layout)
        
        # Log level and keyword filters
        filter_options_layout = QHBoxLayout()
        
        filter_options_layout.addWidget(QLabel("Min Level:"))
        self.level_combo = QComboBox()
        self.level_combo.addItems(["All", "ERROR", "WARNING", "INFO", "DEBUG"])
        filter_options_layout.addWidget(self.level_combo)
        
        filter_options_layout.addWidget(QLabel("Max Events:"))
        self.max_events_spin = QSpinBox()
        self.max_events_spin.setRange(100, 100000)
        self.max_events_spin.setValue(10000)
        filter_options_layout.addWidget(self.max_events_spin)
        
        filter_options_layout.addStretch()
        filter_layout.addLayout(filter_options_layout)
        
        layout.addWidget(filter_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.parse_button = QPushButton("Start Parsing")
        self.parse_button.clicked.connect(self.start_parsing)
        self.parse_button.setEnabled(False)
        button_layout.addWidget(self.parse_button)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_parsing)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        button_layout.addStretch()
        
        self.export_button = QPushButton("Export Events")
        self.export_button.clicked.connect(self.export_events)
        self.export_button.setEnabled(False)
        button_layout.addWidget(self.export_button)
        
        layout.addLayout(button_layout)
        
        # Progress widget
        self.progress_widget = ProgressWidget()
        layout.addWidget(self.progress_widget)
        
        # Results area
        results_splitter = QSplitter(Qt.Vertical)
        
        # Events table
        table_group = QGroupBox("Parsed Events")
        table_layout = QVBoxLayout(table_group)
        
        self.events_table = DataTableWidget()
        table_layout.addWidget(self.events_table)
        
        results_splitter.addWidget(table_group)
        
        # Raw log viewer
        raw_group = QGroupBox("Raw Log Viewer")
        raw_layout = QVBoxLayout(raw_group)
        
        self.log_viewer = LogViewerWidget()
        raw_layout.addWidget(self.log_viewer)
        
        results_splitter.addWidget(raw_group)
        results_splitter.setSizes([400, 200])
        
        layout.addWidget(results_splitter, 1)
        
    def add_log_file(self, file_path):
        """Add a single log file."""
        if file_path not in self.log_paths:
            self.log_paths.append(file_path)
            self.update_files_table()
            self.parse_button.setEnabled(True)
            
    def add_log_directory(self, dir_path):
        """Add all log files from directory."""
        import os
        log_extensions = ['.log', '.evtx', '.txt']
        
        added_count = 0
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                if any(file.lower().endswith(ext) for ext in log_extensions):
                    file_path = os.path.join(root, file)
                    if file_path not in self.log_paths:
                        self.log_paths.append(file_path)
                        added_count += 1
                        
        self.update_files_table()
        if added_count > 0:
            self.parse_button.setEnabled(True)
            QMessageBox.information(self, "Info", f"Added {added_count} log files from directory")
            
    def clear_log_files(self):
        """Clear all selected log files."""
        self.log_paths.clear()
        self.update_files_table()
        self.parse_button.setEnabled(False)
        
    def update_files_table(self):
        """Update the files table display."""
        if self.log_paths:
            import os
            headers = ["Filename", "Path", "Size"]
            table_data = []
            
            for path in self.log_paths:
                filename = os.path.basename(path)
                try:
                    size = os.path.getsize(path)
                    size_str = f"{size:,} bytes"
                except:
                    size_str = "Unknown"
                    
                table_data.append([filename, path, size_str])
                
            self.files_table.load_data(table_data, headers)
        else:
            self.files_table.clear()
            
    def start_parsing(self):
        """Start the log parsing process."""
        if not self.log_paths:
            QMessageBox.warning(self, "Warning", "Please select log files first.")
            return
            
        # Prepare filters
        filters = {
            'start_date': self.start_date.dateTime().toPyDateTime(),
            'end_date': self.end_date.dateTime().toPyDateTime(),
            'min_level': self.level_combo.currentText(),
            'max_events': self.max_events_spin.value()
        }
        
        # Get log types
        log_types = [self.log_type_combo.currentText()]
        
        # Clear previous results
        self.current_events.clear()
        self.events_table.clear()
        self.log_viewer.set_content("")
        
        # Start parsing thread
        self.parsing_thread = LogParsingThread(self.log_paths, log_types, filters)
        self.parsing_thread.progress_update.connect(self.update_progress)
        self.parsing_thread.events_found.connect(self.on_events_found)
        self.parsing_thread.finished_parsing.connect(self.on_parsing_finished)
        
        self.parsing_thread.start()
        
        # Update UI state
        self.parse_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_widget.show_progress("Starting log parsing...", 100)
        
    def stop_parsing(self):
        """Stop the current parsing."""
        if self.parsing_thread and self.parsing_thread.isRunning():
            self.parsing_thread.terminate()
            self.parsing_thread.wait()
            
        self.on_parsing_finished("Parsing stopped by user")
        
    def update_progress(self, value, message):
        """Update parsing progress."""
        self.progress_widget.update_progress(value, message)
        
    def on_events_found(self, events):
        """Handle found log events."""
        self.current_events = events
        
        if events:
            # Prepare data for table
            headers = ["Timestamp", "Level", "Source", "Event ID", "Message"]
            table_data = []
            
            for event in events:
                row = [
                    event.get("timestamp", ""),
                    event.get("level", ""),
                    event.get("source", ""),
                    event.get("event_id", ""),
                    event.get("message", "")[:100] + "..." if len(event.get("message", "")) > 100 else event.get("message", "")
                ]
                table_data.append(row)
                
            self.events_table.load_data(table_data, headers)
            
            # Show raw content of first few events
            raw_content = ""
            for event in events[:50]:  # Show first 50 events
                raw_content += f"[{event.get('timestamp', 'Unknown')}] {event.get('level', 'INFO')}: {event.get('message', '')}\n"
            self.log_viewer.set_content(raw_content)
            
        # Send to timeline
        if events:
            self.main_window.update_timeline(events)
            
    def on_parsing_finished(self, message):
        """Handle parsing completion."""
        self.progress_widget.hide_progress(message)
        
        # Update UI state
        self.parse_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.export_button.setEnabled(bool(self.current_events))
        
    def export_events(self):
        """Export current log events."""
        if not self.current_events:
            QMessageBox.information(self, "Info", "No events to export.")
            return
            
        from PyQt5.QtWidgets import QFileDialog
        import json
        import csv
        from datetime import datetime
        
        file_path, file_type = QFileDialog.getSaveFileName(
            self,
            "Export Log Events",
            f"log_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
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
                
            QMessageBox.information(self, "Success", f"Events exported to {file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")
            
    def export_csv(self, file_path):
        """Export events to CSV."""
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            if self.current_events:
                fieldnames = self.current_events[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.current_events)
                
    def export_json(self, file_path):
        """Export events to JSON."""
        with open(file_path, 'w', encoding='utf-8') as jsonfile:
            json.dump(self.current_events, jsonfile, indent=2, default=str)
            
    def export_html(self, file_path):
        """Export events to HTML."""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>InvestiGUI - Log Parsing Results</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .error { color: red; }
                .warning { color: orange; }
                .info { color: blue; }
            </style>
        </head>
        <body>
            <h1>Log Parsing Results</h1>
            <p>Generated on: {timestamp}</p>
            <p>Total events: {count}</p>
            
            <table>
                <tr>
                    <th>Timestamp</th>
                    <th>Level</th>
                    <th>Source</th>
                    <th>Event ID</th>
                    <th>Message</th>
                </tr>
        """
        
        for event in self.current_events:
            level_class = event.get('level', '').lower()
            html_content += f"""
                <tr>
                    <td>{event.get('timestamp', '')}</td>
                    <td class="{level_class}">{event.get('level', '')}</td>
                    <td>{event.get('source', '')}</td>
                    <td>{event.get('event_id', '')}</td>
                    <td>{event.get('message', '')}</td>
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
            count=len(self.current_events)
        )
        
        with open(file_path, 'w', encoding='utf-8') as htmlfile:
            htmlfile.write(html_content)
            
    def clear_data(self):
        """Clear all data in the tab."""
        self.current_events.clear()
        self.log_paths.clear()
        self.events_table.clear()
        self.files_table.clear()
        self.log_viewer.set_content("")
        self.log_file_picker.set_path("")
        self.log_dir_picker.set_path("")
        self.parse_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.progress_widget.hide_progress("Ready")