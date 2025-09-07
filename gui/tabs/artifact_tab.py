"""
Artifact Extraction Tab for InvestiGUI
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QGroupBox, QCheckBox, QLabel, QProgressBar,
                             QTextEdit, QMessageBox, QSplitter, QComboBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont

from ..widgets import FilePickerWidget, DataTableWidget, ProgressWidget
from artifacts.browser import BrowserArtifacts
from artifacts.usb import USBArtifacts
from artifacts.wifi import WiFiArtifacts
from artifacts.files import FileArtifacts


class ArtifactExtractionThread(QThread):
    """Thread for running artifact extraction in background."""
    
    progress_update = pyqtSignal(int, str)
    artifacts_found = pyqtSignal(list)
    finished_extraction = pyqtSignal(str)
    
    def __init__(self, source_path, artifact_types):
        super().__init__()
        self.source_path = source_path
        self.artifact_types = artifact_types
        self.artifacts = []
        
    def run(self):
        """Run the artifact extraction."""
        try:
            total_types = len(self.artifact_types)
            current = 0
            
            for artifact_type in self.artifact_types:
                current += 1
                self.progress_update.emit(
                    int((current / total_types) * 100),
                    f"Extracting {artifact_type} artifacts..."
                )
                
                # Extract artifacts based on type
                if artifact_type == "Browser History":
                    extractor = BrowserArtifacts()
                    artifacts = extractor.extract_history(self.source_path)
                    self.artifacts.extend(artifacts)
                    
                elif artifact_type == "USB History":
                    extractor = USBArtifacts()
                    artifacts = extractor.extract_usb_history(self.source_path)
                    self.artifacts.extend(artifacts)
                    
                elif artifact_type == "WiFi Networks":
                    extractor = WiFiArtifacts()
                    artifacts = extractor.extract_wifi_profiles(self.source_path)
                    self.artifacts.extend(artifacts)
                    
                elif artifact_type == "Recent Files":
                    extractor = FileArtifacts()
                    artifacts = extractor.extract_recent_files(self.source_path)
                    self.artifacts.extend(artifacts)
                    
            self.artifacts_found.emit(self.artifacts)
            self.finished_extraction.emit(f"Extracted {len(self.artifacts)} artifacts successfully")
            
        except Exception as e:
            self.finished_extraction.emit(f"Error during extraction: {str(e)}")


class ArtifactTab(QWidget):
    """Tab for artifact extraction functionality."""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.current_artifacts = []
        self.extraction_thread = None
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Source selection
        source_group = QGroupBox("Source Selection")
        source_layout = QVBoxLayout(source_group)
        
        # Source type selection
        source_type_layout = QHBoxLayout()
        source_type_layout.addWidget(QLabel("Source Type:"))
        
        self.source_type_combo = QComboBox()
        self.source_type_combo.addItems(["Disk Image", "Live System", "Directory"])
        self.source_type_combo.currentTextChanged.connect(self.on_source_type_changed)
        source_type_layout.addWidget(self.source_type_combo)
        source_type_layout.addStretch()
        
        source_layout.addLayout(source_type_layout)
        
        # File picker
        self.file_picker = FilePickerWidget(
            "Source Path:", 
            "file", 
            "All Files (*);; Disk Images (*.dd *.img *.e01);; Virtual Machines (*.vmdk *.vdi)"
        )
        self.file_picker.file_selected.connect(self.on_source_selected)
        source_layout.addWidget(self.file_picker)
        
        layout.addWidget(source_group)
        
        # Artifact types selection
        types_group = QGroupBox("Artifact Types")
        types_layout = QVBoxLayout(types_group)
        
        # Checkboxes for artifact types
        self.artifact_checkboxes = {}
        artifact_types = [
            ("Browser History", "Extract web browser history and bookmarks"),
            ("USB History", "Extract USB device connection history"),
            ("WiFi Networks", "Extract saved WiFi network profiles"),
            ("Recent Files", "Extract recently accessed files")
        ]
        
        for artifact_type, description in artifact_types:
            checkbox = QCheckBox(artifact_type)
            checkbox.setToolTip(description)
            checkbox.setChecked(True)  # Default to checked
            self.artifact_checkboxes[artifact_type] = checkbox
            types_layout.addWidget(checkbox)
            
        layout.addWidget(types_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.extract_button = QPushButton("Start Extraction")
        self.extract_button.clicked.connect(self.start_extraction)
        self.extract_button.setEnabled(False)
        button_layout.addWidget(self.extract_button)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_extraction)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        button_layout.addStretch()
        
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        button_layout.addWidget(self.export_button)
        
        layout.addLayout(button_layout)
        
        # Progress widget
        self.progress_widget = ProgressWidget()
        layout.addWidget(self.progress_widget)
        
        # Results area
        results_splitter = QSplitter(Qt.Vertical)
        
        # Artifacts table
        table_group = QGroupBox("Extracted Artifacts")
        table_layout = QVBoxLayout(table_group)
        
        self.artifacts_table = DataTableWidget()
        table_layout.addWidget(self.artifacts_table)
        
        results_splitter.addWidget(table_group)
        
        # Log area
        log_group = QGroupBox("Extraction Log")
        log_layout = QVBoxLayout(log_group)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(150)
        font = QFont("Consolas, Monaco, monospace")
        font.setPointSize(9)
        self.log_text.setFont(font)
        log_layout.addWidget(self.log_text)
        
        results_splitter.addWidget(log_group)
        results_splitter.setSizes([400, 150])
        
        layout.addWidget(results_splitter, 1)
        
    def on_source_type_changed(self, source_type):
        """Handle source type change."""
        if source_type == "Directory":
            self.file_picker.file_type = "directory"
        else:
            self.file_picker.file_type = "file"
            
        self.file_picker.path_input.clear()
        self.extract_button.setEnabled(False)
        
    def on_source_selected(self, path):
        """Handle source selection."""
        self.extract_button.setEnabled(True)
        self.log_message(f"Source selected: {path}")
        
    def start_extraction(self):
        """Start the artifact extraction process."""
        source_path = self.file_picker.get_path()
        if not source_path:
            QMessageBox.warning(self, "Warning", "Please select a source path first.")
            return
            
        # Get selected artifact types
        selected_types = []
        for artifact_type, checkbox in self.artifact_checkboxes.items():
            if checkbox.isChecked():
                selected_types.append(artifact_type)
                
        if not selected_types:
            QMessageBox.warning(self, "Warning", "Please select at least one artifact type.")
            return
            
        # Clear previous results
        self.current_artifacts.clear()
        self.artifacts_table.clear()
        self.log_text.clear()
        
        # Start extraction thread
        self.extraction_thread = ArtifactExtractionThread(source_path, selected_types)
        self.extraction_thread.progress_update.connect(self.update_progress)
        self.extraction_thread.artifacts_found.connect(self.on_artifacts_found)
        self.extraction_thread.finished_extraction.connect(self.on_extraction_finished)
        
        self.extraction_thread.start()
        
        # Update UI state
        self.extract_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_widget.show_progress("Starting extraction...", 100)
        
        self.log_message(f"Started extraction of {len(selected_types)} artifact types")
        
    def stop_extraction(self):
        """Stop the current extraction."""
        if self.extraction_thread and self.extraction_thread.isRunning():
            self.extraction_thread.terminate()
            self.extraction_thread.wait()
            
        self.on_extraction_finished("Extraction stopped by user")
        
    def update_progress(self, value, message):
        """Update extraction progress."""
        self.progress_widget.update_progress(value, message)
        self.log_message(message)
        
    def on_artifacts_found(self, artifacts):
        """Handle found artifacts."""
        self.current_artifacts = artifacts
        
        if artifacts:
            # Prepare data for table
            headers = ["Type", "Timestamp", "Source", "Description", "Details"]
            table_data = []
            
            for artifact in artifacts:
                row = [
                    artifact.get("type", ""),
                    artifact.get("timestamp", ""),
                    artifact.get("source", ""),
                    artifact.get("description", ""),
                    artifact.get("details", "")
                ]
                table_data.append(row)
                
            self.artifacts_table.load_data(table_data, headers)
            
        # Send to timeline
        if artifacts:
            self.main_window.update_timeline(artifacts)
            
    def on_extraction_finished(self, message):
        """Handle extraction completion."""
        self.progress_widget.hide_progress(message)
        self.log_message(message)
        
        # Update UI state
        self.extract_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.export_button.setEnabled(bool(self.current_artifacts))
        
    def export_results(self):
        """Export current results."""
        if not self.current_artifacts:
            QMessageBox.information(self, "Info", "No artifacts to export.")
            return
            
        from PyQt5.QtWidgets import QFileDialog
        import json
        import csv
        from datetime import datetime
        
        file_path, file_type = QFileDialog.getSaveFileName(
            self,
            "Export Artifacts",
            f"artifacts_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
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
                
            QMessageBox.information(self, "Success", f"Artifacts exported to {file_path}")
            self.log_message(f"Exported {len(self.current_artifacts)} artifacts to {file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")
            
    def export_csv(self, file_path):
        """Export artifacts to CSV."""
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            if self.current_artifacts:
                fieldnames = self.current_artifacts[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.current_artifacts)
                
    def export_json(self, file_path):
        """Export artifacts to JSON."""
        with open(file_path, 'w', encoding='utf-8') as jsonfile:
            json.dump(self.current_artifacts, jsonfile, indent=2, default=str)
            
    def export_html(self, file_path):
        """Export artifacts to HTML."""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>InvestiGUI - Artifact Extraction Results</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
            </style>
        </head>
        <body>
            <h1>Artifact Extraction Results</h1>
            <p>Generated on: {timestamp}</p>
            <p>Total artifacts: {count}</p>
            
            <table>
                <tr>
                    <th>Type</th>
                    <th>Timestamp</th>
                    <th>Source</th>
                    <th>Description</th>
                    <th>Details</th>
                </tr>
        """
        
        for artifact in self.current_artifacts:
            html_content += f"""
                <tr>
                    <td>{artifact.get('type', '')}</td>
                    <td>{artifact.get('timestamp', '')}</td>
                    <td>{artifact.get('source', '')}</td>
                    <td>{artifact.get('description', '')}</td>
                    <td>{artifact.get('details', '')}</td>
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
            count=len(self.current_artifacts)
        )
        
        with open(file_path, 'w', encoding='utf-8') as htmlfile:
            htmlfile.write(html_content)
            
    def log_message(self, message):
        """Add message to extraction log."""
        from datetime import datetime
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.append(f"[{timestamp}] {message}")
        
    def clear_data(self):
        """Clear all data in the tab."""
        self.current_artifacts.clear()
        self.artifacts_table.clear()
        self.log_text.clear()
        self.file_picker.set_path("")
        self.extract_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.progress_widget.hide_progress("Ready")