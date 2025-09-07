"""
Custom widgets for InvestiGUI
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QFileDialog, QLineEdit, QLabel, QTableWidget,
                             QTableWidgetItem, QHeaderView, QProgressBar,
                             QTextEdit, QSplitter, QGroupBox, QComboBox)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont
import os


class FilePickerWidget(QWidget):
    """Widget for selecting files or directories."""
    
    file_selected = pyqtSignal(str)  # Signal emitted when file is selected
    
    def __init__(self, label_text="Select File:", file_type="file", file_filter="All Files (*)", parent=None):
        super().__init__(parent)
        self.file_type = file_type  # "file" or "directory"
        self.file_filter = file_filter
        self.init_ui(label_text)
        
    def init_ui(self, label_text):
        """Initialize the UI."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Label
        self.label = QLabel(label_text)
        layout.addWidget(self.label)
        
        # Path input
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("No file selected...")
        self.path_input.textChanged.connect(self.on_path_changed)
        layout.addWidget(self.path_input, 1)
        
        # Browse button
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_file)
        layout.addWidget(self.browse_button)
        
    def browse_file(self):
        """Open file/directory browser."""
        if self.file_type == "directory":
            path = QFileDialog.getExistingDirectory(self, "Select Directory")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Select File", "", self.file_filter)
            
        if path:
            self.path_input.setText(path)
            
    def on_path_changed(self, text):
        """Handle path text change."""
        if text and os.path.exists(text):
            self.file_selected.emit(text)
            
    def get_path(self):
        """Get the selected path."""
        return self.path_input.text()
        
    def set_path(self, path):
        """Set the path."""
        self.path_input.setText(path)


class DataTableWidget(QTableWidget):
    """Enhanced table widget for displaying forensic data."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        """Initialize the table UI."""
        # Set selection behavior
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setAlternatingRowColors(True)
        
        # Enable sorting
        self.setSortingEnabled(True)
        
        # Set header properties
        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.Interactive)
        
        # Set font
        font = QFont()
        font.setFamily("Consolas, Monaco, monospace")
        font.setPointSize(9)
        self.setFont(font)
        
    def load_data(self, data, headers):
        """Load data into the table.
        
        Args:
            data: List of dictionaries or list of lists
            headers: List of column headers
        """
        if not data:
            self.clear()
            return
            
        # Set up table dimensions
        self.setRowCount(len(data))
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        
        # Populate data
        for row, item in enumerate(data):
            if isinstance(item, dict):
                for col, header in enumerate(headers):
                    value = str(item.get(header, ""))
                    table_item = QTableWidgetItem(value)
                    table_item.setFlags(table_item.flags() & ~Qt.ItemIsEditable)
                    self.setItem(row, col, table_item)
            else:
                for col, value in enumerate(item):
                    table_item = QTableWidgetItem(str(value))
                    table_item.setFlags(table_item.flags() & ~Qt.ItemIsEditable)
                    self.setItem(row, col, table_item)
                    
        # Resize columns to content
        self.resizeColumnsToContents()
        
    def export_to_csv(self, filename):
        """Export table data to CSV file."""
        import csv
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write headers
            headers = []
            for col in range(self.columnCount()):
                headers.append(self.horizontalHeaderItem(col).text())
            writer.writerow(headers)
            
            # Write data
            for row in range(self.rowCount()):
                row_data = []
                for col in range(self.columnCount()):
                    item = self.item(row, col)
                    row_data.append(item.text() if item else "")
                writer.writerow(row_data)


class LogViewerWidget(QWidget):
    """Widget for displaying log content with filtering."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        """Initialize the UI."""
        layout = QVBoxLayout(self)
        
        # Filter controls
        filter_group = QGroupBox("Filter Options")
        filter_layout = QHBoxLayout(filter_group)
        
        filter_layout.addWidget(QLabel("Filter:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Enter filter text...")
        self.filter_input.textChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_input, 1)
        
        self.level_combo = QComboBox()
        self.level_combo.addItems(["All Levels", "ERROR", "WARNING", "INFO", "DEBUG"])
        self.level_combo.currentTextChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.level_combo)
        
        layout.addWidget(filter_group)
        
        # Log content
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        font = QFont("Consolas, Monaco, monospace")
        font.setPointSize(9)
        self.log_text.setFont(font)
        
        layout.addWidget(self.log_text, 1)
        
        self.original_content = ""
        
    def set_content(self, content):
        """Set the log content."""
        self.original_content = content
        self.apply_filter()
        
    def apply_filter(self):
        """Apply current filter settings."""
        content = self.original_content
        filter_text = self.filter_input.text().lower()
        level_filter = self.level_combo.currentText()
        
        if not content:
            return
            
        lines = content.split('\n')
        filtered_lines = []
        
        for line in lines:
            # Apply text filter
            if filter_text and filter_text not in line.lower():
                continue
                
            # Apply level filter
            if level_filter != "All Levels" and level_filter not in line:
                continue
                
            filtered_lines.append(line)
            
        self.log_text.setPlainText('\n'.join(filtered_lines))


class ProgressWidget(QWidget):
    """Widget for showing progress with message."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        """Initialize the UI."""
        layout = QVBoxLayout(self)
        
        self.message_label = QLabel("Ready")
        layout.addWidget(self.message_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
    def show_progress(self, message, maximum=0):
        """Show progress bar with message."""
        self.message_label.setText(message)
        self.progress_bar.setMaximum(maximum)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        
    def update_progress(self, value, message=None):
        """Update progress value and optionally message."""
        if message:
            self.message_label.setText(message)
        self.progress_bar.setValue(value)
        
    def hide_progress(self, message="Ready"):
        """Hide progress bar and show completion message."""
        self.progress_bar.setVisible(False)
        self.message_label.setText(message)


class SplitPaneWidget(QSplitter):
    """Splitter widget for resizable panes."""
    
    def __init__(self, orientation=Qt.Horizontal, parent=None):
        super().__init__(orientation, parent)
        self.setChildrenCollapsible(False)