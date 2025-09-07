"""
Main Window for InvestiGUI Digital Forensics Toolkit
"""

from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QVBoxLayout, 
                             QWidget, QMenuBar, QStatusBar, QApplication,
                             QMessageBox, QToolBar, QAction)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QIcon, QFont

from .tabs.artifact_tab import ArtifactTab
from .tabs.logs_tab import LogsTab
from .tabs.timeline_tab import TimelineTab


class MainWindow(QMainWindow):
    """Main window containing all tabs and functionality."""
    
    def __init__(self):
        super().__init__()
        self.timeline_data = []  # Shared timeline data
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("InvestiGUI - Digital Forensics Toolkit")
        self.setGeometry(100, 100, 1200, 800)
        
        # Set application icon (placeholder)
        self.setWindowIcon(QIcon())
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Initialize tabs
        self.artifact_tab = ArtifactTab(self)
        self.logs_tab = LogsTab(self)
        self.timeline_tab = TimelineTab(self)
        
        # Add tabs
        self.tabs.addTab(self.artifact_tab, "Artifact Extraction")
        self.tabs.addTab(self.logs_tab, "Log Parser")
        self.tabs.addTab(self.timeline_tab, "Timeline Viewer")
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Apply styling
        self.apply_styles()
        
    def create_menu_bar(self):
        """Create the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        # New analysis action
        new_action = QAction("New Analysis", self)
        new_action.setShortcut("Ctrl+N")
        new_action.triggered.connect(self.new_analysis)
        file_menu.addAction(new_action)
        
        file_menu.addSeparator()
        
        # Exit action
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def apply_styles(self):
        """Apply custom styling to the application."""
        font = QFont()
        font.setPointSize(10)
        QApplication.instance().setFont(font)
        
        # Set custom stylesheet
        style = """
        QMainWindow {
            background-color: #f0f0f0;
        }
        QTabWidget::pane {
            border: 1px solid #c0c0c0;
            background-color: white;
        }
        QTabWidget::tab-bar {
            left: 5px;
        }
        QTabBar::tab {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                        stop: 0 #e1e1e1, stop: 0.4 #dddddd,
                                        stop: 0.5 #d8d8d8, stop: 1.0 #d3d3d3);
            border: 1px solid #c4c4c3;
            border-bottom-color: #c2c7cb;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            min-width: 8ex;
            padding: 8px 12px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                        stop: 0 #fafafa, stop: 0.4 #f4f4f4,
                                        stop: 0.5 #e7e7e7, stop: 1.0 #fafafa);
            border-bottom-color: white;
        }
        QTabBar::tab:!selected {
            margin-top: 2px;
        }
        """
        self.setStyleSheet(style)
        
    def new_analysis(self):
        """Start a new analysis session."""
        reply = QMessageBox.question(self, 'New Analysis', 
                                   'Clear all current data and start new analysis?',
                                   QMessageBox.Yes | QMessageBox.No, 
                                   QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.timeline_data.clear()
            self.artifact_tab.clear_data()
            self.logs_tab.clear_data()
            self.timeline_tab.clear_data()
            self.status_bar.showMessage("New analysis started")
            
    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(self, "About InvestiGUI",
                         "InvestiGUI - Digital Forensics Toolkit\n\n"
                         "A Python-based forensics tool for artifact extraction,\n"
                         "log parsing, and timeline analysis.\n\n"
                         "Version: 1.0\n"
                         "License: MIT")
        
    def update_timeline(self, events):
        """Update the shared timeline with new events."""
        self.timeline_data.extend(events)
        self.timeline_tab.refresh_timeline()
        
    def update_status(self, message):
        """Update the status bar message."""
        self.status_bar.showMessage(message)
        QApplication.processEvents()  # Process pending events
        
    def show_progress(self, message):
        """Show progress message in status bar."""
        self.update_status(f"Processing: {message}")
        
    def closeEvent(self, event):
        """Handle application close event."""
        reply = QMessageBox.question(self, 'Exit Application',
                                   'Are you sure you want to exit?',
                                   QMessageBox.Yes | QMessageBox.No,
                                   QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()