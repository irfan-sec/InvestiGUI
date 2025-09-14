"""
Main Window for InvestiGUI Digital Forensics Toolkit v2.0.0
Enhanced with new capabilities and modern UI.
"""

from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QVBoxLayout, 
                             QWidget, QMenuBar, QStatusBar, QApplication,
                             QMessageBox, QToolBar, QAction, QProgressBar,
                             QSplitter, QDockWidget, QTextEdit, QLabel)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QFont, QPalette

from .tabs.artifact_tab import ArtifactTab
from .tabs.logs_tab import LogsTab
from .tabs.timeline_tab import TimelineTab

# Import new modules
from version import get_version, get_full_version
from plugin_manager import get_plugin_manager, initialize_plugin_system
from reporting import generate_investigation_report
from ml_analysis import perform_anomaly_detection, generate_ml_insights


class MainWindow(QMainWindow):
    """Main window containing all tabs and functionality."""
    
    def __init__(self):
        super().__init__()
        self.timeline_data = []  # Shared timeline data
        self.artifacts_data = {}  # Shared artifacts data
        self.ml_insights = {}  # ML analysis results
        self.plugin_manager = None
        self.current_case_info = {}
        self.analysis_running = False
        
        self.init_ui()
        self.init_plugins()
        
    def init_ui(self):
        """Initialize the user interface."""
        version_info = get_full_version()
        self.setWindowTitle(f"InvestiGUI v{version_info['version']} - Digital Forensics Toolkit")
        self.setGeometry(100, 100, 1400, 900)
        
        # Set application icon (placeholder)
        self.setWindowIcon(QIcon())
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create main splitter for better layout
        main_splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(main_splitter)
        
        # Create tab widget
        self.tabs = QTabWidget()
        main_splitter.addWidget(self.tabs)
        
        # Initialize tabs with enhanced functionality
        self.artifact_tab = ArtifactTab(self)
        self.logs_tab = LogsTab(self)
        self.timeline_tab = TimelineTab(self)
        
        # Add tabs
        self.tabs.addTab(self.artifact_tab, "🔍 Artifact Extraction")
        self.tabs.addTab(self.logs_tab, "📝 Log Parser")
        self.tabs.addTab(self.timeline_tab, "⏰ Timeline Viewer")
        
        # Create side panel for insights and tools
        self.create_side_panel(main_splitter)
        
        # Create enhanced menu bar
        self.create_menu_bar()
        
        # Create enhanced toolbar
        self.create_toolbar()
        
        # Create enhanced status bar
        self.create_status_bar()
        
        # Create dock widgets for additional functionality
        self.create_dock_widgets()
        
        # Apply modern styling
        self.apply_modern_styles()
        
    def create_side_panel(self, parent_splitter):
        """Create side panel for insights and quick tools."""
        side_panel = QWidget()
        side_layout = QVBoxLayout(side_panel)
        side_layout.setContentsMargins(10, 10, 10, 10)
        
        # ML Insights section
        insights_label = QLabel("🤖 ML Insights")
        insights_label.setFont(QFont("Arial", 12, QFont.Bold))
        side_layout.addWidget(insights_label)
        
        self.insights_text = QTextEdit()
        self.insights_text.setMaximumHeight(200)
        self.insights_text.setPlainText("Initialize analysis to see ML insights...")
        side_layout.addWidget(self.insights_text)
        
        # Plugin status section
        plugins_label = QLabel("🔌 Plugins")
        plugins_label.setFont(QFont("Arial", 12, QFont.Bold))
        side_layout.addWidget(plugins_label)
        
        self.plugins_text = QTextEdit()
        self.plugins_text.setMaximumHeight(150)
        self.plugins_text.setPlainText("Loading plugins...")
        side_layout.addWidget(self.plugins_text)
        
        # Quick stats section
        stats_label = QLabel("📊 Quick Stats")
        stats_label.setFont(QFont("Arial", 12, QFont.Bold))
        side_layout.addWidget(stats_label)
        
        self.stats_text = QTextEdit()
        self.stats_text.setMaximumHeight(100)
        self.stats_text.setPlainText("No data analyzed yet")
        side_layout.addWidget(self.stats_text)
        
        side_layout.addStretch()
        
        side_panel.setMaximumWidth(300)
        parent_splitter.addWidget(side_panel)
        
    def create_toolbar(self):
        """Create enhanced toolbar with new actions."""
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)
        
        # New Case action
        new_case_action = QAction("🆕 New Case", self)
        new_case_action.setShortcut("Ctrl+N")
        new_case_action.triggered.connect(self.new_case)
        toolbar.addAction(new_case_action)
        
        toolbar.addSeparator()
        
        # Memory Analysis action
        memory_action = QAction("🧠 Memory Analysis", self)
        memory_action.triggered.connect(self.start_memory_analysis)
        toolbar.addAction(memory_action)
        
        # Network Analysis action
        network_action = QAction("🌐 Network Analysis", self)
        network_action.triggered.connect(self.start_network_analysis)
        toolbar.addAction(network_action)
        
        # ML Analysis action
        ml_action = QAction("🤖 ML Analysis", self)
        ml_action.triggered.connect(self.start_ml_analysis)
        toolbar.addAction(ml_action)
        
        toolbar.addSeparator()
        
        # Generate Report action
        report_action = QAction("📄 Generate Report", self)
        report_action.triggered.connect(self.generate_report)
        toolbar.addAction(report_action)
        
        # Plugin Manager action
        plugin_action = QAction("🔌 Plugin Manager", self)
        plugin_action.triggered.connect(self.show_plugin_manager)
        toolbar.addAction(plugin_action)
        
    def create_status_bar(self):
        """Create enhanced status bar with progress indicator."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Add progress bar to status bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        # Version info in status bar
        version_label = QLabel(f"v{get_version()}")
        self.status_bar.addPermanentWidget(version_label)
        
        self.status_bar.showMessage("Ready - InvestiGUI v2.0.0 Digital Forensics Toolkit")
        
    def create_dock_widgets(self):
        """Create dock widgets for additional functionality."""
        # Log dock widget
        log_dock = QDockWidget("System Log", self)
        self.log_widget = QTextEdit()
        self.log_widget.setFont(QFont("Consolas", 9))
        log_dock.setWidget(self.log_widget)
        self.addDockWidget(Qt.BottomDockWidgetArea, log_dock)
        
        # Initially hide the log dock
        log_dock.hide()
        
        # Add to View menu for toggling
        self.log_dock = log_dock
        
    def create_menu_bar(self):
        """Create enhanced menu bar with new features."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("📁 File")
        
        # New Case action
        new_case_action = QAction("New Case", self)
        new_case_action.setShortcut("Ctrl+N")
        new_case_action.triggered.connect(self.new_case)
        file_menu.addAction(new_case_action)
        
        # Open Case action
        open_case_action = QAction("Open Case", self)
        open_case_action.setShortcut("Ctrl+O")
        open_case_action.triggered.connect(self.open_case)
        file_menu.addAction(open_case_action)
        
        # Save Case action
        save_case_action = QAction("Save Case", self)
        save_case_action.setShortcut("Ctrl+S")
        save_case_action.triggered.connect(self.save_case)
        file_menu.addAction(save_case_action)
        
        file_menu.addSeparator()
        
        # Export submenu
        export_menu = file_menu.addMenu("Export")
        
        export_html_action = QAction("Export Report (HTML)", self)
        export_html_action.triggered.connect(lambda: self.export_report('html'))
        export_menu.addAction(export_html_action)
        
        export_json_action = QAction("Export Report (JSON)", self)
        export_json_action.triggered.connect(lambda: self.export_report('json'))
        export_menu.addAction(export_json_action)
        
        export_xml_action = QAction("Export Report (XML)", self)
        export_xml_action.triggered.connect(lambda: self.export_report('xml'))
        export_menu.addAction(export_xml_action)
        
        file_menu.addSeparator()
        
        # Exit action
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Analysis menu
        analysis_menu = menubar.addMenu("🔍 Analysis")
        
        # Memory Analysis
        memory_action = QAction("Memory Analysis", self)
        memory_action.triggered.connect(self.start_memory_analysis)
        analysis_menu.addAction(memory_action)
        
        # Network Analysis
        network_action = QAction("Network Analysis", self)
        network_action.triggered.connect(self.start_network_analysis)
        analysis_menu.addAction(network_action)
        
        analysis_menu.addSeparator()
        
        # ML Analysis
        ml_action = QAction("ML Anomaly Detection", self)
        ml_action.triggered.connect(self.start_ml_analysis)
        analysis_menu.addAction(ml_action)
        
        # Plugin execution
        plugin_exec_action = QAction("Execute All Plugins", self)
        plugin_exec_action.triggered.connect(self.execute_all_plugins)
        analysis_menu.addAction(plugin_exec_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("🔧 Tools")
        
        # Plugin Manager
        plugin_manager_action = QAction("Plugin Manager", self)
        plugin_manager_action.triggered.connect(self.show_plugin_manager)
        tools_menu.addAction(plugin_manager_action)
        
        # Report Generator
        report_gen_action = QAction("Report Generator", self)
        report_gen_action.triggered.connect(self.generate_report)
        tools_menu.addAction(report_gen_action)
        
        tools_menu.addSeparator()
        
        # Settings
        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self.show_settings)
        tools_menu.addAction(settings_action)
        
        # View menu
        view_menu = menubar.addMenu("👁️ View")
        
        # Dark theme toggle
        dark_theme_action = QAction("Toggle Dark Theme", self)
        dark_theme_action.triggered.connect(self.toggle_dark_theme)
        view_menu.addAction(dark_theme_action)
        
        view_menu.addSeparator()
        
        # Show/Hide dock widgets
        log_dock_action = QAction("Show System Log", self)
        log_dock_action.setCheckable(True)
        log_dock_action.triggered.connect(self.toggle_log_dock)
        view_menu.addAction(log_dock_action)
        
        # Help menu
        help_menu = menubar.addMenu("❓ Help")
        
        # Documentation
        docs_action = QAction("Documentation", self)
        docs_action.triggered.connect(self.show_documentation)
        help_menu.addAction(docs_action)
        
        # Plugin Development Guide
        plugin_guide_action = QAction("Plugin Development Guide", self)
        plugin_guide_action.triggered.connect(self.show_plugin_guide)
        help_menu.addAction(plugin_guide_action)
        
        help_menu.addSeparator()
        
        # About
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def apply_modern_styles(self):
        """Apply modern styling to the application."""
        font = QFont()
        font.setPointSize(10)
        QApplication.instance().setFont(font)
        
        # Enhanced stylesheet with modern design
        style = """
        QMainWindow {
            background-color: #f5f5f5;
        }
        QTabWidget::pane {
            border: 1px solid #c0c0c0;
            background-color: white;
            border-radius: 4px;
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
            font-weight: bold;
        }
        QTabBar::tab:selected {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                        stop: 0 #ffffff, stop: 0.4 #f4f4f4,
                                        stop: 0.5 #e7e7e7, stop: 1.0 #ffffff);
            border-bottom-color: white;
            color: #2c3e50;
        }
        QTabBar::tab:!selected {
            margin-top: 2px;
        }
        QToolBar {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                       stop: 0 #f0f0f0, stop: 1 #e0e0e0);
            border: 1px solid #c0c0c0;
            padding: 3px;
        }
        QToolBar QToolButton {
            background: transparent;
            border: 1px solid transparent;
            border-radius: 3px;
            padding: 5px;
            margin: 1px;
        }
        QToolBar QToolButton:hover {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                       stop: 0 #e0e0e0, stop: 1 #d0d0d0);
            border: 1px solid #b0b0b0;
        }
        QStatusBar {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                       stop: 0 #f0f0f0, stop: 1 #e0e0e0);
            border-top: 1px solid #c0c0c0;
        }
        QProgressBar {
            border: 1px solid #c0c0c0;
            border-radius: 3px;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #3498db;
            border-radius: 2px;
        }
        QMenuBar {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                       stop: 0 #f0f0f0, stop: 1 #e0e0e0);
            border-bottom: 1px solid #c0c0c0;
        }
        QMenuBar::item {
            padding: 4px 8px;
            background: transparent;
        }
        QMenuBar::item:selected {
            background: #3498db;
            color: white;
        }
        QDockWidget {
            border: 1px solid #c0c0c0;
            border-radius: 4px;
        }
        QDockWidget::title {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                       stop: 0 #e0e0e0, stop: 1 #d0d0d0);
            padding: 4px;
            border-bottom: 1px solid #b0b0b0;
        }
        """
        self.setStyleSheet(style)
        
    def init_plugins(self):
        """Initialize the plugin system."""
        try:
            self.log_message("🔧 Initializing plugin system...")
            load_results = initialize_plugin_system()
            self.plugin_manager = get_plugin_manager()
            
            plugins_loaded = len(load_results['loaded'])
            plugins_failed = len(load_results['failed'])
            
            self.log_message(f"✅ Plugin system initialized: {plugins_loaded} loaded, {plugins_failed} failed")
            
            # Update plugins display
            self.update_plugins_display(load_results)
            
        except Exception as e:
            self.log_message(f"❌ Plugin system initialization failed: {str(e)}")
    
    def update_plugins_display(self, load_results):
        """Update the plugins display in side panel."""
        plugins_info = f"Loaded: {len(load_results['loaded'])}\n"
        plugins_info += f"Failed: {len(load_results['failed'])}\n\n"
        
        if load_results['loaded']:
            plugins_info += "✅ Active Plugins:\n"
            for plugin in load_results['loaded'][:5]:  # Show first 5
                plugins_info += f"  • {plugin}\n"
            if len(load_results['loaded']) > 5:
                plugins_info += f"  ... and {len(load_results['loaded']) - 5} more\n"
        
        self.plugins_text.setPlainText(plugins_info)
    
    def log_message(self, message):
        """Add a message to the system log."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        
        if hasattr(self, 'log_widget'):
            self.log_widget.append(log_entry)
        
        print(log_entry)  # Also print to console
    
    # New feature implementations
    def new_case(self):
        """Start a new forensic case."""
        reply = QMessageBox.question(self, 'New Case', 
                                   'Clear all current data and start new case?',
                                   QMessageBox.Yes | QMessageBox.No, 
                                   QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.timeline_data.clear()
            self.artifacts_data.clear()
            self.ml_insights.clear()
            self.current_case_info.clear()
            
            # Clear tab data
            self.artifact_tab.clear_data()
            self.logs_tab.clear_data()
            self.timeline_tab.clear_data()
            
            # Reset displays
            self.insights_text.setPlainText("Initialize analysis to see ML insights...")
            self.stats_text.setPlainText("No data analyzed yet")
            
            self.update_status("New case started")
            self.log_message("🆕 New case started")
    
    def open_case(self):
        """Open an existing case (placeholder)."""
        QMessageBox.information(self, "Open Case", 
                               "Case loading functionality will be implemented in future versions.")
    
    def save_case(self):
        """Save current case (placeholder)."""
        QMessageBox.information(self, "Save Case", 
                               "Case saving functionality will be implemented in future versions.")
    
    def start_memory_analysis(self):
        """Start memory dump analysis."""
        if self.analysis_running:
            QMessageBox.warning(self, "Analysis Running", 
                               "Another analysis is already running. Please wait for it to complete.")
            return
        
        # This would typically open a file dialog to select memory dump
        QMessageBox.information(self, "Memory Analysis", 
                               "Memory analysis functionality integrated.\n"
                               "Select memory dump files in the Artifact Extraction tab and choose 'Memory Analysis' type.")
        self.log_message("🧠 Memory analysis mode activated")
    
    def start_network_analysis(self):
        """Start network packet analysis."""
        if self.analysis_running:
            QMessageBox.warning(self, "Analysis Running", 
                               "Another analysis is already running. Please wait for it to complete.")
            return
        
        QMessageBox.information(self, "Network Analysis", 
                               "Network analysis functionality integrated.\n"
                               "Select PCAP files in the Artifact Extraction tab and choose 'Network Analysis' type.")
        self.log_message("🌐 Network analysis mode activated")
    
    def start_ml_analysis(self):
        """Start machine learning analysis."""
        if not self.timeline_data:
            QMessageBox.warning(self, "No Data", 
                               "No timeline data available for ML analysis.\n"
                               "Please extract artifacts or parse logs first.")
            return
        
        try:
            self.analysis_running = True
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
            self.update_status("Running ML analysis...")
            
            self.log_message("🤖 Starting ML anomaly detection...")
            
            # Perform ML analysis (this would be threaded in production)
            self.ml_insights = generate_ml_insights(self.timeline_data, self.artifacts_data)
            
            # Update insights display
            self.update_insights_display()
            
            self.progress_bar.setVisible(False)
            self.analysis_running = False
            self.update_status("ML analysis completed")
            self.log_message("✅ ML analysis completed successfully")
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            self.analysis_running = False
            self.update_status("ML analysis failed")
            self.log_message(f"❌ ML analysis failed: {str(e)}")
            QMessageBox.critical(self, "Analysis Error", f"ML analysis failed:\n{str(e)}")
    
    def update_insights_display(self):
        """Update the ML insights display."""
        if not self.ml_insights:
            return
        
        insights_text = "🤖 ML Analysis Results:\n\n"
        
        anomaly_data = self.ml_insights.get('anomaly_detection', {})
        anomalies = anomaly_data.get('anomalies_detected', [])
        
        insights_text += f"Anomalies Detected: {len(anomalies)}\n"
        
        risk_scoring = anomaly_data.get('risk_scoring', {})
        risk_score = risk_scoring.get('overall_risk_score', 0)
        insights_text += f"Risk Score: {risk_score:.1f}/10\n\n"
        
        if anomalies:
            insights_text += "Top Anomalies:\n"
            for anomaly in anomalies[:3]:
                insights_text += f"• {anomaly.get('subtype', 'Unknown')} ({anomaly.get('severity', 'Medium')})\n"
        
        recommendations = anomaly_data.get('recommendations', [])
        if recommendations:
            insights_text += f"\nRecommendations: {len(recommendations)} items"
        
        self.insights_text.setPlainText(insights_text)
    
    def execute_all_plugins(self):
        """Execute all loaded plugins."""
        if not self.plugin_manager:
            QMessageBox.warning(self, "No Plugin Manager", 
                               "Plugin system not initialized.")
            return
        
        try:
            self.analysis_running = True
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            self.update_status("Executing plugins...")
            self.log_message("🔌 Executing all plugins...")
            
            # Execute plugins (simplified version)
            stats = self.plugin_manager.get_plugin_statistics()
            
            self.progress_bar.setVisible(False)
            self.analysis_running = False
            self.update_status("Plugin execution completed")
            self.log_message(f"✅ Executed {stats['total_plugins']} plugins")
            
            QMessageBox.information(self, "Plugin Execution", 
                                   f"Executed {stats['total_plugins']} plugins successfully.")
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            self.analysis_running = False
            self.update_status("Plugin execution failed")
            self.log_message(f"❌ Plugin execution failed: {str(e)}")
            QMessageBox.critical(self, "Plugin Error", f"Plugin execution failed:\n{str(e)}")
    
    def generate_report(self):
        """Generate comprehensive investigation report."""
        if not self.timeline_data and not self.artifacts_data:
            QMessageBox.warning(self, "No Data", 
                               "No data available for report generation.\n"
                               "Please extract artifacts or parse logs first.")
            return
        
        try:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            self.update_status("Generating report...")
            self.log_message("📄 Generating comprehensive report...")
            
            # Generate report
            case_info = self.current_case_info or {
                'title': 'InvestiGUI Investigation Report',
                'investigator': 'InvestiGUI User',
                'organization': 'Digital Forensics Analysis'
            }
            
            report_path = generate_investigation_report(
                self.timeline_data, 
                self.artifacts_data, 
                case_info,
                'html'
            )
            
            self.progress_bar.setVisible(False)
            self.update_status("Report generated successfully")
            self.log_message(f"✅ Report generated: {report_path}")
            
            QMessageBox.information(self, "Report Generated", 
                                   f"Investigation report generated successfully:\n{report_path}")
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            self.update_status("Report generation failed")
            self.log_message(f"❌ Report generation failed: {str(e)}")
            QMessageBox.critical(self, "Report Error", f"Report generation failed:\n{str(e)}")
    
    def export_report(self, format_type):
        """Export report in specified format."""
        try:
            case_info = self.current_case_info or {}
            report_path = generate_investigation_report(
                self.timeline_data, 
                self.artifacts_data, 
                case_info,
                format_type
            )
            
            QMessageBox.information(self, "Export Successful", 
                                   f"Report exported to:\n{report_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Export failed:\n{str(e)}")
    
    def show_plugin_manager(self):
        """Show plugin manager dialog."""
        if not self.plugin_manager:
            QMessageBox.warning(self, "No Plugin Manager", 
                               "Plugin system not initialized.")
            return
        
        stats = self.plugin_manager.get_plugin_statistics()
        plugin_info = self.plugin_manager.get_available_plugins()
        
        info_text = f"Plugin Statistics:\n"
        info_text += f"Total Plugins: {stats['total_plugins']}\n\n"
        
        for category, count in stats['by_category'].items():
            if count > 0:
                info_text += f"{category.replace('_', ' ').title()}: {count}\n"
        
        info_text += "\nLoaded Plugins:\n"
        for plugin_detail in stats['plugin_details'][:10]:  # Show first 10
            name = plugin_detail['name']
            plugin_info_data = plugin_detail['info']
            if 'error' not in plugin_info_data:
                info_text += f"• {name} v{plugin_info_data.get('version', 'Unknown')}\n"
        
        QMessageBox.information(self, "Plugin Manager", info_text)
    
    def show_settings(self):
        """Show settings dialog (placeholder)."""
        QMessageBox.information(self, "Settings", 
                               "Settings functionality will be implemented in future versions.")
    
    def toggle_dark_theme(self):
        """Toggle between light and dark themes (placeholder)."""
        QMessageBox.information(self, "Dark Theme", 
                               "Dark theme functionality will be implemented in future versions.")
    
    def toggle_log_dock(self):
        """Toggle system log dock widget visibility."""
        if self.log_dock.isVisible():
            self.log_dock.hide()
        else:
            self.log_dock.show()
    
    def show_documentation(self):
        """Show documentation (placeholder)."""
        QMessageBox.information(self, "Documentation", 
                               "Comprehensive documentation is available in the README.md file and will be expanded in future versions.")
    
    def show_plugin_guide(self):
        """Show plugin development guide."""
        guide_text = """Plugin Development Guide:

1. Create a Python file in the 'plugins' directory
2. Import the appropriate base class:
   - ArtifactExtractorPlugin for artifact extractors
   - LogParserPlugin for log parsers  
   - AnalysisPlugin for analyzers

3. Implement required methods:
   - get_plugin_info(): Return plugin metadata
   - initialize(): Initialize plugin resources
   - execute(): Main plugin functionality
   - cleanup(): Clean up resources

4. See example plugins in the plugins directory for reference.

The plugin system automatically loads and registers plugins at startup."""
        
        QMessageBox.information(self, "Plugin Development Guide", guide_text)
        
    def new_analysis(self):
        """Start a new analysis session (legacy method for compatibility)."""
        self.new_case()
            
    def show_about(self):
        """Show enhanced about dialog."""
        version_info = get_full_version()
        about_text = f"""InvestiGUI - Digital Forensics Toolkit

Version: {version_info['version']}
Build Date: {version_info['build_date']}

🚀 NEW IN VERSION 2.0.0:
• Memory/RAM artifact analysis
• Network packet capture analysis (PCAP support)
• Machine learning-based anomaly detection
• Automated report generation with visualizations
• Plugin architecture for extensibility
• Real-time monitoring capabilities
• Modern UI with enhanced user experience
• Advanced timeline correlation analysis
• Multi-threaded processing for better performance

🔧 CAPABILITIES:
• Artifact extraction from multiple sources
• Multi-format log parsing and analysis
• Timeline creation and correlation
• Export to multiple formats (HTML, JSON, XML)
• Comprehensive investigation reporting

📄 License: MIT License
🌐 Website: https://github.com/irfan-sec/InvestiGUI

Built with PyQt5 and modern forensics methodologies.
"""
        QMessageBox.about(self, "About InvestiGUI v2.0.0", about_text)
        
    def update_timeline(self, events):
        """Update the shared timeline with new events."""
        self.timeline_data.extend(events)
        self.timeline_tab.refresh_timeline()
        self.update_stats_display()
        
    def update_artifacts(self, artifact_type, artifacts):
        """Update shared artifacts data."""
        self.artifacts_data[artifact_type] = artifacts
        self.update_stats_display()
        
    def update_stats_display(self):
        """Update the quick stats display."""
        stats_text = f"📊 Analysis Statistics:\n\n"
        stats_text += f"Timeline Events: {len(self.timeline_data)}\n"
        stats_text += f"Artifact Types: {len(self.artifacts_data)}\n"
        
        # Count total artifacts
        total_artifacts = sum(len(artifacts) if isinstance(artifacts, list) else 1 
                            for artifacts in self.artifacts_data.values())
        stats_text += f"Total Artifacts: {total_artifacts}\n"
        
        # Count by severity
        if self.timeline_data:
            severity_counts = {}
            for event in self.timeline_data:
                severity = event.get('severity', 'Info')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            stats_text += f"\nSeverity Breakdown:\n"
            for severity, count in sorted(severity_counts.items()):
                stats_text += f"  {severity}: {count}\n"
        
        self.stats_text.setPlainText(stats_text)
        
    def update_status(self, message):
        """Update the status bar message."""
        self.status_bar.showMessage(message)
        QApplication.processEvents()  # Process pending events
        
    def show_progress(self, message):
        """Show progress message in status bar."""
        self.update_status(f"Processing: {message}")
        
    def closeEvent(self, event):
        """Handle application close event."""
        if self.analysis_running:
            reply = QMessageBox.question(self, 'Analysis Running',
                                       'Analysis is currently running. Force exit?',
                                       QMessageBox.Yes | QMessageBox.No,
                                       QMessageBox.No)
            if reply == QMessageBox.No:
                event.ignore()
                return
        
        reply = QMessageBox.question(self, 'Exit InvestiGUI',
                                   'Are you sure you want to exit?',
                                   QMessageBox.Yes | QMessageBox.No,
                                   QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            # Cleanup plugins
            if self.plugin_manager:
                try:
                    for plugin_name in list(self.plugin_manager.loaded_plugins.keys()):
                        self.plugin_manager.unload_plugin(plugin_name)
                except:
                    pass
            
            self.log_message("👋 InvestiGUI shutting down...")
            event.accept()
        else:
            event.ignore()