# InvestiGUI v2.0.0 - Digital Forensics Toolkit

A Python-based, open-source digital forensics toolkit with a graphical user interface for artifact extraction, log parsing, timeline analysis, and advanced forensic capabilities. InvestiGUI v2.0.0 provides forensics investigators with an intuitive GUI and powerful new features for analyzing disk images, system logs, memory dumps, network traffic, and various digital artifacts.

## 🚀 What's New in v2.0.0

### Major New Features
- **🧠 Memory/RAM Analysis**: Complete memory dump processing and analysis
- **🌐 Network Packet Analysis**: PCAP file analysis with threat detection
- **🤖 Machine Learning**: AI-powered anomaly detection and pattern recognition
- **🔌 Plugin Architecture**: Extensible system for custom analyzers
- **📄 Advanced Reporting**: Automated report generation with visualizations
- **🎨 Modern UI**: Enhanced interface with insights panel and improved UX
- **⚡ Multi-threading**: Better performance for large dataset processing

## Features

### 🔍 Artifact Extraction
- **Browser History**: Extract browsing history from Chrome, Firefox, Edge, and Safari
- **USB Devices**: Analyze USB device connection history and mounted drives
- **WiFi Networks**: Extract saved WiFi network profiles and connection logs
- **Recent Files**: Parse recently accessed files from various sources (LNK files, Jump Lists, MRU lists)
- **Prefetch Files**: Analyze Windows Prefetch files for program execution history
- **Memory Dumps**: 🆕 Extract artifacts from memory dumps (.dmp, .mem, .vmem)
- **Network Traffic**: 🆕 Analyze PCAP files for network forensics

### 📝 Log Parsing
- **Windows Event Logs**: Parse .evtx files for security, system, and application events
- **Linux System Logs**: Analyze syslog, auth.log, kernel logs, and web server logs  
- **Browser Logs**: Extract console logs, crash reports, and navigation history
- **Custom Logs**: 🆕 Plugin-based parsing for custom log formats
- **Advanced Filtering**: Filter by date range, log level, event type, and keywords

### ⏰ Timeline Analysis
- **Unified Timeline**: Merge artifacts and log events into a chronological timeline
- **Advanced Filtering**: Filter by date, type, source, and search text
- **Interactive Display**: Sortable and searchable event tables
- **Pattern Analysis**: 🆕 AI-powered detection of anomalies and suspicious activity patterns
- **Correlation Engine**: 🆕 Identify relationships between events

### 🤖 Machine Learning & AI
- **Anomaly Detection**: Automatically identify unusual patterns in timeline data
- **Risk Scoring**: AI-powered risk assessment with confidence weighting
- **Behavioral Analysis**: Detect deviations from normal system/user behavior
- **Threat Hunting**: ML-assisted identification of suspicious activities
- **Pattern Recognition**: Advanced text and temporal pattern analysis

### 🔌 Plugin System
- **Extensible Architecture**: Create custom artifact extractors and analyzers
- **Plugin Manager**: Load, unload, and manage plugins at runtime
- **Example Plugins**: Custom registry extractor, log parser, and threat hunter
- **Easy Development**: Simple plugin API with comprehensive documentation

### 📊 Advanced Reporting & Visualizations
- **Multi-format Reports**: Generate HTML, JSON, and XML reports
- **Executive Summaries**: Automated high-level findings and recommendations
- **Risk Assessment**: Comprehensive risk scoring and threat analysis
- **Visualizations**: 🆕 Charts, graphs, and timeline visualizations
- **Export Options**: Multiple output formats for integration with other tools

### 🧠 Memory Analysis Capabilities
- **Process Extraction**: Extract running processes with command lines and memory usage
- **Network Connections**: Identify network connections from memory dumps
- **Loaded Modules**: Analyze loaded DLLs and modules
- **Registry Artifacts**: Extract registry keys and values from memory
- **String Analysis**: Search for suspicious strings and patterns
- **Malware Detection**: Identify potential malware artifacts in memory

### 🌐 Network Analysis Features
- **PCAP Processing**: Support for .pcap, .pcapng, and .cap files
- **Traffic Analysis**: Detailed analysis of network conversations
- **Protocol Distribution**: TCP, UDP, ICMP, and other protocol analysis
- **Threat Detection**: Identify port scanning, DNS tunneling, and data exfiltration
- **DNS Analysis**: Suspicious domain detection and query analysis
- **HTTP/HTTPS**: Web traffic analysis and credential detection
- **IOC Extraction**: Automatic extraction of Indicators of Compromise

## Screenshot

![InvestiGUI Main Interface](screenshot.png)
*Enhanced v2.0.0 interface showing new capabilities including ML insights panel, modern toolbar, and comprehensive analysis features*

## Installation

### Prerequisites
- Python 3.7 or higher
- PyQt5 for the GUI framework (optional for CLI-only usage)
- Additional dependencies listed in requirements.txt

### Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/irfan-sec/InvestiGUI.git
   cd InvestiGUI
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize plugin system**:
   ```bash
   python main.py --init-plugins
   ```

4. **Run the application**:
   ```bash
   # GUI mode (requires PyQt5)
   python main.py
   
   # CLI mode
   python main.py --cli
   
   # Demo mode
   python main.py --demo
   ```

### Professional Installation

For production use, install as a package:

```bash
# Install from source
pip install -e .

# Or install specific features
pip install -e ".[analysis,docs]"

# Use entry points
investigui                    # Start GUI
investigui-cli               # Start CLI
investigui-demo              # Run demo
```

### Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv investigui-env

# Activate virtual environment
# On Windows:
investigui-env\Scripts\activate
# On Linux/macOS:
source investigui-env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run application
python main.py
```

## 🚀 Quick Start Guide v2.0.0

### Command Line Interface

```bash
# Show version and capabilities
python main.py --version

# Initialize plugin system
python main.py --init-plugins

# List available plugins
python main.py --plugins

# Run comprehensive demo
python main.py --demo

# Start interactive CLI
python main.py --cli

# Force CLI mode (no GUI)
python main.py --no-gui
```

### New Analysis Capabilities

#### Memory Analysis
```bash
# Analyze memory dumps
python -c "
from artifacts.memory import MemoryArtifacts
analyzer = MemoryArtifacts()
results = analyzer.analyze_memory_dump('path/to/memory.dmp')
print(f'Found {len(results[\"processes\"])} processes')
"
```

#### Network Analysis  
```bash
# Analyze PCAP files
python -c "
from artifacts.network import NetworkAnalyzer
analyzer = NetworkAnalyzer()
results = analyzer.analyze_pcap_file('path/to/capture.pcap')
print(f'Found {len(results[\"conversations\"])} conversations')
"
```

#### ML Anomaly Detection
```bash
# Run ML analysis on timeline data
python -c "
from ml_analysis import perform_anomaly_detection
# ... timeline_data ...
results = perform_anomaly_detection(timeline_data)
print(f'Detected {len(results[\"anomalies_detected\"])} anomalies')
"
```

## 📋 Usage Guide v2.0.0

### 1. Modern GUI Interface

The enhanced GUI includes:
- **Main Analysis Tabs**: Artifact Extraction, Log Parser, Timeline Viewer
- **Insights Panel**: Real-time ML analysis results and risk scoring  
- **Plugin Status**: Active plugins and system status
- **System Log**: Comprehensive activity logging
- **Modern Toolbar**: Quick access to new analysis features

#### New Toolbar Features
- 🆕 **New Case**: Start fresh investigation
- 🧠 **Memory Analysis**: Analyze memory dumps
- 🌐 **Network Analysis**: Process PCAP files
- 🤖 **ML Analysis**: Run AI-powered anomaly detection
- 📄 **Generate Report**: Create comprehensive investigation reports
- 🔌 **Plugin Manager**: Manage and execute plugins

### 2. Enhanced Artifact Extraction

#### Traditional Artifacts
1. **Select Source**: Choose your evidence source:
   - **Disk Image**: .dd, .img, .e01 forensic images
   - **Live System**: Analyze the current running system  
   - **Directory**: Specific folder containing user data

2. **Choose Artifact Types**: Select which artifacts to extract:
   - ✅ Browser History
   - ✅ USB History  
   - ✅ WiFi Networks
   - ✅ Recent Files

#### 🆕 New Artifact Types
- **Memory Analysis**: 
  - Select .dmp, .mem, .raw, .vmem files
  - Extract processes, network connections, loaded modules
  - Identify suspicious strings and patterns
  
- **Network Analysis**:
  - Select .pcap, .pcapng, .cap files  
  - Analyze network conversations and protocols
  - Detect suspicious activity and IOCs

### 3. Advanced Log Parsing

#### Enhanced Log Processing
1. **Select Log Sources**:
   - **Single File**: Choose specific log file (.evtx, .log, .txt)
   - **Directory**: Select folder containing multiple log files
   - **Auto-detection**: Automatically detect log format
   - 🆕 **Plugin-based**: Use custom log parsers

2. **Configure Advanced Filters**:
   - **Date Range**: Specify start and end dates
   - **Log Level**: Filter by ERROR, WARNING, INFO, DEBUG
   - **Max Events**: Limit number of events to process
   - 🆕 **ML Filtering**: AI-powered relevant event detection

### 4. 🤖 AI-Powered Timeline Analysis

#### Machine Learning Features
1. **Automatic Anomaly Detection**:
   - Temporal anomalies (after-hours activity, event bursting)
   - Frequency anomalies (unusual event patterns)  
   - Pattern anomalies (suspicious text content)
   - Behavioral anomalies (user/system behavior changes)

2. **Risk Assessment**:
   - Overall risk scoring (0-10 scale)
   - Confidence-weighted analysis
   - Severity breakdown and recommendations
   - Pattern correlation identification

3. **Interactive Analysis**:
   - Real-time insights in side panel
   - Automated recommendation generation  
   - Advanced filtering with ML assistance
   - Export ML analysis results

### 5. 🔌 Plugin System

#### Using Plugins
1. **Plugin Management**:
   ```bash
   # Initialize plugins
   python main.py --init-plugins
   
   # List available plugins  
   python main.py --plugins
   ```

2. **Plugin Execution**:
   - Automatic execution during analysis
   - Manual execution via Plugin Manager
   - Custom plugin development support

#### Creating Custom Plugins
1. **Plugin Types**:
   - **Artifact Extractors**: Custom artifact extraction
   - **Log Parsers**: Custom log format support
   - **Analyzers**: Custom analysis algorithms

2. **Development Process**:
   ```python
   # Example plugin structure
   from plugin_manager import ArtifactExtractorPlugin
   
   class MyCustomExtractor(ArtifactExtractorPlugin):
       def extract_artifacts(self, source_path):
           # Custom extraction logic
           return artifacts
   ```

### 6. 📄 Advanced Reporting

#### Report Generation
1. **Automatic Reports**:
   - Click "Generate Report" in toolbar
   - Comprehensive HTML reports with styling
   - Executive summaries and technical details
   - Charts and visualizations

2. **Export Options**:
   - **HTML**: Web-viewable reports with styling
   - **JSON**: Structured data for integration
   - **XML**: Standard format for processing
   - **Custom**: Plugin-based custom formats

#### Report Contents
- **Executive Summary**: High-level findings and risk assessment
- **Timeline Analysis**: Event correlation and patterns  
- **Artifact Summary**: Detailed artifact breakdown
- **ML Insights**: AI-powered analysis results
- **Recommendations**: Automated investigative guidance
- **Technical Appendices**: Raw data and technical details

## 🏗️ Project Structure v2.0.0

```
InvestiGUI/
├── main.py                     # Enhanced application entry point with CLI
├── version.py                  # 🆕 Version management and release info
├── setup.py                    # 🆕 Professional packaging configuration
├── CHANGELOG.md                # 🆕 Comprehensive version history
├── requirements.txt            # Updated dependencies
├── README.md                   # Enhanced documentation
├── demo.py                     # Enhanced CLI demonstration mode
├── gui/                        # GUI components
│   ├── __init__.py
│   ├── main_window.py          # 🔄 Enhanced main interface with new features
│   ├── tabs/                   # Individual tab implementations
│   │   ├── artifact_tab.py     # Artifact extraction interface
│   │   ├── logs_tab.py         # Log parsing interface
│   │   └── timeline_tab.py     # Timeline analysis interface
│   └── widgets.py              # Custom UI widgets
├── artifacts/                  # Artifact extraction modules
│   ├── __init__.py             # 🔄 Updated with new modules
│   ├── browser.py              # Browser history extraction
│   ├── usb.py                  # USB device history
│   ├── wifi.py                 # WiFi network profiles
│   ├── files.py                # Recent files and MRU lists
│   ├── memory.py               # 🆕 Memory dump analysis
│   └── network.py              # 🆕 Network packet analysis
├── logs/                       # Log parsing modules
│   ├── __init__.py
│   ├── windows.py              # Windows Event Log parser
│   ├── linux.py                # Linux system log parser
│   └── browser.py              # Browser log parser
├── plugins/                    # 🆕 Plugin system
│   ├── custom_registry_extractor.py     # Example artifact extractor plugin
│   ├── custom_app_log_parser.py         # Example log parser plugin
│   └── custom_threat_hunter.py          # Example analysis plugin
├── timeline.py                 # Timeline processing and analysis
├── utils.py                    # Utility functions
├── ml_analysis.py              # 🆕 Machine learning and anomaly detection
├── reporting.py                # 🆕 Advanced report generation
├── plugin_manager.py           # 🆕 Plugin architecture system
└── examples/                   # Example data and scripts
    ├── sample_logs/
    └── test_artifacts/
```

### 🆕 New Components

#### Core Enhancements
- **version.py**: Centralized version management with release notes
- **setup.py**: Professional Python package configuration
- **CHANGELOG.md**: Detailed version history and migration guide

#### Advanced Analysis
- **ml_analysis.py**: Machine learning-powered anomaly detection
- **reporting.py**: Automated report generation with visualizations  
- **plugin_manager.py**: Extensible plugin architecture

#### New Artifact Types
- **artifacts/memory.py**: Memory dump analysis capabilities
- **artifacts/network.py**: Network packet analysis and forensics

#### Plugin Ecosystem
- **plugins/**: Example plugins demonstrating extensibility
- Plugin types: Artifact extractors, log parsers, analysis engines

## 🔧 Supported File Types & Evidence Sources

### Evidence Sources
- **Disk Images**: .dd, .img, .e01, .aff, .vmdk, .vdi, .vhd
- **Memory Dumps**: 🆕 .dmp, .mem, .raw, .bin, .vmem (Windows/Linux/VMware)
- **Network Captures**: 🆕 .pcap, .pcapng, .cap (Wireshark/tcpdump compatible)  
- **Virtual Machines**: .vmdk, .vdi, .vhd, .ova
- **Live Systems**: Direct system analysis and monitoring
- **Directories**: User profiles, application data, custom paths

### Log Formats
- **Windows**: .evtx (Event Logs), .log files, Security logs
- **Linux**: syslog, auth.log, kern.log, dmesg, audit logs
- **Web Servers**: Apache access/error logs, Nginx logs, IIS logs
- **Applications**: Browser console logs, crash reports, custom formats
- **Network**: 🆕 DNS logs, DHCP logs, firewall logs
- **Security**: 🆕 IDS/IPS logs, antivirus logs, endpoint protection

### Artifact Sources  
- **Browsers**: Chrome, Firefox, Edge, Safari, Opera databases
- **System**: Registry hives, Prefetch files, LNK shortcuts, MFT
- **Network**: WiFi profiles, network configurations, connection history
- **Storage**: USB device history, mounted drives, file access logs
- **Memory**: 🆕 Process memory, heap analysis, network connections
- **Mobile**: 🆕 iOS/Android backups, app data, communication logs

## 🚀 Advanced Features v2.0.0

### 🤖 Machine Learning Capabilities
- **Anomaly Detection**: Multi-layered ML analysis for suspicious patterns
- **Risk Scoring**: AI-powered risk assessment with confidence metrics
- **Pattern Recognition**: Advanced temporal and behavioral analysis
- **Threat Hunting**: ML-assisted identification of APT and malware indicators
- **Behavioral Baselines**: Learn normal patterns to identify deviations

### 🔌 Plugin Architecture
InvestiGUI v2.0.0 features a comprehensive plugin system:

#### Plugin Types
1. **Artifact Extractors**: Custom extraction for new file types
2. **Log Parsers**: Support for proprietary log formats  
3. **Analysis Engines**: Custom analysis algorithms and ML models
4. **Report Generators**: Custom output formats and visualizations

#### Plugin Development
```python
# Example Artifact Extractor Plugin
from plugin_manager import ArtifactExtractorPlugin

class CustomExtractor(ArtifactExtractorPlugin):
    def get_plugin_info(self):
        return {
            'name': 'Custom Artifact Extractor',
            'version': '1.0.0',
            'description': 'Extracts custom artifacts'
        }
    
    def extract_artifacts(self, source_path):
        # Custom extraction logic
        return artifacts
```

#### Plugin Management
- **Automatic Discovery**: Plugins loaded from plugins/ directory
- **Runtime Management**: Load, unload, and reload plugins dynamically
- **Error Handling**: Graceful failure handling for plugin errors
- **Plugin Registry**: Categorized plugin management system

### 🧠 Memory Analysis Deep Dive
Advanced memory forensics capabilities:

#### Process Analysis
- **Process Trees**: Parent-child relationships and execution chains
- **Command Lines**: Full command line arguments and parameters
- **Memory Maps**: Virtual memory layout and permissions
- **Handles**: Open file handles, registry keys, network connections

#### Network Artifacts
- **Active Connections**: Current network connections from memory
- **Historical Connections**: Previously established connections
- **Socket Information**: Detailed socket state and options
- **Protocol Analysis**: TCP/UDP state information

#### Malware Detection
- **Code Injection**: Detect DLL injection and process hollowing
- **Rootkit Detection**: Hidden processes and network connections
- **Persistence Mechanisms**: Registry modifications and service installations
- **IOC Matching**: Compare against known malware indicators

### 🌐 Network Forensics Features

#### Traffic Analysis
- **Flow Analysis**: Detailed network conversation tracking
- **Protocol Reconstruction**: Reassemble application-layer protocols
- **File Carving**: Extract files transferred over the network
- **Credential Extraction**: Identify authentication attempts

#### Threat Detection
- **Intrusion Detection**: Signature-based attack detection
- **Behavioral Analysis**: Identify unusual network patterns
- **C&C Communication**: Detect command and control traffic
- **Data Exfiltration**: Identify large outbound data transfers

#### Forensic Artifacts
- **DNS Analysis**: Suspicious domain queries and responses
- **HTTP/HTTPS**: Web browsing patterns and file downloads
- **Email Traffic**: SMTP/POP3/IMAP communication analysis
- **P2P Detection**: Peer-to-peer file sharing identification

### 📊 Advanced Visualization & Reporting

#### Interactive Charts
- **Timeline Visualizations**: Interactive event timelines
- **Network Graphs**: Visual network communication maps
- **Risk Heatmaps**: Visual risk assessment displays
- **Correlation Matrices**: Event relationship visualization

#### Report Customization
- **Template System**: Customizable report templates
- **Brand Integration**: Organization logos and styling
- **Multi-language**: Internationalization support
- **Export Options**: PDF, Word, PowerPoint integration

### ⚡ Performance & Scalability

#### Multi-threading Architecture
- **Parallel Processing**: Multi-core CPU utilization
- **Streaming Analysis**: Process large files without loading entirely into memory
- **Caching**: Intelligent caching for improved performance
- **Progress Tracking**: Real-time progress indicators

#### Optimization Features
- **Memory Management**: Efficient memory usage for large datasets
- **Disk I/O**: Optimized file reading and writing
- **Database Integration**: Optional database backends for large investigations
- **Distributed Processing**: 🔮 Future support for cluster processing

## 💻 System Requirements

### Minimum Requirements
- **OS**: Windows 10, Linux (Ubuntu 18.04+), macOS 10.14+
- **Python**: 3.7 or higher
- **RAM**: 4GB (8GB recommended for large datasets)
- **Storage**: 2GB free space (more for evidence processing)
- **CPU**: Dual-core processor (quad-core recommended)

### Recommended for Optimal Performance
- **RAM**: 16GB+ for large investigations and memory analysis
- **Storage**: SSD with 10GB+ free space for temporary processing
- **CPU**: 8+ cores for multi-threaded analysis
- **GPU**: 🔮 Future ML acceleration support
- **Network**: High-speed connection for cloud integration

### Performance Optimization Tips

#### For Large Cases
- **Use SSD storage** for evidence and temporary files
- **Increase virtual memory** for memory dump analysis
- **Close other applications** during intensive analysis
- **Process in chunks** for very large datasets (>100GB)
- **Use filtering** to focus on relevant time periods

#### Memory Analysis Optimization
- **Available RAM**: 2x the size of memory dump for optimal performance
- **Virtual Memory**: Set to 3x physical RAM for large dumps
- **Temp Space**: Ensure 5x dump size available for processing
- **64-bit Python**: Required for dumps >4GB

#### Network Analysis Optimization
- **I/O Performance**: Use local SSD storage for PCAP files
- **RAM**: 1GB RAM per 100MB PCAP file for optimal processing
- **CPU**: Multi-core processors significantly improve parsing speed
- **Filtering**: Apply time/protocol filters early to reduce processing load

## 🔧 Troubleshooting v2.0.0

### Common Issues & Solutions

#### Installation Issues
1. **PyQt5 Installation Fails**:
   ```bash
   # On Ubuntu/Debian
   sudo apt-get install python3-pyqt5
   
   # On CentOS/RHEL  
   sudo yum install python3-qt5
   
   # Alternative: Use conda
   conda install pyqt
   ```

2. **Plugin Loading Errors**:
   ```bash
   # Reinitialize plugin system
   python main.py --init-plugins
   
   # Check plugin status
   python main.py --plugins
   ```

3. **Memory/Performance Issues**:
   ```bash
   # Use CLI mode for large datasets
   python main.py --no-gui
   
   # Limit concurrent operations
   # Reduce batch size in config
   ```

#### Analysis Issues
1. **Memory Dump Analysis Fails**:
   - **Check file format**: Ensure .dmp, .mem, .raw format
   - **Free space**: Ensure 3x dump size available  
   - **File permissions**: Verify read access to dump file
   - **Memory**: Close other applications to free RAM

2. **PCAP Analysis Errors**:
   - **File corruption**: Verify PCAP with `tcpdump -r file.pcap`
   - **Large files**: Use filtering or split large captures
   - **Format support**: Ensure .pcap, .pcapng, or .cap format

3. **Plugin Execution Failures**:
   - **Check dependencies**: Ensure plugin requirements met
   - **File permissions**: Verify plugin file is readable
   - **Python path**: Ensure plugin directory in path
   - **Error logs**: Check system log for detailed errors

#### ML Analysis Issues
1. **Anomaly Detection Returns No Results**:
   - **Data volume**: Ensure sufficient events (10+ recommended)
   - **Time span**: Verify events span multiple time periods
   - **Event diversity**: Mix of different event types needed
   - **Threshold tuning**: Adjust sensitivity in settings

2. **Risk Scoring Seems Incorrect**:
   - **Baseline data**: ML improves with more baseline data
   - **Context**: Risk scores are relative to dataset patterns
   - **Manual review**: Always validate ML results manually
   - **Feedback**: Use plugin system to customize scoring

#### Performance Issues
1. **Slow Processing**:
   - **Hardware**: Check CPU, RAM, and disk I/O usage
   - **File size**: Large files require more processing time
   - **Filtering**: Apply filters to reduce data volume
   - **Parallel processing**: Ensure multi-threading enabled

2. **Memory Usage High**:
   - **Close unused tabs**: Reduce memory footprint
   - **Process smaller batches**: Break large analyses into chunks
   - **Temporary files**: Clear temp directory regularly
   - **Virtual memory**: Increase system virtual memory

### Getting Help

#### Self-Help Resources
- **Documentation**: Comprehensive guides in /docs directory
- **Examples**: Sample data and scripts in /examples
- **Plugin Guide**: Plugin development documentation
- **FAQ**: Frequently asked questions and solutions

#### Community Support
- **GitHub Issues**: https://github.com/irfan-sec/InvestiGUI/issues
- **Discussions**: https://github.com/irfan-sec/InvestiGUI/discussions  
- **Wiki**: https://github.com/irfan-sec/InvestiGUI/wiki
- **Contributing**: Guidelines for code contributions

#### Professional Support
- **Bug Reports**: Detailed bug reporting with logs
- **Feature Requests**: Suggest new capabilities
- **Plugin Development**: Custom plugin development assistance
- **Training**: Available for enterprise deployments

## 🤝 Development & Contributing

### Building from Source
```bash
# Clone repository
git clone https://github.com/irfan-sec/InvestiGUI.git
cd InvestiGUI

# Create development environment
python -m venv dev-env
source dev-env/bin/activate  # Linux/macOS
# dev-env\Scripts\activate   # Windows

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run application
python main.py
```

### Development Environment
```bash
# Install additional development tools
pip install -e ".[dev,docs,analysis]"

# Code formatting
black .

# Type checking  
mypy .

# Linting
flake8 .

# Documentation
cd docs && make html
```

### Contributing Guidelines
1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Plugin Development
```bash
# Create new plugin
cp plugins/custom_registry_extractor.py plugins/my_plugin.py

# Edit plugin code
# Implement required methods

# Test plugin
python main.py --init-plugins
python main.py --plugins

# Submit plugin
# Create PR with plugin in plugins/ directory
```

### Testing
```bash
# Run unit tests
pytest tests/unit/

# Run integration tests  
pytest tests/integration/

# Run plugin tests
pytest tests/plugins/

# Generate coverage report
pytest --cov=. --cov-report=html
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

### Core Technologies  
- **PyQt5**: Cross-platform GUI framework for professional interface
- **Python**: Robust programming language for forensics applications
- **Open Source Community**: Inspiration from forensics tools and methodologies

### Research & Standards
- **Digital Forensics Research Workshop (DFRWS)**: Forensics standards and best practices
- **NIST**: Digital forensics guidelines and frameworks  
- **SANS**: Digital forensics and incident response methodologies
- **Academic Research**: ML applications in cybersecurity and forensics

### Community Contributors
- **Security Researchers**: Input on forensics methodologies
- **Plugin Developers**: Extending functionality through plugins
- **Beta Testers**: Quality assurance and usability feedback
- **Documentation Contributors**: Improving user experience

## ⚠️ Legal Disclaimer

**IMPORTANT**: InvestiGUI is intended for legitimate forensics investigations, educational purposes, and authorized security testing only.

### Authorized Use
- ✅ **Forensic Investigations**: Authorized digital forensics examinations
- ✅ **Incident Response**: Legitimate incident response activities  
- ✅ **Security Research**: Authorized security research and testing
- ✅ **Education**: Learning digital forensics methodologies
- ✅ **Compliance**: Meeting regulatory and legal requirements

### User Responsibilities
- 🔒 **Authorization**: Ensure proper authorization before analyzing systems or data
- 📋 **Legal Compliance**: Comply with applicable laws and regulations
- 🔐 **Data Protection**: Protect sensitive information discovered during analysis
- 📊 **Chain of Custody**: Maintain proper evidence handling procedures
- 🚫 **Ethical Use**: Use only for legitimate and ethical purposes

### Limitations
- **No Warranty**: Software provided "as is" without warranty
- **User Liability**: Users responsible for proper and legal use
- **Jurisdiction**: Subject to applicable local and international laws
- **Best Practices**: Follow established forensics and legal procedures

The authors and contributors are not responsible for any misuse of this tool or any legal consequences arising from improper use.

## 🔮 Future Roadmap

### Version 2.1.0 (Planned)
- **Real-time Monitoring**: Live system monitoring and alerting
- **Cloud Integration**: Cloud storage and processing capabilities
- **Advanced Visualizations**: Interactive charts, graphs, and dashboards
- **Mobile Forensics**: iOS and Android device analysis
- **Database Integration**: PostgreSQL/MySQL backends for large investigations

### Version 2.2.0 (Planned)  
- **Team Collaboration**: Multi-user investigation support
- **REST API**: Programmatic access and integration capabilities
- **Dark Theme**: Complete dark mode interface
- **Advanced ML**: Deep learning models for threat detection
- **Encrypted Evidence**: Support for encrypted containers and files

### Version 3.0.0 (Future)
- **Distributed Processing**: Cluster-based analysis for large datasets
- **AI Chatbot**: Natural language queries for investigation assistance
- **Blockchain Evidence**: Cryptocurrency and blockchain analysis
- **IoT Forensics**: Internet of Things device analysis
- **Advanced Correlation**: Graph-based evidence correlation

### Long-term Vision
- **Industry Standard**: Become leading open-source forensics platform
- **Enterprise Ready**: Professional features for large organizations  
- **Global Community**: Worldwide community of contributors and users
- **Certification**: Professional certification and training programs

---

## 📞 Contact & Support

### Project Information
- **GitHub Repository**: https://github.com/irfan-sec/InvestiGUI
- **Documentation**: https://github.com/irfan-sec/InvestiGUI/wiki
- **Issue Tracker**: https://github.com/irfan-sec/InvestiGUI/issues
- **Discussions**: https://github.com/irfan-sec/InvestiGUI/discussions

### Community
- **Contributing Guide**: See CONTRIBUTING.md for development guidelines
- **Code of Conduct**: See CODE_OF_CONDUCT.md for community standards
- **Security Policy**: See SECURITY.md for vulnerability reporting

### Version Information
- **Current Version**: 2.0.0
- **Release Date**: 2024-12-14  
- **License**: MIT License
- **Python Compatibility**: 3.7+

---

**InvestiGUI v2.0.0** - Making Digital Forensics Accessible, Powerful, and Intelligent

*"Next-generation digital forensics with AI-powered analysis and extensible architecture"*