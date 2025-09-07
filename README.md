# InvestiGUI - Digital Forensics Toolkit

A Python-based, open-source digital forensics toolkit with a graphical user interface for artifact extraction, log parsing, and timeline analysis. InvestiGUI provides forensics investigators with an intuitive GUI for analyzing disk images, system logs, and various digital artifacts.

## Features

### 🔍 Artifact Extraction
- **Browser History**: Extract browsing history from Chrome, Firefox, Edge, and Safari
- **USB Devices**: Analyze USB device connection history and mounted drives
- **WiFi Networks**: Extract saved WiFi network profiles and connection logs
- **Recent Files**: Parse recently accessed files from various sources (LNK files, Jump Lists, MRU lists)
- **Prefetch Files**: Analyze Windows Prefetch files for program execution history

### 📝 Log Parsing
- **Windows Event Logs**: Parse .evtx files for security, system, and application events
- **Linux System Logs**: Analyze syslog, auth.log, kernel logs, and web server logs  
- **Browser Logs**: Extract console logs, crash reports, and navigation history
- **Custom Filtering**: Filter by date range, log level, event type, and keywords

### ⏰ Timeline Analysis
- **Unified Timeline**: Merge artifacts and log events into a chronological timeline
- **Advanced Filtering**: Filter by date, type, source, and search text
- **Interactive Display**: Sortable and searchable event tables
- **Pattern Analysis**: Detect anomalies and suspicious activity patterns

### 📊 Export & Reporting
- **Multiple Formats**: Export results in CSV, JSON, and HTML formats
- **Detailed Reports**: Generate comprehensive investigation reports
- **Screenshot Capture**: Document findings with integrated screenshots

## Screenshot

![InvestiGUI Main Interface](screenshot.png)
*Main interface showing the tabbed layout with artifact extraction, log parsing, and timeline analysis*

## Installation

### Prerequisites
- Python 3.7 or higher
- PyQt5 for the GUI framework
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

3. **Run the application**:
   ```bash
   python main.py
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

## Usage Guide

### 1. Artifact Extraction

1. **Select Source**: Choose your evidence source:
   - **Disk Image**: .dd, .img, .e01 forensic images
   - **Live System**: Analyze the current running system  
   - **Directory**: Specific folder containing user data

2. **Choose Artifact Types**: Select which artifacts to extract:
   - ✅ Browser History
   - ✅ USB History  
   - ✅ WiFi Networks
   - ✅ Recent Files

3. **Start Extraction**: Click "Start Extraction" to begin analysis
   - Progress bar shows current status
   - Results appear in the table below
   - Log shows detailed extraction information

4. **Review Results**: 
   - Sort and filter results in the interactive table
   - Click rows to see detailed information
   - Export results for further analysis

### 2. Log Parsing

1. **Select Log Sources**:
   - **Single File**: Choose specific log file (.evtx, .log, .txt)
   - **Directory**: Select folder containing multiple log files
   - **Auto-detection**: Automatically detect log format

2. **Configure Filters**:
   - **Date Range**: Specify start and end dates
   - **Log Level**: Filter by ERROR, WARNING, INFO, DEBUG
   - **Max Events**: Limit number of events to process

3. **Parse Logs**: Click "Start Parsing" to process log files
   - Real-time progress updates
   - Parsed events appear in structured table
   - Raw log viewer shows original content

4. **Analyze Events**:
   - Use built-in filters to find relevant events
   - Export filtered results for reporting

### 3. Timeline Analysis

1. **Automatic Population**: Timeline automatically updates as you extract artifacts and parse logs

2. **Filter Timeline**:
   - **Date Range**: Focus on specific time periods
   - **Event Type**: Show only certain types of events
   - **Source Filter**: Filter by data source
   - **Text Search**: Search event descriptions and details

3. **Interactive Analysis**:
   - Sort events chronologically
   - Click events to see full details
   - Identify patterns and correlations

4. **Export Timeline**: Save complete timeline for reporting

## Project Structure

```
InvestiGUI/
├── main.py                 # Application entry point
├── gui/                    # GUI components
│   ├── __init__.py
│   ├── main_window.py      # Main application window
│   ├── tabs/               # Individual tab implementations
│   │   ├── artifact_tab.py # Artifact extraction interface
│   │   ├── logs_tab.py     # Log parsing interface
│   │   └── timeline_tab.py # Timeline analysis interface
│   └── widgets.py          # Custom UI widgets
├── artifacts/              # Artifact extraction modules
│   ├── __init__.py
│   ├── browser.py          # Browser history extraction
│   ├── usb.py              # USB device history
│   ├── wifi.py             # WiFi network profiles
│   └── files.py            # Recent files and MRU lists
├── logs/                   # Log parsing modules
│   ├── __init__.py
│   ├── windows.py          # Windows Event Log parser
│   ├── linux.py            # Linux system log parser
│   └── browser.py          # Browser log parser
├── timeline.py             # Timeline processing and analysis
├── utils.py                # Utility functions
├── requirements.txt        # Python dependencies
├── README.md              # This file
└── examples/              # Example data and scripts
    ├── sample_logs/
    └── test_artifacts/
```

## Supported File Types

### Evidence Sources
- **Disk Images**: .dd, .img, .e01, .aff
- **Virtual Machines**: .vmdk, .vdi, .vhd
- **Live Systems**: Direct system analysis
- **Directories**: User profiles, application data

### Log Formats
- **Windows**: .evtx (Event Logs), .log files
- **Linux**: syslog, auth.log, kern.log, dmesg
- **Web Servers**: Apache access/error logs, Nginx logs
- **Applications**: Browser console logs, crash reports

### Artifact Sources
- **Browsers**: Chrome, Firefox, Edge, Safari databases
- **System**: Registry hives, Prefetch files, LNK shortcuts
- **Network**: WiFi profiles, network configurations
- **Storage**: USB device history, mounted drives

## Advanced Features

### Custom Parsers
InvestiGUI is designed to be extensible. You can add custom parsers by:

1. Creating a new module in the appropriate directory (`artifacts/` or `logs/`)
2. Implementing the required interface methods
3. Registering your parser in the GUI

### Batch Processing
For large-scale investigations, InvestiGUI supports:
- Processing multiple evidence sources
- Batch export of results
- Automated report generation

### Integration Capabilities
- Export to other forensics tools
- JSON API for programmatic access
- Plugin architecture for extensions

## Performance Considerations

### System Requirements
- **Minimum**: 4GB RAM, 2GB free disk space
- **Recommended**: 8GB+ RAM, SSD storage
- **Large Cases**: 16GB+ RAM for processing large disk images

### Optimization Tips
- Process smaller date ranges for faster results
- Use SSD storage for temporary files
- Close other applications during intensive analysis
- Consider processing artifacts separately for large cases

## Troubleshooting

### Common Issues

1. **Database Lock Errors**:
   - Close browsers before analyzing their databases
   - InvestiGUI creates temporary copies to avoid locks

2. **Permission Denied**:
   - Run as administrator/root for system-level artifacts
   - Check file permissions on evidence sources

3. **Memory Issues**:
   - Reduce max events limit in log parsing
   - Process smaller date ranges
   - Ensure sufficient RAM for large cases

4. **Missing Dependencies**:
   ```bash
   pip install --upgrade -r requirements.txt
   ```

### Getting Help
- Check the [Issues](https://github.com/irfan-sec/InvestiGUI/issues) page for known problems
- Review log files for error details
- Enable debug mode for verbose logging

## Development

### Contributing
Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

### Building from Source
```bash
git clone https://github.com/irfan-sec/InvestiGUI.git
cd InvestiGUI
pip install -r requirements.txt
python main.py
```

### Testing
```bash
# Run basic functionality tests
python -m pytest tests/

# Test with sample data
python examples/test_extraction.py
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with PyQt5 for cross-platform GUI support
- Inspired by open-source forensics tools and methodologies
- Thanks to the digital forensics community for research and standards

## Disclaimer

InvestiGUI is intended for legitimate forensics investigations and educational purposes. Users are responsible for ensuring they have proper authorization before analyzing systems or data. The authors are not responsible for any misuse of this tool.

---

**InvestiGUI** - Making Digital Forensics Accessible