"""
Version information for InvestiGUI
"""

__version__ = "2.0.0"
__version_info__ = (2, 0, 0)

VERSION_MAJOR = 2
VERSION_MINOR = 0
VERSION_PATCH = 0

BUILD_DATE = "2024-12-14"
RELEASE_NOTES = """
InvestiGUI v2.0.0 - Major Update Release

🚀 NEW FEATURES:
- Memory/RAM artifact analysis and dump processing
- Network packet capture and analysis (PCAP support)  
- Automated report generation with charts and visualizations
- Plugin architecture for custom analyzers
- Real-time system monitoring capabilities
- Machine learning-based anomaly detection
- Modern UI with dark theme and improved UX
- Database support (SQLite/PostgreSQL) for large datasets
- Multi-threaded processing for better performance
- Encryption/decryption utilities for protected files
- REST API for programmatic access and integration

🔧 IMPROVEMENTS:
- Enhanced timeline analysis with correlation features
- Improved error handling and logging
- Better memory management for large files
- Advanced filtering and search capabilities
- Export to additional formats (PDF reports, XML)
- Cross-platform compatibility improvements

🐛 BUG FIXES:
- Fixed dependency conflicts with PyQt5
- Improved stability with large dataset processing
- Better handling of corrupted files
- Enhanced error messages and user guidance

📚 DOCUMENTATION:
- Comprehensive API documentation
- Updated user manual with new features
- Video tutorials and examples
- Plugin development guide
"""

def get_version():
    """Get the current version string."""
    return __version__

def get_version_info():
    """Get version info as tuple."""
    return __version_info__

def get_full_version():
    """Get full version information."""
    return {
        'version': __version__,
        'version_info': __version_info__,
        'build_date': BUILD_DATE,
        'major': VERSION_MAJOR,
        'minor': VERSION_MINOR,
        'patch': VERSION_PATCH
    }

def print_version():
    """Print version information."""
    print(f"InvestiGUI v{__version__} ({BUILD_DATE})")
    print("Digital Forensics Toolkit - Next Generation")