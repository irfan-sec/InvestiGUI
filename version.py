"""
Version information for InvestiGUI
"""

__version__ = "3.0.0"
__version_info__ = (3, 0, 0)

VERSION_MAJOR = 3
VERSION_MINOR = 0
VERSION_PATCH = 0

BUILD_DATE = "2024-12-14"
RELEASE_NOTES = """
InvestiGUI v3.0.0 - World-Class Digital Forensics Platform

🌟 REVOLUTIONARY FEATURES:
- 🤖 Advanced AI-Powered Threat Detection and Attribution
- 🧠 Real-time Memory Forensics with Volatility Integration  
- 🔍 Advanced Malware Detection with YARA Rules
- 🌐 Deep Packet Inspection and Network Threat Analysis
- 🎯 Automated Threat Hunting with Machine Learning
- 🔴 Live System Monitoring and Real-time Alerting
- 🏛️ Blockchain and Cryptocurrency Transaction Analysis
- 📱 Mobile Device Forensics (iOS, Android)
- ☁️  Cloud Forensics (AWS, Azure, GCP)
- 🔐 Advanced Cryptographic Analysis
- 🔍 Steganography Detection and Analysis
- 🌍 OSINT (Open Source Intelligence) Integration
- 🔗 Multi-source Evidence Correlation
- 📊 3D Timeline Visualization and Analysis
- 🚨 Real-time Threat Intelligence Feeds

🧠 AI & MACHINE LEARNING:
- Advanced Persistent Threat (APT) Detection
- Behavioral Anomaly Analysis with Deep Learning
- Automated Malware Family Classification
- Threat Actor Attribution Engine
- Predictive Risk Assessment
- Natural Language Processing for Log Analysis
- Computer Vision for Image/Video Forensics

🔒 SECURITY & COMPLIANCE:
- NIST Cybersecurity Framework Integration
- MITRE ATT&CK Technique Mapping
- ISO 27001/27035 Compliance Features
- Chain of Custody Management
- Digital Evidence Integrity Verification
- Multi-factor Authentication
- Role-based Access Control

⚡ PERFORMANCE & SCALE:
- Distributed Processing for Large Datasets
- GPU Acceleration for ML Workloads
- In-memory Database for Speed
- Real-time Processing Pipeline
- Horizontal Scaling Support
- Advanced Caching Mechanisms

🌐 INTEGRATION & APIS:
- REST API for Enterprise Integration
- SIEM/SOAR Platform Connectors
- Threat Intelligence Platform APIs
- Custom Plugin Development Framework
- Webhook Support for Notifications
- GraphQL Query Interface

📈 ADVANCED ANALYTICS:
- Statistical Analysis and Correlation
- Geospatial Analysis and Mapping
- Social Network Analysis
- Communication Pattern Analysis
- Data Leak Detection
- Compliance Monitoring
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
    print("🌟 World's Most Advanced Digital Forensics & Cybersecurity Platform")
    print("🤖 AI-Powered • 🧠 Memory Forensics • 🌐 Network Analysis • 🔍 Malware Detection")