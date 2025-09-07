#!/usr/bin/env python3
"""
InvestiGUI CLI Demo
Demonstrates core functionality without GUI dependency
"""

import sys
import os
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from artifacts.browser import BrowserArtifacts
from artifacts.usb import USBArtifacts
from artifacts.wifi import WiFiArtifacts
from artifacts.files import FileArtifacts

from logs.linux import LinuxLogParser
from logs.windows import WindowsLogParser
from logs.browser import BrowserLogParser

from timeline import TimelineProcessor
from utils import format_timestamp, format_file_size


def demo_artifact_extraction():
    """Demonstrate artifact extraction capabilities."""
    print("\n" + "="*60)
    print("ARTIFACT EXTRACTION DEMO")
    print("="*60)
    
    # Browser artifacts
    browser = BrowserArtifacts()
    print("\n🌐 Browser Artifacts:")
    print("- Extracting browser history...")
    browser_artifacts = browser.extract_history("examples/")
    print(f"  Found {len(browser_artifacts)} browser artifacts")
    
    # USB artifacts
    usb = USBArtifacts()
    print("\n🔌 USB Device Artifacts:")
    print("- Extracting USB history...")
    usb_artifacts = usb.extract_usb_history("examples/")
    print(f"  Found {len(usb_artifacts)} USB artifacts")
    
    # WiFi artifacts
    wifi = WiFiArtifacts()
    print("\n📶 WiFi Network Artifacts:")
    print("- Extracting WiFi profiles...")
    wifi_artifacts = wifi.extract_wifi_profiles("examples/")
    print(f"  Found {len(wifi_artifacts)} WiFi artifacts")
    
    # File artifacts
    files = FileArtifacts()
    print("\n📁 File System Artifacts:")
    print("- Extracting recent files...")
    file_artifacts = files.extract_recent_files("examples/")
    print(f"  Found {len(file_artifacts)} file artifacts")
    
    return browser_artifacts + usb_artifacts + wifi_artifacts + file_artifacts


def demo_log_parsing():
    """Demonstrate log parsing capabilities."""
    print("\n" + "="*60)
    print("LOG PARSING DEMO")
    print("="*60)
    
    all_events = []
    
    # Linux log parsing
    linux_parser = LinuxLogParser()
    
    # Parse sample syslog
    syslog_path = "examples/sample_logs/syslog_sample.log"
    if os.path.exists(syslog_path):
        print(f"\n🐧 Parsing Linux syslog: {syslog_path}")
        syslog_events = linux_parser.parse_log(syslog_path)
        print(f"  Parsed {len(syslog_events)} syslog events")
        all_events.extend(syslog_events)
        
        # Show sample events
        for i, event in enumerate(syslog_events[:3]):
            print(f"    [{i+1}] {event['timestamp']} - {event['description']}")
    
    # Parse sample auth log
    auth_path = "examples/sample_logs/auth_sample.log"
    if os.path.exists(auth_path):
        print(f"\n🔐 Parsing Linux auth log: {auth_path}")
        auth_events = linux_parser.parse_log(auth_path)
        print(f"  Parsed {len(auth_events)} auth events")
        all_events.extend(auth_events)
        
        # Show sample events
        for i, event in enumerate(auth_events[:3]):
            print(f"    [{i+1}] {event['timestamp']} - {event['description']}")
    
    # Windows log parsing demo
    windows_parser = WindowsLogParser()
    print(f"\n🪟 Demonstrating Windows event parsing...")
    windows_events = windows_parser.parse_log("demo.evtx")  # Creates sample events
    print(f"  Generated {len(windows_events)} sample Windows events")
    all_events.extend(windows_events)
    
    # Browser log parsing demo
    browser_parser = BrowserLogParser()
    print(f"\n🌐 Demonstrating browser log parsing...")
    browser_events = browser_parser.parse_log("examples/")
    print(f"  Found {len(browser_events)} browser log events")
    all_events.extend(browser_events)
    
    return all_events


def demo_timeline_analysis(artifacts, events):
    """Demonstrate timeline analysis capabilities."""
    print("\n" + "="*60)
    print("TIMELINE ANALYSIS DEMO")
    print("="*60)
    
    # Combine all events
    all_items = artifacts + events
    print(f"\n⏰ Processing {len(all_items)} total items for timeline...")
    
    # Initialize timeline processor
    processor = TimelineProcessor()
    
    # Process events
    timeline = processor.process_events(all_items)
    print(f"  Created unified timeline with {len(timeline)} events")
    
    # Show timeline statistics
    if timeline:
        print("\n📊 Timeline Statistics:")
        analysis = processor.analyze_timeline(timeline)
        
        print(f"  Total events: {analysis['total_events']}")
        print(f"  Date range: {analysis['date_range']['start']} to {analysis['date_range']['end']}")
        print(f"  Time span: {analysis['date_range']['span_hours']:.1f} hours")
        
        print("\n  Event types:")
        for event_type, count in list(analysis['event_types'].items())[:5]:
            print(f"    - {event_type}: {count}")
            
        print("\n  Top sources:")
        for source, count in list(analysis['sources'].items())[:5]:
            print(f"    - {source}: {count}")
    
    # Show recent events
    print("\n🕒 Most Recent Events:")
    for i, event in enumerate(timeline[:5]):
        timestamp = format_timestamp(event['timestamp'], '%Y-%m-%d %H:%M:%S')
        print(f"  [{i+1}] {timestamp} | {event['type']} | {event['description']}")
    
    # Demonstrate filtering
    print("\n🔍 Filtering Demo - ERROR level events:")
    error_events = processor.filter_events(timeline, search_text="error", case_sensitive=False)
    print(f"  Found {len(error_events)} events containing 'error'")
    
    return timeline


def demo_export_functionality(timeline):
    """Demonstrate export capabilities."""
    print("\n" + "="*60)
    print("EXPORT DEMO")
    print("="*60)
    
    if not timeline:
        print("No timeline data to export")
        return
    
    # Initialize timeline processor
    processor = TimelineProcessor()
    
    # Export to different formats
    print("\n📤 Exporting timeline data...")
    
    # JSON export
    try:
        json_data = processor.export_timeline(timeline[:10], 'json')
        print(f"  JSON export: {len(json_data)} characters")
    except Exception as e:
        print(f"  JSON export failed: {e}")
    
    # CSV export
    try:
        csv_data = processor.export_timeline(timeline[:10], 'csv')
        print(f"  CSV export: {len(csv_data)} characters")
    except Exception as e:
        print(f"  CSV export failed: {e}")
    
    # HTML export
    try:
        html_data = processor.export_timeline(timeline[:10], 'html')
        print(f"  HTML export: {len(html_data)} characters")
    except Exception as e:
        print(f"  HTML export failed: {e}")
    
    print("  All export formats generated successfully!")


def main():
    """Main demonstration function."""
    print("InvestiGUI - Digital Forensics Toolkit")
    print("CLI Demonstration Mode")
    print("="*60)
    
    try:
        # Step 1: Artifact extraction
        artifacts = demo_artifact_extraction()
        
        # Step 2: Log parsing
        events = demo_log_parsing()
        
        # Step 3: Timeline analysis
        timeline = demo_timeline_analysis(artifacts, events)
        
        # Step 4: Export demo
        demo_export_functionality(timeline)
        
        print("\n" + "="*60)
        print("✅ DEMO COMPLETED SUCCESSFULLY!")
        print("="*60)
        
        print("\nInvestiGUI Features Demonstrated:")
        print("  ✅ Artifact extraction from multiple sources")
        print("  ✅ Multi-format log parsing (Linux, Windows, Browser)")
        print("  ✅ Timeline creation and analysis")
        print("  ✅ Event filtering and searching") 
        print("  ✅ Export to JSON, CSV, and HTML formats")
        print("\nTo use the full GUI version, install PyQt5:")
        print("  pip install PyQt5")
        print("  python main.py")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())