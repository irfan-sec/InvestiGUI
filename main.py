#!/usr/bin/env python3
"""
InvestiGUI - Digital Forensics Toolkit v2.0.0
Main entry point for the application.
"""

import sys
import os
import argparse
from datetime import datetime

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import version information
from version import get_version, print_version, get_full_version

# Try to import GUI components
try:
    from PyQt5.QtWidgets import QApplication
    from PyQt5.QtCore import Qt
    from gui.main_window import MainWindow
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("GUI components not available. Install PyQt5 for full GUI functionality.")

# Import CLI components
from demo import main as demo_main
from plugin_manager import initialize_plugin_system, get_plugin_manager


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='InvestiGUI - Digital Forensics Toolkit v2.0.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Start GUI interface
  python main.py --version          # Show version information  
  python main.py --demo             # Run CLI demonstration
  python main.py --cli              # Start CLI mode
  python main.py --plugins          # List available plugins
  python main.py --init-plugins     # Initialize plugin system
        """
    )
    
    parser.add_argument('--version', action='store_true',
                       help='Show version information')
    parser.add_argument('--demo', action='store_true',
                       help='Run CLI demonstration mode')
    parser.add_argument('--cli', action='store_true',
                       help='Start command-line interface')
    parser.add_argument('--plugins', action='store_true',
                       help='List available plugins')
    parser.add_argument('--init-plugins', action='store_true',
                       help='Initialize plugin system')
    parser.add_argument('--no-gui', action='store_true',
                       help='Force CLI mode even if GUI is available')
    
    return parser.parse_args()


def show_version_info():
    """Display comprehensive version information."""
    print_version()
    version_info = get_full_version()
    
    print(f"\nVersion Details:")
    print(f"  Version: {version_info['version']}")
    print(f"  Build Date: {version_info['build_date']}")
    print(f"  Major: {version_info['major']}")
    print(f"  Minor: {version_info['minor']}")
    print(f"  Patch: {version_info['patch']}")
    
    print(f"\nCapabilities:")
    print(f"  GUI Available: {'Yes' if GUI_AVAILABLE else 'No'}")
    print(f"  CLI Available: Yes")
    print(f"  Plugin System: Yes")
    print(f"  Memory Analysis: Yes")
    print(f"  Network Analysis: Yes")
    print(f"  ML Anomaly Detection: Yes")
    print(f"  Report Generation: Yes")


def list_plugins():
    """List all available plugins."""
    print("InvestiGUI Plugin System")
    print("=" * 50)
    
    try:
        # Initialize plugin system
        load_results = initialize_plugin_system()
        manager = get_plugin_manager()
        
        print(f"\nPlugin Loading Results:")
        print(f"  Total Found: {load_results['total_found']}")
        print(f"  Successfully Loaded: {len(load_results['loaded'])}")
        print(f"  Failed to Load: {len(load_results['failed'])}")
        
        if load_results['loaded']:
            print(f"\nSuccessfully Loaded Plugins:")
            for plugin_name in load_results['loaded']:
                print(f"  ✅ {plugin_name}")
        
        if load_results['failed']:
            print(f"\nFailed to Load:")
            for failure in load_results['failed']:
                print(f"  ❌ {failure['plugin']}: {failure['error']}")
        
        # Get detailed plugin information
        plugin_info = manager.get_available_plugins()
        
        for category, plugins in plugin_info.items():
            if plugins:
                print(f"\n{category.replace('_', ' ').title()}:")
                for plugin_name, info in plugins.items():
                    if 'error' not in info:
                        print(f"  📁 {plugin_name}")
                        print(f"     Name: {info.get('name', 'Unknown')}")
                        print(f"     Version: {info.get('version', 'Unknown')}")
                        print(f"     Description: {info.get('description', 'No description')}")
                    else:
                        print(f"  ❌ {plugin_name}: {info['error']}")
        
        # Plugin statistics
        stats = manager.get_plugin_statistics()
        print(f"\nPlugin Statistics:")
        print(f"  Total Plugins: {stats['total_plugins']}")
        for category, count in stats['by_category'].items():
            if count > 0:
                print(f"  {category.replace('_', ' ').title()}: {count}")
                
    except Exception as e:
        print(f"Error listing plugins: {e}")


def initialize_plugins():
    """Initialize the plugin system."""
    print("Initializing InvestiGUI Plugin System...")
    print("=" * 50)
    
    try:
        load_results = initialize_plugin_system()
        
        print(f"✅ Plugin system initialized successfully!")
        print(f"📊 Results:")
        print(f"   Total plugins found: {load_results['total_found']}")
        print(f"   Successfully loaded: {len(load_results['loaded'])}")
        print(f"   Failed to load: {len(load_results['failed'])}")
        
        if load_results['loaded']:
            print(f"\n✅ Loaded plugins:")
            for plugin in load_results['loaded']:
                print(f"   - {plugin}")
        
        if load_results['failed']:
            print(f"\n❌ Failed plugins:")
            for failure in load_results['failed']:
                print(f"   - {failure['plugin']}: {failure['error']}")
        
        print(f"\n💡 Use 'python main.py --plugins' to see detailed plugin information")
        
    except Exception as e:
        print(f"❌ Error initializing plugins: {e}")


def start_cli_mode():
    """Start command-line interface mode."""
    print("InvestiGUI - Command Line Interface")
    print("=" * 50)
    print("Available commands:")
    print("  demo     - Run demonstration mode")
    print("  plugins  - List plugins")
    print("  version  - Show version")
    print("  help     - Show this help")
    print("  exit     - Exit CLI")
    print()
    
    while True:
        try:
            command = input("investigui> ").strip().lower()
            
            if command == 'exit':
                print("Goodbye!")
                break
            elif command == 'demo':
                demo_main()
            elif command == 'plugins':
                list_plugins()
            elif command == 'version':
                show_version_info()
            elif command == 'help':
                print("Available commands: demo, plugins, version, help, exit")
            elif command == '':
                continue
            else:
                print(f"Unknown command: {command}")
                print("Type 'help' for available commands")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except EOFError:
            print("\nExiting...")
            break


def start_gui():
    """Start the GUI interface."""
    if not GUI_AVAILABLE:
        print("❌ GUI not available. Install PyQt5:")
        print("   pip install PyQt5")
        print("   or use --cli for command-line interface")
        return 1
    
    try:
        app = QApplication(sys.argv)
        app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
        
        # Initialize plugin system
        print("🔧 Initializing plugin system...")
        initialize_plugin_system()
        
        window = MainWindow()
        window.show()
        
        print(f"🚀 InvestiGUI v{get_version()} started successfully!")
        
        return app.exec_()
        
    except Exception as e:
        print(f"❌ Error starting GUI: {e}")
        return 1


def main():
    """Main function to start the application."""
    args = parse_arguments()
    
    # Handle command line arguments
    if args.version:
        show_version_info()
        return 0
    
    if args.demo:
        print(f"🚀 Starting InvestiGUI v{get_version()} Demo Mode")
        demo_main()
        return 0
    
    if args.plugins:
        list_plugins()
        return 0
    
    if args.init_plugins:
        initialize_plugins()
        return 0
    
    if args.cli or args.no_gui or not GUI_AVAILABLE:
        start_cli_mode()
        return 0
    
    # Default: start GUI
    return start_gui()


if __name__ == "__main__":
    sys.exit(main())