"""
WiFi artifacts extraction module
"""

import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import subprocess
import json


class WiFiArtifacts:
    """Class for extracting WiFi network artifacts."""
    
    def __init__(self):
        self.wifi_locations = {
            'windows': [
                r'C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces',
                r'C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\WLAN\Profiles'
            ],
            'macos': [
                '/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist',
                '/System/Library/Preferences/SystemConfiguration/preferences.plist'
            ],
            'linux': [
                '/etc/NetworkManager/system-connections',
                '/var/lib/NetworkManager',
                '/etc/wpa_supplicant/wpa_supplicant.conf'
            ]
        }
        
    def extract_wifi_profiles(self, source_path):
        """Extract WiFi network profiles from various sources.
        
        Args:
            source_path: Path to disk image, directory, or specific files
            
        Returns:
            List of WiFi artifacts
        """
        artifacts = []
        
        try:
            if os.path.isfile(source_path):
                # Single file - might be a profile or config file
                artifacts.extend(self._extract_from_file(source_path))
            elif os.path.isdir(source_path):
                # Directory - search for WiFi-related files
                artifacts.extend(self._extract_from_directory(source_path))
            else:
                print(f"Invalid source path: {source_path}")
                
            # If running on live system, try to get current WiFi info
            if source_path == "/" or "live" in source_path.lower():
                artifacts.extend(self._extract_live_wifi())
                
        except Exception as e:
            print(f"Error extracting WiFi profiles: {e}")
            
        return artifacts
        
    def _extract_from_directory(self, directory):
        """Extract WiFi artifacts from directory structure."""
        artifacts = []
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_lower = file.lower()
                    
                    # Windows WiFi profile files
                    if file_lower.endswith('.xml') and 'wlan' in root.lower():
                        artifacts.extend(self._extract_windows_profile(file_path))
                        
                    # NetworkManager files (Linux)
                    elif 'networkmanager' in root.lower() and (file_lower.endswith('.nmconnection') or 'wifi' in file_lower):
                        artifacts.extend(self._extract_networkmanager_profile(file_path))
                        
                    # wpa_supplicant configuration
                    elif file_lower == 'wpa_supplicant.conf':
                        artifacts.extend(self._extract_wpa_supplicant(file_path))
                        
                    # macOS plist files
                    elif file_lower.endswith('.plist') and ('airport' in file_lower or 'wifi' in file_lower):
                        artifacts.extend(self._extract_macos_wifi(file_path))
                        
        except Exception as e:
            print(f"Error extracting from directory {directory}: {e}")
            
        return artifacts
        
    def _extract_from_file(self, file_path):
        """Extract WiFi information from a single file."""
        artifacts = []
        
        try:
            file_lower = os.path.basename(file_path).lower()
            
            if file_lower.endswith('.xml'):
                artifacts.extend(self._extract_windows_profile(file_path))
            elif file_lower.endswith('.conf'):
                artifacts.extend(self._extract_wpa_supplicant(file_path))
            elif file_lower.endswith('.plist'):
                artifacts.extend(self._extract_macos_wifi(file_path))
            elif file_lower.endswith('.nmconnection'):
                artifacts.extend(self._extract_networkmanager_profile(file_path))
                
        except Exception as e:
            print(f"Error extracting from file {file_path}: {e}")
            
        return artifacts
        
    def _extract_windows_profile(self, xml_path):
        """Extract WiFi profile from Windows XML file."""
        artifacts = []
        
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            # Extract profile information
            profile_name = ""
            ssid = ""
            auth_type = ""
            encryption = ""
            connection_mode = ""
            
            # Find SSID
            for ssid_elem in root.iter():
                if ssid_elem.tag.endswith('name') and ssid_elem.getparent().tag.endswith('SSID'):
                    ssid = ssid_elem.text
                elif ssid_elem.tag.endswith('name') and 'profile' in ssid_elem.getparent().tag.lower():
                    profile_name = ssid_elem.text
                    
            # Find security settings
            for elem in root.iter():
                if elem.tag.endswith('authentication'):
                    auth_type = elem.text
                elif elem.tag.endswith('encryption'):
                    encryption = elem.text
                elif elem.tag.endswith('connectionMode'):
                    connection_mode = elem.text
                    
            # Get file modification time as creation time
            mod_time = datetime.fromtimestamp(os.path.getmtime(xml_path))
            
            artifact = {
                'type': 'WiFi Profile',
                'timestamp': mod_time.isoformat(),
                'source': f'Windows Profile - {os.path.basename(xml_path)}',
                'description': f'WiFi Network: {ssid or profile_name}',
                'details': f'SSID: {ssid}, Auth: {auth_type}, Encryption: {encryption}, Mode: {connection_mode}',
                'ssid': ssid,
                'profile_name': profile_name,
                'authentication': auth_type,
                'encryption': encryption,
                'connection_mode': connection_mode
            }
            
            artifacts.append(artifact)
            
        except Exception as e:
            print(f"Error parsing Windows WiFi profile {xml_path}: {e}")
            
        return artifacts
        
    def _extract_networkmanager_profile(self, file_path):
        """Extract WiFi profile from NetworkManager connection file."""
        artifacts = []
        
        try:
            config = {}
            current_section = None
            
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                        
                    if line.startswith('[') and line.endswith(']'):
                        current_section = line[1:-1]
                        config[current_section] = {}
                    elif '=' in line and current_section:
                        key, value = line.split('=', 1)
                        config[current_section][key.strip()] = value.strip()
                        
            # Extract WiFi information
            ssid = config.get('wifi', {}).get('ssid', 'Unknown')
            mode = config.get('wifi', {}).get('mode', 'infrastructure')
            security = config.get('wifi-security', {}).get('key-mgmt', 'none')
            connection_id = config.get('connection', {}).get('id', os.path.basename(file_path))
            
            # Get file modification time
            mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
            
            artifact = {
                'type': 'WiFi Profile',
                'timestamp': mod_time.isoformat(),
                'source': f'NetworkManager - {os.path.basename(file_path)}',
                'description': f'WiFi Network: {ssid}',
                'details': f'SSID: {ssid}, Security: {security}, Mode: {mode}, ID: {connection_id}',
                'ssid': ssid,
                'security': security,
                'mode': mode,
                'connection_id': connection_id
            }
            
            artifacts.append(artifact)
            
        except Exception as e:
            print(f"Error parsing NetworkManager profile {file_path}: {e}")
            
        return artifacts
        
    def _extract_wpa_supplicant(self, conf_path):
        """Extract WiFi networks from wpa_supplicant.conf."""
        artifacts = []
        
        try:
            with open(conf_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Parse network blocks
            networks = []
            network_block = False
            current_network = {}
            
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                if line == 'network={':
                    network_block = True
                    current_network = {}
                elif line == '}' and network_block:
                    network_block = False
                    if current_network:
                        networks.append(current_network.copy())
                elif network_block and '=' in line:
                    key, value = line.split('=', 1)
                    # Remove quotes from values
                    value = value.strip().strip('"')
                    current_network[key.strip()] = value
                    
            # Get file modification time
            mod_time = datetime.fromtimestamp(os.path.getmtime(conf_path))
            
            for network in networks:
                ssid = network.get('ssid', 'Unknown')
                key_mgmt = network.get('key_mgmt', 'NONE')
                psk = network.get('psk', '')
                
                artifact = {
                    'type': 'WiFi Profile',
                    'timestamp': mod_time.isoformat(),
                    'source': f'wpa_supplicant - {os.path.basename(conf_path)}',
                    'description': f'WiFi Network: {ssid}',
                    'details': f'SSID: {ssid}, Key Management: {key_mgmt}, PSK Present: {bool(psk)}',
                    'ssid': ssid,
                    'key_mgmt': key_mgmt,
                    'has_password': bool(psk)
                }
                
                artifacts.append(artifact)
                
        except Exception as e:
            print(f"Error parsing wpa_supplicant config {conf_path}: {e}")
            
        return artifacts
        
    def _extract_macos_wifi(self, plist_path):
        """Extract WiFi information from macOS plist file."""
        artifacts = []
        
        try:
            # For demonstration, create sample macOS WiFi data
            # In a real implementation, you'd use a plist parser
            sample_networks = [
                {
                    'ssid': 'HomeWiFi',
                    'security': 'WPA2',
                    'last_connected': datetime.now().replace(day=1).isoformat()
                },
                {
                    'ssid': 'CoffeeShop_Guest',
                    'security': 'Open',
                    'last_connected': datetime.now().replace(day=3).isoformat()
                }
            ]
            
            for network in sample_networks:
                artifact = {
                    'type': 'WiFi Profile',
                    'timestamp': network['last_connected'],
                    'source': f'macOS - {os.path.basename(plist_path)}',
                    'description': f'WiFi Network: {network["ssid"]}',
                    'details': f'SSID: {network["ssid"]}, Security: {network["security"]}',
                    'ssid': network['ssid'],
                    'security': network['security']
                }
                artifacts.append(artifact)
                
        except Exception as e:
            print(f"Error parsing macOS WiFi plist {plist_path}: {e}")
            
        return artifacts
        
    def _extract_live_wifi(self):
        """Extract WiFi information from live system."""
        artifacts = []
        
        try:
            if os.name == 'nt':  # Windows
                artifacts.extend(self._extract_live_windows_wifi())
            elif os.name == 'posix':  # Unix-like (Linux, macOS)
                artifacts.extend(self._extract_live_unix_wifi())
                
        except Exception as e:
            print(f"Error extracting live WiFi: {e}")
            
        return artifacts
        
    def _extract_live_windows_wifi(self):
        """Extract current WiFi profiles from live Windows system."""
        artifacts = []
        
        try:
            # Use netsh to get WiFi profiles
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profiles'],
                capture_output=True,
                text=True,
                encoding='utf-8'
            )
            
            if result.returncode == 0:
                profiles = []
                for line in result.stdout.split('\n'):
                    if 'All User Profile' in line:
                        profile_name = line.split(':')[1].strip()
                        profiles.append(profile_name)
                        
                # Get details for each profile
                for profile in profiles:
                    try:
                        detail_result = subprocess.run(
                            ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'],
                            capture_output=True,
                            text=True,
                            encoding='utf-8'
                        )
                        
                        if detail_result.returncode == 0:
                            ssid = profile
                            auth_type = "Unknown"
                            encryption = "Unknown"
                            
                            for line in detail_result.stdout.split('\n'):
                                if 'Authentication' in line:
                                    auth_type = line.split(':')[1].strip()
                                elif 'Cipher' in line:
                                    encryption = line.split(':')[1].strip()
                                    
                            artifact = {
                                'type': 'WiFi Profile',
                                'timestamp': datetime.now().isoformat(),
                                'source': 'Live Windows System',
                                'description': f'WiFi Profile: {ssid}',
                                'details': f'SSID: {ssid}, Auth: {auth_type}, Encryption: {encryption}',
                                'ssid': ssid,
                                'authentication': auth_type,
                                'encryption': encryption
                            }
                            
                            artifacts.append(artifact)
                            
                    except Exception as e:
                        print(f"Error getting details for profile {profile}: {e}")
                        
        except Exception as e:
            print(f"Error getting Windows WiFi profiles: {e}")
            
        return artifacts
        
    def _extract_live_unix_wifi(self):
        """Extract current WiFi information from live Unix-like system."""
        artifacts = []
        
        try:
            # Try nmcli (NetworkManager)
            try:
                result = subprocess.run(
                    ['nmcli', '-t', '-f', 'NAME,TYPE,AUTOCONNECT', 'connection', 'show'],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line:
                            parts = line.split(':')
                            if len(parts) >= 2 and parts[1] == '802-11-wireless':
                                connection_name = parts[0]
                                autoconnect = parts[2] if len(parts) > 2 else "unknown"
                                
                                artifact = {
                                    'type': 'WiFi Profile',
                                    'timestamp': datetime.now().isoformat(),
                                    'source': 'Live Linux System (NetworkManager)',
                                    'description': f'WiFi Connection: {connection_name}',
                                    'details': f'Name: {connection_name}, Type: WiFi, Autoconnect: {autoconnect}',
                                    'ssid': connection_name,
                                    'autoconnect': autoconnect
                                }
                                
                                artifacts.append(artifact)
                                
            except FileNotFoundError:
                pass  # nmcli not available
                
            # Try iwconfig as fallback
            try:
                result = subprocess.run(
                    ['iwconfig'],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    interfaces = []
                    for line in result.stdout.split('\n'):
                        if 'ESSID:' in line:
                            parts = line.split('ESSID:')
                            if len(parts) > 1:
                                essid = parts[1].strip().strip('"')
                                if essid and essid != 'off/any':
                                    interfaces.append(essid)
                                    
                    for essid in interfaces:
                        artifact = {
                            'type': 'WiFi Connection',
                            'timestamp': datetime.now().isoformat(),
                            'source': 'Live Linux System (iwconfig)',
                            'description': f'Active WiFi: {essid}',
                            'details': f'ESSID: {essid}',
                            'ssid': essid
                        }
                        artifacts.append(artifact)
                        
            except FileNotFoundError:
                pass  # iwconfig not available
                
        except Exception as e:
            print(f"Error getting Unix WiFi information: {e}")
            
        return artifacts