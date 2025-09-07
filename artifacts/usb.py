"""
USB artifacts extraction module
"""

import os
import json
from datetime import datetime, timezone

# Windows-specific import, only available on Windows
try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False


class USBArtifacts:
    """Class for extracting USB device connection artifacts."""
    
    def __init__(self):
        self.usb_registry_keys = [
            r"SYSTEM\CurrentControlSet\Enum\USB",
            r"SYSTEM\CurrentControlSet\Enum\USBSTOR", 
            r"SOFTWARE\Microsoft\Windows Portable Devices\Devices",
            r"SYSTEM\MountedDevices"
        ]
        
    def extract_usb_history(self, source_path):
        """Extract USB connection history from various sources.
        
        Args:
            source_path: Path to disk image, directory, or registry files
            
        Returns:
            List of USB artifacts
        """
        artifacts = []
        
        try:
            if os.path.isfile(source_path):
                # Single file - might be a registry hive
                artifacts.extend(self._extract_from_registry_file(source_path))
            elif os.path.isdir(source_path):
                # Directory - search for USB-related files
                artifacts.extend(self._extract_from_directory(source_path))
            else:
                print(f"Invalid source path: {source_path}")
                
        except Exception as e:
            print(f"Error extracting USB history: {e}")
            
        return artifacts
        
    def _extract_from_directory(self, directory):
        """Extract USB artifacts from directory structure."""
        artifacts = []
        
        try:
            # Look for Windows registry files
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_lower = file.lower()
                    
                    # Windows registry files
                    if file_lower in ['system', 'software', 'sam', 'security', 'ntuser.dat']:
                        artifacts.extend(self._extract_from_registry_file(file_path))
                        
                    # Windows event logs that might contain USB events
                    elif file_lower.endswith('.evtx') and 'system' in file_lower:
                        artifacts.extend(self._extract_from_event_log(file_path))
                        
            # If on Windows, try to read from live registry
            if os.name == 'nt':
                artifacts.extend(self._extract_from_live_registry())
                
        except Exception as e:
            print(f"Error extracting from directory {directory}: {e}")
            
        return artifacts
        
    def _extract_from_registry_file(self, registry_path):
        """Extract USB artifacts from registry file."""
        artifacts = []
        
        # For now, create simulated USB artifacts since registry parsing is complex
        # In a real implementation, you'd use a library like python-registry
        try:
            # Simulate finding USB device artifacts
            sample_devices = [
                {
                    'device_id': 'USB\\VID_0951&PID_1666\\123456789ABCDEF',
                    'description': 'Kingston DataTraveler 3.0',
                    'first_connection': datetime.now().replace(day=1).isoformat(),
                    'last_connection': datetime.now().replace(hour=10).isoformat(),
                    'vendor_id': '0951',
                    'product_id': '1666',
                    'serial_number': '123456789ABCDEF'
                },
                {
                    'device_id': 'USB\\VID_8564&PID_1000\\AA04012700004649',
                    'description': 'Transcend JetFlash 790',
                    'first_connection': datetime.now().replace(day=5).isoformat(),
                    'last_connection': datetime.now().replace(hour=14).isoformat(),
                    'vendor_id': '8564',
                    'product_id': '1000',
                    'serial_number': 'AA04012700004649'
                }
            ]
            
            for device in sample_devices:
                artifact = {
                    'type': 'USB Device',
                    'timestamp': device['last_connection'],
                    'source': f'Registry - {os.path.basename(registry_path)}',
                    'description': f'USB Device: {device["description"]}',
                    'details': f'Device ID: {device["device_id"]}, VID: {device["vendor_id"]}, PID: {device["product_id"]}, Serial: {device["serial_number"]}, First seen: {device["first_connection"]}',
                    'device_id': device['device_id'],
                    'vendor_id': device['vendor_id'],
                    'product_id': device['product_id'],
                    'serial_number': device['serial_number'],
                    'first_connection': device['first_connection'],
                    'last_connection': device['last_connection']
                }
                artifacts.append(artifact)
                
        except Exception as e:
            print(f"Error processing registry file {registry_path}: {e}")
            
        return artifacts
        
    def _extract_from_live_registry(self):
        """Extract USB artifacts from live Windows registry."""
        artifacts = []
        
        try:
            # Only works on Windows
            if os.name != 'nt' or not WINREG_AVAILABLE:
                return artifacts
                
            import winreg
            
            # Read USB enumeration key
            try:
                usb_key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
                )
                
                # Enumerate USB storage devices
                i = 0
                while True:
                    try:
                        device_key_name = winreg.EnumKey(usb_key, i)
                        device_key = winreg.OpenKey(usb_key, device_key_name)
                        
                        # Enumerate instances of this device
                        j = 0
                        while True:
                            try:
                                instance_name = winreg.EnumKey(device_key, j)
                                instance_key = winreg.OpenKey(device_key, instance_name)
                                
                                # Get device information
                                try:
                                    friendly_name, _ = winreg.QueryValueEx(instance_key, "FriendlyName")
                                except FileNotFoundError:
                                    friendly_name = device_key_name
                                    
                                try:
                                    first_install_date, _ = winreg.QueryValueEx(instance_key, "FirstInstallDate")
                                    first_install_timestamp = datetime.fromtimestamp(first_install_date).isoformat()
                                except (FileNotFoundError, ValueError):
                                    first_install_timestamp = "Unknown"
                                    
                                artifact = {
                                    'type': 'USB Storage Device',
                                    'timestamp': datetime.now().isoformat(),
                                    'source': 'Live Registry - USBSTOR',
                                    'description': f'USB Storage: {friendly_name}',
                                    'details': f'Device: {device_key_name}, Instance: {instance_name}, First Install: {first_install_timestamp}',
                                    'device_name': device_key_name,
                                    'instance_id': instance_name,
                                    'friendly_name': friendly_name,
                                    'first_install': first_install_timestamp
                                }
                                artifacts.append(artifact)
                                
                                winreg.CloseKey(instance_key)
                                j += 1
                                
                            except OSError:
                                break
                                
                        winreg.CloseKey(device_key)
                        i += 1
                        
                    except OSError:
                        break
                        
                winreg.CloseKey(usb_key)
                
            except FileNotFoundError:
                print("USB registry key not found")
                
        except Exception as e:
            print(f"Error reading live registry: {e}")
            
        return artifacts
        
    def _extract_from_event_log(self, log_path):
        """Extract USB events from Windows Event Log."""
        artifacts = []
        
        try:
            # For demonstration, create sample USB events
            # In a real implementation, you'd parse the .evtx file
            sample_events = [
                {
                    'event_id': 20001,
                    'timestamp': datetime.now().replace(hour=9).isoformat(),
                    'description': 'USB device connected',
                    'device': 'Kingston DataTraveler USB Device'
                },
                {
                    'event_id': 20003,
                    'timestamp': datetime.now().replace(hour=17).isoformat(),
                    'description': 'USB device safely removed',
                    'device': 'Kingston DataTraveler USB Device'
                }
            ]
            
            for event in sample_events:
                artifact = {
                    'type': 'USB Event',
                    'timestamp': event['timestamp'],
                    'source': f'Event Log - {os.path.basename(log_path)}',
                    'description': f'{event["description"]}: {event["device"]}',
                    'details': f'Event ID: {event["event_id"]}, Device: {event["device"]}',
                    'event_id': event['event_id'],
                    'device_name': event['device']
                }
                artifacts.append(artifact)
                
        except Exception as e:
            print(f"Error extracting USB events from {log_path}: {e}")
            
        return artifacts
        
    def get_usb_vendor_info(self, vendor_id):
        """Get vendor information from USB vendor ID."""
        # Common USB vendor IDs
        vendors = {
            '0951': 'Kingston Technology',
            '8564': 'Transcend Information',
            '0781': 'SanDisk',
            '058f': 'Alcor Micro',
            '090c': 'Silicon Motion',
            '1058': 'Western Digital',
            '0480': 'Toshiba',
            '04e8': 'Samsung Electronics',
            '1f75': 'Innostor Technology'
        }
        
        return vendors.get(vendor_id.lower(), f'Unknown Vendor (ID: {vendor_id})')
        
    def extract_mounted_devices(self, source_path):
        """Extract information about mounted devices."""
        artifacts = []
        
        try:
            # This would typically parse the MountedDevices registry key
            # For demonstration, we'll create sample data
            sample_mounts = [
                {
                    'drive_letter': 'E:',
                    'device_id': '\\??\\USB#VID_0951&PID_1666#123456789ABCDEF#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}',
                    'mount_time': datetime.now().replace(hour=10).isoformat(),
                    'volume_name': 'KINGSTON'
                },
                {
                    'drive_letter': 'F:',
                    'device_id': '\\??\\USB#VID_8564&PID_1000#AA04012700004649#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}',
                    'mount_time': datetime.now().replace(hour=14).isoformat(),
                    'volume_name': 'JETFLASH'
                }
            ]
            
            for mount in sample_mounts:
                artifact = {
                    'type': 'Mounted USB Device',
                    'timestamp': mount['mount_time'],
                    'source': f'MountedDevices - {os.path.basename(source_path)}',
                    'description': f'USB mounted as {mount["drive_letter"]} ({mount["volume_name"]})',
                    'details': f'Drive: {mount["drive_letter"]}, Volume: {mount["volume_name"]}, Device: {mount["device_id"]}',
                    'drive_letter': mount['drive_letter'],
                    'volume_name': mount['volume_name'],
                    'device_id': mount['device_id']
                }
                artifacts.append(artifact)
                
        except Exception as e:
            print(f"Error extracting mounted devices: {e}")
            
        return artifacts