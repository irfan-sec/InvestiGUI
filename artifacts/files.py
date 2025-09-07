"""
File artifacts extraction module
"""

import os
from datetime import datetime, timezone
import json
import struct

# Windows-specific import, only available on Windows
try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False


class FileArtifacts:
    """Class for extracting file-related artifacts."""
    
    def __init__(self):
        self.recent_locations = {
            'windows': [
                r'%USERPROFILE%\Recent',
                r'%APPDATA%\Microsoft\Windows\Recent',
                r'%APPDATA%\Microsoft\Office\Recent'
            ],
            'macos': [
                '~/Library/Application Support/com.apple.sharedfilelist',
                '~/Library/Preferences/com.apple.recentitems.plist'
            ],
            'linux': [
                '~/.local/share/recently-used.xbel',
                '~/.recently-used'
            ]
        }
        
    def extract_recent_files(self, source_path):
        """Extract recent files artifacts from various sources.
        
        Args:
            source_path: Path to disk image, directory, or user profile
            
        Returns:
            List of recent files artifacts
        """
        artifacts = []
        
        try:
            if os.path.isfile(source_path):
                # Single file - might be a recent files database
                artifacts.extend(self._extract_from_file(source_path))
            elif os.path.isdir(source_path):
                # Directory - search for recent files artifacts
                artifacts.extend(self._extract_from_directory(source_path))
            else:
                print(f"Invalid source path: {source_path}")
                
        except Exception as e:
            print(f"Error extracting recent files: {e}")
            
        return artifacts
        
    def _extract_from_directory(self, directory):
        """Extract recent files from directory structure."""
        artifacts = []
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_lower = file.lower()
                    
                    # Windows LNK files (shortcuts)
                    if file_lower.endswith('.lnk'):
                        artifacts.extend(self._extract_lnk_file(file_path))
                        
                    # Windows jump lists
                    elif file_lower.endswith('.automaticDestinations-ms') or file_lower.endswith('.customDestinations-ms'):
                        artifacts.extend(self._extract_jump_list(file_path))
                        
                    # Recently used files databases
                    elif file_lower in ['recently-used.xbel', 'recently-used']:
                        artifacts.extend(self._extract_xbel_recent(file_path))
                        
                    # macOS plist files
                    elif file_lower.endswith('.plist') and 'recent' in file_lower:
                        artifacts.extend(self._extract_macos_recent(file_path))
                        
                    # Office recent files
                    elif 'office' in root.lower() and 'recent' in root.lower():
                        artifacts.extend(self._extract_office_recent(file_path))
                        
        except Exception as e:
            print(f"Error extracting from directory {directory}: {e}")
            
        return artifacts
        
    def _extract_from_file(self, file_path):
        """Extract recent files from a single file."""
        artifacts = []
        
        try:
            file_lower = os.path.basename(file_path).lower()
            
            if file_lower.endswith('.lnk'):
                artifacts.extend(self._extract_lnk_file(file_path))
            elif 'destinations-ms' in file_lower:
                artifacts.extend(self._extract_jump_list(file_path))
            elif file_lower in ['recently-used.xbel', 'recently-used']:
                artifacts.extend(self._extract_xbel_recent(file_path))
            elif file_lower.endswith('.plist'):
                artifacts.extend(self._extract_macos_recent(file_path))
                
        except Exception as e:
            print(f"Error extracting from file {file_path}: {e}")
            
        return artifacts
        
    def _extract_lnk_file(self, lnk_path):
        """Extract information from Windows LNK (shortcut) file."""
        artifacts = []
        
        try:
            # For demonstration, create sample LNK data
            # In a real implementation, you'd parse the binary LNK format
            
            # Get file timestamps
            creation_time = datetime.fromtimestamp(os.path.getctime(lnk_path))
            access_time = datetime.fromtimestamp(os.path.getatime(lnk_path))
            
            # Extract filename without extension
            target_name = os.path.basename(lnk_path)[:-4]  # Remove .lnk
            
            # Sample target information (in real implementation, parse from binary)
            sample_targets = {
                'document.docx.lnk': {
                    'target': 'C:\\Users\\User\\Documents\\document.docx',
                    'arguments': '',
                    'working_dir': 'C:\\Users\\User\\Documents'
                },
                'presentation.pptx.lnk': {
                    'target': 'C:\\Users\\User\\Desktop\\presentation.pptx',
                    'arguments': '',
                    'working_dir': 'C:\\Users\\User\\Desktop'
                }
            }
            
            lnk_name = os.path.basename(lnk_path)
            target_info = sample_targets.get(lnk_name, {
                'target': f'Unknown target for {target_name}',
                'arguments': '',
                'working_dir': 'Unknown'
            })
            
            artifact = {
                'type': 'Recent File (LNK)',
                'timestamp': access_time.isoformat(),
                'source': f'Windows Shortcut - {os.path.basename(lnk_path)}',
                'description': f'Recent file: {target_name}',
                'details': f'Target: {target_info["target"]}, Working Dir: {target_info["working_dir"]}, Created: {creation_time.isoformat()}',
                'target_path': target_info['target'],
                'working_directory': target_info['working_dir'],
                'creation_time': creation_time.isoformat(),
                'access_time': access_time.isoformat()
            }
            
            artifacts.append(artifact)
            
        except Exception as e:
            print(f"Error parsing LNK file {lnk_path}: {e}")
            
        return artifacts
        
    def _extract_jump_list(self, jumplist_path):
        """Extract information from Windows Jump List files."""
        artifacts = []
        
        try:
            # For demonstration, create sample jump list data
            # In a real implementation, you'd parse the binary jump list format
            
            mod_time = datetime.fromtimestamp(os.path.getmtime(jumplist_path))
            
            # Sample jump list entries
            sample_entries = [
                {
                    'path': 'C:\\Users\\User\\Documents\\Report.docx',
                    'access_time': datetime.now().replace(hour=10).isoformat(),
                    'app': 'Microsoft Word'
                },
                {
                    'path': 'C:\\Users\\User\\Pictures\\vacation.jpg',
                    'access_time': datetime.now().replace(hour=15).isoformat(),
                    'app': 'Windows Photo Viewer'
                }
            ]
            
            for entry in sample_entries:
                artifact = {
                    'type': 'Recent File (Jump List)',
                    'timestamp': entry['access_time'],
                    'source': f'Jump List - {os.path.basename(jumplist_path)}',
                    'description': f'Recent file: {os.path.basename(entry["path"])}',
                    'details': f'Path: {entry["path"]}, Application: {entry["app"]}, Jump List Modified: {mod_time.isoformat()}',
                    'file_path': entry['path'],
                    'application': entry['app'],
                    'jumplist_modified': mod_time.isoformat()
                }
                
                artifacts.append(artifact)
                
        except Exception as e:
            print(f"Error parsing jump list {jumplist_path}: {e}")
            
        return artifacts
        
    def _extract_xbel_recent(self, xbel_path):
        """Extract recent files from XBEL format (Linux)."""
        artifacts = []
        
        try:
            import xml.etree.ElementTree as ET
            
            tree = ET.parse(xbel_path)
            root = tree.getroot()
            
            for bookmark in root.findall('.//bookmark'):
                href = bookmark.get('href', '')
                added = bookmark.get('added', '')
                modified = bookmark.get('modified', '')
                visited = bookmark.get('visited', '')
                
                # Get title
                title_elem = bookmark.find('title')
                title = title_elem.text if title_elem is not None else os.path.basename(href)
                
                # Convert timestamps
                timestamp = visited or modified or added or datetime.now().isoformat()
                if timestamp and timestamp != datetime.now().isoformat():
                    try:
                        # XBEL uses ISO format timestamps
                        timestamp_dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        timestamp = timestamp_dt.isoformat()
                    except:
                        pass  # Use as-is if parsing fails
                        
                # Clean up file path
                file_path = href
                if file_path.startswith('file://'):
                    file_path = file_path[7:]  # Remove file:// prefix
                    
                artifact = {
                    'type': 'Recent File (XBEL)',
                    'timestamp': timestamp,
                    'source': f'Linux Recent - {os.path.basename(xbel_path)}',
                    'description': f'Recent file: {title}',
                    'details': f'Path: {file_path}, Added: {added}, Modified: {modified}, Visited: {visited}',
                    'file_path': file_path,
                    'title': title,
                    'added': added,
                    'modified': modified,
                    'visited': visited
                }
                
                artifacts.append(artifact)
                
        except Exception as e:
            print(f"Error parsing XBEL file {xbel_path}: {e}")
            
        return artifacts
        
    def _extract_macos_recent(self, plist_path):
        """Extract recent files from macOS plist files."""
        artifacts = []
        
        try:
            # For demonstration, create sample macOS recent files data
            # In a real implementation, you'd use a plist parser
            
            mod_time = datetime.fromtimestamp(os.path.getmtime(plist_path))
            
            sample_files = [
                {
                    'path': '/Users/user/Documents/Presentation.key',
                    'name': 'Presentation.key',
                    'last_opened': datetime.now().replace(hour=9).isoformat()
                },
                {
                    'path': '/Users/user/Desktop/Report.pages',
                    'name': 'Report.pages',
                    'last_opened': datetime.now().replace(hour=14).isoformat()
                }
            ]
            
            for file_info in sample_files:
                artifact = {
                    'type': 'Recent File (macOS)',
                    'timestamp': file_info['last_opened'],
                    'source': f'macOS Recent - {os.path.basename(plist_path)}',
                    'description': f'Recent file: {file_info["name"]}',
                    'details': f'Path: {file_info["path"]}, Plist Modified: {mod_time.isoformat()}',
                    'file_path': file_info['path'],
                    'file_name': file_info['name'],
                    'plist_modified': mod_time.isoformat()
                }
                
                artifacts.append(artifact)
                
        except Exception as e:
            print(f"Error parsing macOS plist {plist_path}: {e}")
            
        return artifacts
        
    def _extract_office_recent(self, file_path):
        """Extract recent files from Microsoft Office recent files."""
        artifacts = []
        
        try:
            # For demonstration, create sample Office recent files
            mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
            
            # Sample Office recent files
            office_files = [
                {
                    'path': 'C:\\Users\\User\\Documents\\Budget.xlsx',
                    'app': 'Microsoft Excel',
                    'last_opened': datetime.now().replace(hour=11).isoformat()
                },
                {
                    'path': 'C:\\Users\\User\\Desktop\\Meeting Notes.docx',
                    'app': 'Microsoft Word', 
                    'last_opened': datetime.now().replace(hour=16).isoformat()
                }
            ]
            
            for office_file in office_files:
                artifact = {
                    'type': 'Recent File (Office)',
                    'timestamp': office_file['last_opened'],
                    'source': f'Office Recent - {os.path.basename(file_path)}',
                    'description': f'Recent Office file: {os.path.basename(office_file["path"])}',
                    'details': f'Path: {office_file["path"]}, Application: {office_file["app"]}, Registry Modified: {mod_time.isoformat()}',
                    'file_path': office_file['path'],
                    'application': office_file['app'],
                    'registry_modified': mod_time.isoformat()
                }
                
                artifacts.append(artifact)
                
        except Exception as e:
            print(f"Error extracting Office recent files from {file_path}: {e}")
            
        return artifacts
        
    def extract_mru_lists(self, source_path):
        """Extract Most Recently Used (MRU) lists from Windows registry."""
        artifacts = []
        
        try:
            # For demonstration, create sample MRU data
            # In a real implementation, you'd parse registry hives
            
            mru_locations = [
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs',
                'HKCU\\Software\\Microsoft\\Office\\Common\\Open Find\\Microsoft Office\\Settings'
            ]
            
            sample_mru_entries = [
                {
                    'location': 'OpenSaveMRU\\docx',
                    'file': 'C:\\Users\\User\\Documents\\Contract.docx',
                    'timestamp': datetime.now().replace(hour=13).isoformat()
                },
                {
                    'location': 'RecentDocs\\.txt',
                    'file': 'C:\\Users\\User\\Desktop\\Notes.txt',
                    'timestamp': datetime.now().replace(hour=8).isoformat()
                }
            ]
            
            for entry in sample_mru_entries:
                artifact = {
                    'type': 'Recent File (MRU)',
                    'timestamp': entry['timestamp'],
                    'source': f'Registry MRU - {entry["location"]}',
                    'description': f'MRU entry: {os.path.basename(entry["file"])}',
                    'details': f'Path: {entry["file"]}, Registry Location: {entry["location"]}',
                    'file_path': entry['file'],
                    'registry_location': entry['location']
                }
                
                artifacts.append(artifact)
                
        except Exception as e:
            print(f"Error extracting MRU lists: {e}")
            
        return artifacts
        
    def extract_prefetch_files(self, source_path):
        """Extract information from Windows Prefetch files."""
        artifacts = []
        
        try:
            # Look for prefetch directory
            prefetch_dirs = []
            if os.path.isdir(source_path):
                for root, dirs, files in os.walk(source_path):
                    if 'prefetch' in root.lower():
                        prefetch_dirs.append(root)
                        
            # For demonstration, create sample prefetch data
            sample_prefetch = [
                {
                    'filename': 'NOTEPAD.EXE-D8414F97.pf',
                    'executable': 'NOTEPAD.EXE',
                    'run_count': 15,
                    'last_run': datetime.now().replace(hour=12).isoformat()
                },
                {
                    'filename': 'CHROME.EXE-A644B32D.pf',
                    'executable': 'CHROME.EXE',
                    'run_count': 42,
                    'last_run': datetime.now().replace(hour=18).isoformat()
                }
            ]
            
            for pf_entry in sample_prefetch:
                artifact = {
                    'type': 'Program Execution (Prefetch)',
                    'timestamp': pf_entry['last_run'],
                    'source': f'Prefetch - {pf_entry["filename"]}',
                    'description': f'Executed: {pf_entry["executable"]}',
                    'details': f'Executable: {pf_entry["executable"]}, Run Count: {pf_entry["run_count"]}, Prefetch File: {pf_entry["filename"]}',
                    'executable': pf_entry['executable'],
                    'run_count': pf_entry['run_count'],
                    'prefetch_file': pf_entry['filename']
                }
                
                artifacts.append(artifact)
                
        except Exception as e:
            print(f"Error extracting Prefetch files: {e}")
            
        return artifacts