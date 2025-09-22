"""
Advanced Network Forensics Engine with Deep Packet Inspection
Comprehensive network traffic analysis and threat detection capabilities.
"""

import os
import json
import struct
import socket
import re
import hashlib
import gzip
import zlib
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Set, Any, BinaryIO
from collections import defaultdict, Counter
from dataclasses import dataclass
import concurrent.futures
import threading
import ipaddress
import urllib.parse
import base64

# Try to import advanced networking libraries
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.tls import TLS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not available. Install scapy for advanced packet analysis capabilities.")

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

@dataclass
class NetworkThreat:
    """Network threat detection with detailed analysis."""
    threat_id: str
    threat_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float
    source_ip: str
    destination_ip: str
    source_port: int = 0
    destination_port: int = 0
    protocol: str = ""
    description: str = ""
    indicators: List[str] = None
    payload_analysis: Dict = None
    timeline: List[Dict] = None
    mitigation: List[str] = None
    attribution: Optional[str] = None

    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []
        if self.payload_analysis is None:
            self.payload_analysis = {}
        if self.timeline is None:
            self.timeline = []
        if self.mitigation is None:
            self.mitigation = []


class AdvancedNetworkForensics:
    """Advanced network forensics and threat detection engine."""
    
    def __init__(self):
        self.threat_signatures = {}
        self.malicious_ips = set()
        self.suspicious_domains = set()
        self.c2_patterns = []
        self.dga_domains = []
        self.protocol_analyzers = {}
        self.threat_intelligence = {}
        
        # Initialize components
        self._initialize_threat_signatures()
        self._load_threat_intelligence()
        self._initialize_protocol_analyzers()
        
    def analyze_pcap_comprehensive(self, pcap_path: str, deep_analysis: bool = True) -> Dict:
        """
        Perform comprehensive PCAP analysis with threat detection.
        
        Args:
            pcap_path: Path to PCAP file
            deep_analysis: Whether to perform deep packet inspection
            
        Returns:
            Comprehensive network analysis results
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
        analysis_results = {
            'pcap_path': pcap_path,
            'file_size': os.path.getsize(pcap_path),
            'analysis_timestamp': datetime.now().isoformat(),
            'packet_summary': {},
            'conversations': [],
            'protocols': {},
            'threats_detected': [],
            'dns_analysis': {},
            'http_analysis': {},
            'tls_analysis': {},
            'malware_communications': [],
            'data_exfiltration': [],
            'lateral_movement': [],
            'c2_communications': [],
            'anomalies': [],
            'geolocation_analysis': {},
            'timeline_reconstruction': []
        }
        
        try:
            if SCAPY_AVAILABLE:
                # Use Scapy for detailed packet analysis
                analysis_results.update(self._scapy_analysis(pcap_path, deep_analysis))
            else:
                # Fallback to custom packet parsing
                analysis_results.update(self._custom_pcap_analysis(pcap_path))
            
            # Perform threat correlation
            analysis_results['threat_correlation'] = self._correlate_network_threats(analysis_results)
            
            # Generate threat assessment
            analysis_results['threat_assessment'] = self._assess_network_threats(analysis_results)
            
            # Reconstruct attack timeline
            analysis_results['attack_timeline'] = self._reconstruct_network_timeline(analysis_results)
            
        except Exception as e:
            analysis_results['error'] = f"PCAP analysis failed: {str(e)}"
        
        return analysis_results
    
    def detect_c2_communications(self, packets: List) -> List[NetworkThreat]:
        """Detect Command and Control (C2) communications."""
        c2_threats = []
        
        # Analyze HTTP communications for C2 patterns
        http_packets = [pkt for pkt in packets if hasattr(pkt, 'http')]
        
        for packet in http_packets:
            threat = self._analyze_http_c2(packet)
            if threat:
                c2_threats.append(threat)
        
        # Analyze DNS communications for C2 patterns
        dns_packets = [pkt for pkt in packets if hasattr(pkt, 'dns')]
        
        for packet in dns_packets:
            threat = self._analyze_dns_c2(packet)
            if threat:
                c2_threats.append(threat)
        
        # Analyze encrypted communications
        tls_packets = [pkt for pkt in packets if hasattr(pkt, 'tls')]
        
        for packet in tls_packets:
            threat = self._analyze_tls_c2(packet)
            if threat:
                c2_threats.append(threat)
        
        return c2_threats
    
    def detect_data_exfiltration(self, packets: List) -> List[NetworkThreat]:
        """Detect data exfiltration activities."""
        exfiltration_threats = []
        
        # Analyze large data transfers
        conversations = self._extract_conversations(packets)
        
        for conv in conversations:
            if self._is_suspicious_data_transfer(conv):
                threat = NetworkThreat(
                    threat_id=f"exfil_{conv['src_ip']}_{conv['dst_ip']}",
                    threat_type="data_exfiltration",
                    severity="HIGH",
                    confidence=0.7,
                    source_ip=conv['src_ip'],
                    destination_ip=conv['dst_ip'],
                    description=f"Suspicious large data transfer: {conv['bytes_transferred']} bytes"
                )
                exfiltration_threats.append(threat)
        
        # Analyze DNS tunneling
        dns_tunneling = self._detect_dns_tunneling(packets)
        exfiltration_threats.extend(dns_tunneling)
        
        # Analyze ICMP tunneling
        icmp_tunneling = self._detect_icmp_tunneling(packets)
        exfiltration_threats.extend(icmp_tunneling)
        
        return exfiltration_threats
    
    def detect_lateral_movement(self, packets: List) -> List[NetworkThreat]:
        """Detect lateral movement activities."""
        lateral_threats = []
        
        # Analyze SMB/CIFS traffic
        smb_packets = [pkt for pkt in packets if self._is_smb_packet(pkt)]
        
        for packet in smb_packets:
            threat = self._analyze_smb_lateral_movement(packet)
            if threat:
                lateral_threats.append(threat)
        
        # Analyze RDP connections
        rdp_packets = [pkt for pkt in packets if self._is_rdp_packet(pkt)]
        
        for packet in rdp_packets:
            threat = self._analyze_rdp_lateral_movement(packet)
            if threat:
                lateral_threats.append(threat)
        
        # Analyze SSH connections
        ssh_packets = [pkt for pkt in packets if self._is_ssh_packet(pkt)]
        
        for packet in ssh_packets:
            threat = self._analyze_ssh_lateral_movement(packet)
            if threat:
                lateral_threats.append(threat)
        
        return lateral_threats
    
    def analyze_malware_communications(self, packets: List) -> List[NetworkThreat]:
        """Analyze network communications for malware indicators."""
        malware_threats = []
        
        # Check against known malware signatures
        for packet in packets:
            threat = self._check_malware_signatures(packet)
            if threat:
                malware_threats.append(threat)
        
        # Analyze beaconing behavior
        beaconing_threats = self._detect_beaconing(packets)
        malware_threats.extend(beaconing_threats)
        
        # Analyze DGA (Domain Generation Algorithm) domains
        dga_threats = self._detect_dga_domains(packets)
        malware_threats.extend(dga_threats)
        
        return malware_threats
    
    def perform_deep_packet_inspection(self, packet) -> Dict:
        """Perform deep packet inspection on individual packet."""
        dpi_results = {
            'packet_info': {},
            'payload_analysis': {},
            'protocol_analysis': {},
            'threat_indicators': [],
            'extracted_artifacts': []
        }
        
        if not SCAPY_AVAILABLE:
            return dpi_results
        
        try:
            # Basic packet information
            dpi_results['packet_info'] = {
                'timestamp': packet.time if hasattr(packet, 'time') else '',
                'length': len(packet),
                'protocols': self._extract_protocols(packet)
            }
            
            # Layer-specific analysis
            if packet.haslayer(IP):
                dpi_results['ip_analysis'] = self._analyze_ip_layer(packet[IP])
            
            if packet.haslayer(TCP):
                dpi_results['tcp_analysis'] = self._analyze_tcp_layer(packet[TCP])
            
            if packet.haslayer(UDP):
                dpi_results['udp_analysis'] = self._analyze_udp_layer(packet[UDP])
            
            if packet.haslayer(HTTP):
                dpi_results['http_analysis'] = self._analyze_http_layer(packet[HTTP])
            
            if packet.haslayer(DNS):
                dpi_results['dns_analysis'] = self._analyze_dns_layer(packet[DNS])
            
            # Payload analysis
            if hasattr(packet, 'payload') and packet.payload:
                dpi_results['payload_analysis'] = self._analyze_payload(bytes(packet.payload))
            
        except Exception as e:
            dpi_results['dpi_error'] = str(e)
        
        return dpi_results
    
    def _initialize_threat_signatures(self):
        """Initialize network threat signatures."""
        self.threat_signatures = {
            'malware_domains': [
                'malicious-domain.com',
                'evil-c2.net',
                'badactor.org'
            ],
            'c2_patterns': [
                rb'POST /gate\.php',
                rb'GET /config\.bin',
                rb'cmd=',
                rb'upload=',
                rb'download='
            ],
            'malware_user_agents': [
                'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
                'User-Agent: *',
                'Custom-Malware-Agent'
            ],
            'suspicious_ports': [
                6667, 6668, 6669,  # IRC
                1337, 31337,       # Elite/hacker ports
                4444, 5555,        # Common backdoor ports
                8080, 8443         # Alternative HTTP/HTTPS
            ],
            'dga_patterns': [
                rb'[a-z]{8,16}\.(com|net|org|info)',  # Random string domains
                rb'[0-9]+[a-z]+\.(tk|ml|ga|cf)',      # Suspicious TLDs
            ]
        }
    
    def _load_threat_intelligence(self):
        """Load threat intelligence feeds."""
        self.threat_intelligence = {
            'malicious_ips': {
                '185.220.101.78': {'threat_type': 'c2_server', 'malware_family': 'unknown'},
                '194.61.24.107': {'threat_type': 'botnet', 'malware_family': 'mirai'},
                '103.224.182.251': {'threat_type': 'phishing', 'malware_family': 'unknown'}
            },
            'malicious_domains': {
                'evil-domain.com': {'threat_type': 'c2_server', 'first_seen': '2024-01-01'},
                'phishing-site.net': {'threat_type': 'phishing', 'first_seen': '2024-01-02'}
            },
            'malware_families': {
                'emotet': {
                    'c2_patterns': ['/gate.php', '/panel.php'],
                    'user_agents': ['Mozilla/4.0 (compatible; MSIE 8.0)']
                },
                'trickbot': {
                    'c2_patterns': ['/api/v1/', '/srv/'],
                    'user_agents': ['Custom-Bot-Agent']
                }
            }
        }
    
    def _initialize_protocol_analyzers(self):
        """Initialize protocol-specific analyzers."""
        self.protocol_analyzers = {
            'http': self._analyze_http_protocol,
            'dns': self._analyze_dns_protocol,
            'tls': self._analyze_tls_protocol,
            'smtp': self._analyze_smtp_protocol,
            'ftp': self._analyze_ftp_protocol,
            'ssh': self._analyze_ssh_protocol
        }
    
    def _scapy_analysis(self, pcap_path: str, deep_analysis: bool) -> Dict:
        """Perform analysis using Scapy framework."""
        results = {}
        
        try:
            # Read packets
            packets = scapy.rdpcap(pcap_path)
            results['total_packets'] = len(packets)
            
            # Basic packet analysis
            results['packet_summary'] = self._analyze_packet_summary(packets)
            
            # Protocol distribution
            results['protocols'] = self._analyze_protocol_distribution(packets)
            
            # Conversations analysis
            results['conversations'] = self._extract_conversations(packets)
            
            # DNS analysis
            results['dns_analysis'] = self._analyze_dns_traffic(packets)
            
            # HTTP analysis
            results['http_analysis'] = self._analyze_http_traffic(packets)
            
            # Threat detection
            results['threats_detected'] = []
            
            # C2 detection
            c2_threats = self.detect_c2_communications(packets)
            results['threats_detected'].extend(c2_threats)
            
            # Data exfiltration detection
            exfil_threats = self.detect_data_exfiltration(packets)
            results['threats_detected'].extend(exfil_threats)
            
            # Lateral movement detection
            lateral_threats = self.detect_lateral_movement(packets)
            results['threats_detected'].extend(lateral_threats)
            
            # Malware communications
            malware_threats = self.analyze_malware_communications(packets)
            results['threats_detected'].extend(malware_threats)
            
            # Deep packet inspection if requested
            if deep_analysis and len(packets) <= 10000:  # Limit for performance
                results['deep_inspection'] = []
                for i, packet in enumerate(packets[:100]):  # Analyze first 100 packets
                    dpi_result = self.perform_deep_packet_inspection(packet)
                    if dpi_result.get('threat_indicators'):
                        results['deep_inspection'].append(dpi_result)
            
        except Exception as e:
            results['scapy_error'] = str(e)
        
        return results
    
    def _custom_pcap_analysis(self, pcap_path: str) -> Dict:
        """Custom PCAP analysis when Scapy is not available."""
        results = {
            'custom_analysis': True,
            'packet_count': 0,
            'protocols': {},
            'conversations': [],
            'suspicious_activities': []
        }
        
        try:
            # Basic PCAP parsing
            with open(pcap_path, 'rb') as f:
                # Read PCAP header
                pcap_header = f.read(24)
                if len(pcap_header) < 24:
                    return {'error': 'Invalid PCAP file'}
                
                magic_number = struct.unpack('I', pcap_header[:4])[0]
                if magic_number not in [0xa1b2c3d4, 0xd4c3b2a1]:
                    return {'error': 'Invalid PCAP magic number'}
                
                # Read packets
                packet_count = 0
                while True:
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break
                    
                    _, _, incl_len, _ = struct.unpack('IIII', packet_header)
                    packet_data = f.read(incl_len)
                    
                    if len(packet_data) < incl_len:
                        break
                    
                    packet_count += 1
                    
                    # Basic packet analysis
                    if len(packet_data) >= 14:  # Ethernet header
                        # Extract basic information
                        results['suspicious_activities'].extend(
                            self._analyze_packet_data(packet_data)
                        )
                
                results['packet_count'] = packet_count
                
        except Exception as e:
            results['custom_analysis_error'] = str(e)
        
        return results
    
    def _analyze_packet_summary(self, packets: List) -> Dict:
        """Analyze packet summary statistics."""
        summary = {
            'total_packets': len(packets),
            'unique_src_ips': set(),
            'unique_dst_ips': set(),
            'protocols': Counter(),
            'packet_sizes': [],
            'time_range': {}
        }
        
        if not packets:
            return summary
        
        for packet in packets:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                summary['unique_src_ips'].add(ip_layer.src)
                summary['unique_dst_ips'].add(ip_layer.dst)
            
            # Protocol analysis
            if packet.haslayer(TCP):
                summary['protocols']['TCP'] += 1
            elif packet.haslayer(UDP):
                summary['protocols']['UDP'] += 1
            elif packet.haslayer(ICMP):
                summary['protocols']['ICMP'] += 1
            
            summary['packet_sizes'].append(len(packet))
        
        # Convert sets to counts
        summary['unique_src_ips'] = len(summary['unique_src_ips'])
        summary['unique_dst_ips'] = len(summary['unique_dst_ips'])
        
        # Time range analysis
        if hasattr(packets[0], 'time') and hasattr(packets[-1], 'time'):
            summary['time_range'] = {
                'start': datetime.fromtimestamp(packets[0].time).isoformat(),
                'end': datetime.fromtimestamp(packets[-1].time).isoformat(),
                'duration': packets[-1].time - packets[0].time
            }
        
        return summary
    
    def _analyze_protocol_distribution(self, packets: List) -> Dict:
        """Analyze protocol distribution in packets."""
        protocols = Counter()
        
        for packet in packets:
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                port = tcp_layer.dport
                
                if port == 80:
                    protocols['HTTP'] += 1
                elif port == 443:
                    protocols['HTTPS'] += 1
                elif port == 21:
                    protocols['FTP'] += 1
                elif port == 22:
                    protocols['SSH'] += 1
                elif port == 25:
                    protocols['SMTP'] += 1
                else:
                    protocols['TCP_Other'] += 1
            
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                port = udp_layer.dport
                
                if port == 53:
                    protocols['DNS'] += 1
                elif port == 67 or port == 68:
                    protocols['DHCP'] += 1
                else:
                    protocols['UDP_Other'] += 1
            
            elif packet.haslayer(ICMP):
                protocols['ICMP'] += 1
        
        return dict(protocols)
    
    def _extract_conversations(self, packets: List) -> List[Dict]:
        """Extract network conversations from packets."""
        conversations = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'first_seen': None,
            'last_seen': None,
            'protocols': set()
        })
        
        for packet in packets:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                
                # Create conversation key
                conv_key = tuple(sorted([src_ip, dst_ip]))
                
                conv = conversations[conv_key]
                conv['packets'] += 1
                conv['bytes'] += len(packet)
                
                timestamp = packet.time if hasattr(packet, 'time') else time.time()
                if conv['first_seen'] is None or timestamp < conv['first_seen']:
                    conv['first_seen'] = timestamp
                if conv['last_seen'] is None or timestamp > conv['last_seen']:
                    conv['last_seen'] = timestamp
                
                # Track protocols
                if packet.haslayer(TCP):
                    conv['protocols'].add('TCP')
                elif packet.haslayer(UDP):
                    conv['protocols'].add('UDP')
                elif packet.haslayer(ICMP):
                    conv['protocols'].add('ICMP')
        
        # Convert to list format
        conv_list = []
        for (ip1, ip2), data in conversations.items():
            conv_list.append({
                'src_ip': ip1,
                'dst_ip': ip2,
                'packets': data['packets'],
                'bytes_transferred': data['bytes'],
                'duration': data['last_seen'] - data['first_seen'] if data['last_seen'] and data['first_seen'] else 0,
                'protocols': list(data['protocols'])
            })
        
        return sorted(conv_list, key=lambda x: x['bytes_transferred'], reverse=True)
    
    def _analyze_dns_traffic(self, packets: List) -> Dict:
        """Analyze DNS traffic for threats."""
        dns_analysis = {
            'total_queries': 0,
            'unique_domains': set(),
            'suspicious_domains': [],
            'dga_candidates': [],
            'dns_tunneling': []
        }
        
        dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS)]
        dns_analysis['total_queries'] = len(dns_packets)
        
        for packet in dns_packets:
            dns_layer = packet[DNS]
            
            if dns_layer.qr == 0:  # DNS query
                if hasattr(dns_layer, 'qd') and dns_layer.qd:
                    query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                    dns_analysis['unique_domains'].add(query_name)
                    
                    # Check for suspicious domains
                    if self._is_suspicious_domain(query_name):
                        dns_analysis['suspicious_domains'].append(query_name)
                    
                    # Check for DGA candidates
                    if self._is_dga_domain(query_name):
                        dns_analysis['dga_candidates'].append(query_name)
                    
                    # Check for DNS tunneling
                    if self._is_dns_tunneling(query_name):
                        dns_analysis['dns_tunneling'].append(query_name)
        
        dns_analysis['unique_domains'] = len(dns_analysis['unique_domains'])
        return dns_analysis
    
    def _analyze_http_traffic(self, packets: List) -> Dict:
        """Analyze HTTP traffic for threats."""
        http_analysis = {
            'total_requests': 0,
            'unique_hosts': set(),
            'suspicious_requests': [],
            'c2_candidates': [],
            'malware_downloads': []
        }
        
        http_packets = [pkt for pkt in packets if pkt.haslayer(HTTP)]
        http_analysis['total_requests'] = len(http_packets)
        
        for packet in http_packets:
            http_layer = packet[HTTP]
            
            # Analyze HTTP requests
            if hasattr(http_layer, 'Method'):
                method = http_layer.Method.decode('utf-8')
                host = http_layer.Host.decode('utf-8') if hasattr(http_layer, 'Host') else ''
                uri = http_layer.Path.decode('utf-8') if hasattr(http_layer, 'Path') else ''
                
                if host:
                    http_analysis['unique_hosts'].add(host)
                
                # Check for suspicious requests
                if self._is_suspicious_http_request(method, host, uri):
                    http_analysis['suspicious_requests'].append({
                        'method': method,
                        'host': host,
                        'uri': uri
                    })
                
                # Check for C2 communications
                if self._is_c2_http_request(method, host, uri):
                    http_analysis['c2_candidates'].append({
                        'method': method,
                        'host': host,
                        'uri': uri
                    })
        
        http_analysis['unique_hosts'] = len(http_analysis['unique_hosts'])
        return http_analysis
    
    def _correlate_network_threats(self, analysis_results: Dict) -> Dict:
        """Correlate different network threats to identify attack patterns."""
        correlations = {
            'attack_chains': [],
            'persistence_indicators': [],
            'lateral_movement_chains': [],
            'data_exfiltration_campaigns': []
        }
        
        threats = analysis_results.get('threats_detected', [])
        
        # Group threats by source IP
        threats_by_ip = defaultdict(list)
        for threat in threats:
            threats_by_ip[threat.source_ip].append(threat)
        
        # Look for attack chains from same source
        for src_ip, ip_threats in threats_by_ip.items():
            if len(ip_threats) >= 2:
                correlations['attack_chains'].append({
                    'source_ip': src_ip,
                    'threat_count': len(ip_threats),
                    'threat_types': [t.threat_type for t in ip_threats],
                    'confidence': 0.8
                })
        
        return correlations
    
    def _assess_network_threats(self, analysis_results: Dict) -> Dict:
        """Assess overall network threat level."""
        threat_score = 0.0
        threat_factors = []
        
        threats = analysis_results.get('threats_detected', [])
        
        # Score based on threat count and severity
        critical_threats = [t for t in threats if t.severity == 'CRITICAL']
        high_threats = [t for t in threats if t.severity == 'HIGH']
        
        threat_score += len(critical_threats) * 0.3
        threat_score += len(high_threats) * 0.2
        
        if critical_threats:
            threat_factors.append(f"{len(critical_threats)} critical threats detected")
        if high_threats:
            threat_factors.append(f"{len(high_threats)} high-severity threats detected")
        
        # DNS analysis factors
        dns_analysis = analysis_results.get('dns_analysis', {})
        if dns_analysis.get('suspicious_domains'):
            threat_score += 0.1
            threat_factors.append("Suspicious domains detected")
        
        # HTTP analysis factors
        http_analysis = analysis_results.get('http_analysis', {})
        if http_analysis.get('c2_candidates'):
            threat_score += 0.2
            threat_factors.append("C2 communication candidates detected")
        
        # Determine overall threat level
        if threat_score >= 0.8:
            threat_level = 'CRITICAL'
        elif threat_score >= 0.6:
            threat_level = 'HIGH'
        elif threat_score >= 0.4:
            threat_level = 'MEDIUM'
        else:
            threat_level = 'LOW'
        
        return {
            'threat_score': min(threat_score, 1.0),
            'threat_level': threat_level,
            'threat_factors': threat_factors,
            'recommendations': self._generate_network_recommendations(threat_level, threat_factors)
        }
    
    def _reconstruct_network_timeline(self, analysis_results: Dict) -> List[Dict]:
        """Reconstruct timeline of network events."""
        timeline_events = []
        
        # Add threat events to timeline
        for threat in analysis_results.get('threats_detected', []):
            for event in threat.timeline:
                timeline_events.append(event)
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x.get('timestamp', ''))
        
        return timeline_events
    
    def _generate_network_recommendations(self, threat_level: str, threat_factors: List[str]) -> List[str]:
        """Generate network security recommendations."""
        recommendations = []
        
        if threat_level in ['CRITICAL', 'HIGH']:
            recommendations.extend([
                "Immediately block suspicious IP addresses and domains",
                "Isolate affected systems from the network",
                "Perform full network traffic analysis",
                "Review firewall and IDS rules"
            ])
        
        if 'C2 communication' in ' '.join(threat_factors):
            recommendations.extend([
                "Block C2 domains and IP addresses",
                "Hunt for additional compromised systems",
                "Review DNS logs for related activity"
            ])
        
        if 'Data exfiltration' in ' '.join(threat_factors):
            recommendations.extend([
                "Identify and secure sensitive data",
                "Review data loss prevention controls",
                "Monitor for additional exfiltration attempts"
            ])
        
        return recommendations
    
    # Threat detection helper methods
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious."""
        suspicious_patterns = [
            r'[a-z]{10,}\.com',  # Long random-looking domains
            r'\d+[a-z]+\.(tk|ml|ga|cf)',  # Suspicious TLDs
            r'.*\.bit$',  # Namecoin domains
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, domain, re.IGNORECASE):
                return True
        
        return domain in self.threat_intelligence.get('malicious_domains', {})
    
    def _is_dga_domain(self, domain: str) -> bool:
        """Check if domain looks like DGA-generated."""
        # Simple DGA detection heuristics
        if len(domain) > 15 and '.' in domain:
            subdomain = domain.split('.')[0]
            
            # Check for random-looking strings
            vowels = 'aeiou'
            consonants = 'bcdfghjklmnpqrstvwxyz'
            
            vowel_count = sum(1 for c in subdomain.lower() if c in vowels)
            consonant_count = sum(1 for c in subdomain.lower() if c in consonants)
            
            # Suspicious if too many consonants or too random
            if consonant_count > vowel_count * 3:
                return True
            
            # Check for dictionary words (simplified)
            if subdomain.lower() not in ['google', 'facebook', 'microsoft', 'amazon', 'apple']:
                return True
        
        return False
    
    def _is_dns_tunneling(self, domain: str) -> bool:
        """Check for DNS tunneling indicators."""
        # Long subdomains might indicate tunneling
        if '.' in domain:
            subdomains = domain.split('.')
            for subdomain in subdomains:
                if len(subdomain) > 50:  # Unusually long subdomain
                    return True
                
                # Check for base64-like patterns
                if re.match(r'^[A-Za-z0-9+/=]+$', subdomain) and len(subdomain) > 20:
                    return True
        
        return False
    
    def _is_suspicious_http_request(self, method: str, host: str, uri: str) -> bool:
        """Check if HTTP request is suspicious."""
        suspicious_patterns = [
            '/admin/',
            '/config/',
            '/gate.php',
            '/panel.php',
            'cmd=',
            'exec=',
            'shell='
        ]
        
        for pattern in suspicious_patterns:
            if pattern in uri.lower():
                return True
        
        return host in self.threat_intelligence.get('malicious_domains', {})
    
    def _is_c2_http_request(self, method: str, host: str, uri: str) -> bool:
        """Check if HTTP request looks like C2 communication."""
        c2_patterns = [
            '/api/v1/',
            '/gate.php',
            '/panel.php',
            '/config.bin',
            '/update.php'
        ]
        
        for pattern in c2_patterns:
            if pattern in uri:
                return True
        
        # Check POST requests to suspicious domains
        if method == 'POST' and host in self.threat_intelligence.get('malicious_domains', {}):
            return True
        
        return False
    
    def _is_suspicious_data_transfer(self, conversation: Dict) -> bool:
        """Check if conversation indicates suspicious data transfer."""
        # Large data transfers (>100MB) to external IPs
        if conversation['bytes_transferred'] > 100 * 1024 * 1024:
            try:
                dst_ip = ipaddress.ip_address(conversation['dst_ip'])
                if dst_ip.is_global:  # External IP
                    return True
            except ValueError:
                pass
        
        return False
    
    def _detect_dns_tunneling(self, packets: List) -> List[NetworkThreat]:
        """Detect DNS tunneling threats."""
        tunneling_threats = []
        
        dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS)]
        
        # Group DNS queries by domain
        domain_queries = defaultdict(list)
        
        for packet in dns_packets:
            dns_layer = packet[DNS]
            if dns_layer.qr == 0 and hasattr(dns_layer, 'qd') and dns_layer.qd:
                query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                domain_queries[query_name].append(packet)
        
        # Check for tunneling indicators
        for domain, queries in domain_queries.items():
            if len(queries) > 100:  # High query volume
                if self._is_dns_tunneling(domain):
                    threat = NetworkThreat(
                        threat_id=f"dns_tunnel_{domain}",
                        threat_type="dns_tunneling",
                        severity="HIGH",
                        confidence=0.8,
                        source_ip=queries[0][IP].src if queries[0].haslayer(IP) else '',
                        destination_ip=queries[0][IP].dst if queries[0].haslayer(IP) else '',
                        description=f"DNS tunneling detected to domain: {domain}"
                    )
                    tunneling_threats.append(threat)
        
        return tunneling_threats
    
    def _detect_icmp_tunneling(self, packets: List) -> List[NetworkThreat]:
        """Detect ICMP tunneling threats."""
        tunneling_threats = []
        
        icmp_packets = [pkt for pkt in packets if pkt.haslayer(ICMP)]
        
        # Check for unusual ICMP payload sizes
        for packet in icmp_packets:
            icmp_layer = packet[ICMP]
            payload_size = len(bytes(icmp_layer.payload)) if icmp_layer.payload else 0
            
            if payload_size > 100:  # Unusually large ICMP payload
                threat = NetworkThreat(
                    threat_id=f"icmp_tunnel_{packet[IP].src}_{packet[IP].dst}",
                    threat_type="icmp_tunneling",
                    severity="MEDIUM",
                    confidence=0.6,
                    source_ip=packet[IP].src,
                    destination_ip=packet[IP].dst,
                    description=f"ICMP tunneling suspected - large payload: {payload_size} bytes"
                )
                tunneling_threats.append(threat)
        
        return tunneling_threats
    
    def _detect_beaconing(self, packets: List) -> List[NetworkThreat]:
        """Detect beaconing behavior indicative of malware."""
        beaconing_threats = []
        
        # Analyze connections for regular intervals
        conversations = self._extract_conversations(packets)
        
        for conv in conversations:
            if self._is_beaconing_pattern(conv):
                threat = NetworkThreat(
                    threat_id=f"beacon_{conv['src_ip']}_{conv['dst_ip']}",
                    threat_type="beaconing",
                    severity="HIGH",
                    confidence=0.7,
                    source_ip=conv['src_ip'],
                    destination_ip=conv['dst_ip'],
                    description="Regular beaconing pattern detected"
                )
                beaconing_threats.append(threat)
        
        return beaconing_threats
    
    def _is_beaconing_pattern(self, conversation: Dict) -> bool:
        """Check if conversation shows beaconing pattern."""
        # Simple heuristic: regular intervals and consistent packet sizes
        # In real implementation, this would be more sophisticated
        return (
            conversation['packets'] > 10 and
            conversation['duration'] > 300 and  # > 5 minutes
            conversation['bytes_transferred'] / conversation['packets'] < 1000  # Small packets
        )
    
    def _detect_dga_domains(self, packets: List) -> List[NetworkThreat]:
        """Detect DGA (Domain Generation Algorithm) domains."""
        dga_threats = []
        
        dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS)]
        
        for packet in dns_packets:
            dns_layer = packet[DNS]
            if dns_layer.qr == 0 and hasattr(dns_layer, 'qd') and dns_layer.qd:
                query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                
                if self._is_dga_domain(query_name):
                    threat = NetworkThreat(
                        threat_id=f"dga_{query_name}",
                        threat_type="dga_domain",
                        severity="MEDIUM",
                        confidence=0.6,
                        source_ip=packet[IP].src if packet.haslayer(IP) else '',
                        destination_ip=packet[IP].dst if packet.haslayer(IP) else '',
                        description=f"DGA domain detected: {query_name}"
                    )
                    dga_threats.append(threat)
        
        return dga_threats
    
    # Protocol analysis methods (placeholders for comprehensive implementation)
    def _analyze_http_protocol(self, packets: List) -> Dict:
        """Analyze HTTP protocol specifics."""
        return {'http_requests': len(packets)}
    
    def _analyze_dns_protocol(self, packets: List) -> Dict:
        """Analyze DNS protocol specifics."""
        return {'dns_queries': len(packets)}
    
    def _analyze_tls_protocol(self, packets: List) -> Dict:
        """Analyze TLS protocol specifics."""
        return {'tls_sessions': len(packets)}
    
    def _analyze_smtp_protocol(self, packets: List) -> Dict:
        """Analyze SMTP protocol specifics."""
        return {'smtp_sessions': len(packets)}
    
    def _analyze_ftp_protocol(self, packets: List) -> Dict:
        """Analyze FTP protocol specifics."""
        return {'ftp_sessions': len(packets)}
    
    def _analyze_ssh_protocol(self, packets: List) -> Dict:
        """Analyze SSH protocol specifics."""
        return {'ssh_sessions': len(packets)}
    
    # Additional helper methods
    def _analyze_packet_data(self, packet_data: bytes) -> List[Dict]:
        """Analyze raw packet data for suspicious patterns."""
        suspicious_activities = []
        
        # Look for suspicious strings in packet data
        suspicious_strings = [b'cmd.exe', b'powershell', b'nc.exe', b'wget', b'curl']
        
        for sus_string in suspicious_strings:
            if sus_string in packet_data:
                suspicious_activities.append({
                    'type': 'suspicious_string',
                    'string': sus_string.decode('ascii', errors='ignore'),
                    'confidence': 0.6
                })
        
        return suspicious_activities


# Integration functions
def analyze_pcap_file(pcap_path: str) -> Dict:
    """Main function to analyze PCAP file comprehensively."""
    analyzer = AdvancedNetworkForensics()
    return analyzer.analyze_pcap_comprehensive(pcap_path)


def detect_network_threats(pcap_path: str) -> List[NetworkThreat]:
    """Detect network threats in PCAP file."""
    analyzer = AdvancedNetworkForensics()
    analysis = analyzer.analyze_pcap_comprehensive(pcap_path)
    return analysis.get('threats_detected', [])