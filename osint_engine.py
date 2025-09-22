"""
Automated OSINT (Open Source Intelligence) Gathering Module
Advanced intelligence collection and analysis for digital forensics investigations.
"""

import os
import json
import requests
import hashlib
import re
import socket
import whois
import dns.resolver
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Set
from collections import defaultdict, Counter
from dataclasses import dataclass
import concurrent.futures
import threading
import time
import base64
import urllib.parse

# Try to import additional OSINT libraries
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    import censys
    CENSYS_AVAILABLE = True
except ImportError:
    CENSYS_AVAILABLE = False

try:
    import virustotal_python
    VIRUSTOTAL_AVAILABLE = True
except ImportError:
    VIRUSTOTAL_AVAILABLE = False

@dataclass
class OSINTResult:
    """OSINT investigation result with detailed intelligence."""
    source: str
    data_type: str
    target: str
    intelligence: Dict
    confidence: float = 0.0
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    timestamp: str = ""
    related_indicators: List[str] = None
    attribution: Optional[str] = None
    recommendations: List[str] = None

    def __post_init__(self):
        if self.related_indicators is None:
            self.related_indicators = []
        if self.recommendations is None:
            self.recommendations = []
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class AdvancedOSINTEngine:
    """Advanced OSINT collection and analysis engine."""
    
    def __init__(self):
        self.api_keys = {}
        self.sources_available = {}
        self.intelligence_cache = {}
        self.threat_feeds = {}
        self.attribution_database = {}
        
        # Initialize OSINT sources
        self._initialize_sources()
        self._load_threat_feeds()
        self._setup_attribution_database()
        
    def investigate_comprehensive(self, indicators: List[str], 
                                investigation_type: str = "general") -> Dict:
        """
        Perform comprehensive OSINT investigation on multiple indicators.
        
        Args:
            indicators: List of IOCs (IPs, domains, hashes, emails, etc.)
            investigation_type: Type of investigation (apt, malware, phishing, etc.)
            
        Returns:
            Comprehensive OSINT investigation results
        """
        investigation_results = {
            'investigation_id': hashlib.md5(f"{datetime.now().isoformat()}_{len(indicators)}".encode()).hexdigest()[:8],
            'investigation_type': investigation_type,
            'start_time': datetime.now().isoformat(),
            'indicators_analyzed': len(indicators),
            'osint_results': [],
            'correlation_analysis': {},
            'threat_assessment': {},
            'attribution_analysis': {},
            'timeline_reconstruction': [],
            'intelligence_summary': {},
            'actionable_recommendations': []
        }
        
        try:
            # Parallel OSINT collection for performance
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                
                for indicator in indicators:
                    # Determine indicator type and launch appropriate investigations
                    indicator_type = self._classify_indicator(indicator)
                    
                    if indicator_type == 'ip':
                        futures.append(executor.submit(self._investigate_ip, indicator))
                    elif indicator_type == 'domain':
                        futures.append(executor.submit(self._investigate_domain, indicator))
                    elif indicator_type == 'hash':
                        futures.append(executor.submit(self._investigate_hash, indicator))
                    elif indicator_type == 'email':
                        futures.append(executor.submit(self._investigate_email, indicator))
                    elif indicator_type == 'url':
                        futures.append(executor.submit(self._investigate_url, indicator))
                
                # Collect results
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            investigation_results['osint_results'].extend(result)
                    except Exception as e:
                        print(f"Error in OSINT investigation: {e}")
            
            # Perform correlation analysis
            investigation_results['correlation_analysis'] = self._correlate_intelligence(
                investigation_results['osint_results']
            )
            
            # Threat assessment
            investigation_results['threat_assessment'] = self._assess_threat_level(
                investigation_results['osint_results']
            )
            
            # Attribution analysis
            investigation_results['attribution_analysis'] = self._analyze_attribution(
                investigation_results['osint_results']
            )
            
            # Timeline reconstruction
            investigation_results['timeline_reconstruction'] = self._reconstruct_timeline(
                investigation_results['osint_results']
            )
            
            # Generate intelligence summary
            investigation_results['intelligence_summary'] = self._generate_intelligence_summary(
                investigation_results
            )
            
            # Generate recommendations
            investigation_results['actionable_recommendations'] = self._generate_recommendations(
                investigation_results
            )
            
        except Exception as e:
            investigation_results['error'] = f"OSINT investigation failed: {str(e)}"
        
        investigation_results['end_time'] = datetime.now().isoformat()
        return investigation_results
    
    def investigate_apt_campaign(self, indicators: List[str]) -> Dict:
        """Investigate APT campaign using advanced OSINT techniques."""
        apt_analysis = {
            'campaign_analysis': {},
            'ttp_mapping': {},
            'infrastructure_analysis': {},
            'victim_profiling': {},
            'timeline_analysis': {},
            'attribution_assessment': {}
        }
        
        # APT-specific intelligence gathering
        for indicator in indicators:
            # Infrastructure analysis
            if self._is_ip_address(indicator) or self._is_domain(indicator):
                infra_intel = self._analyze_apt_infrastructure(indicator)
                apt_analysis['infrastructure_analysis'][indicator] = infra_intel
            
            # TTP mapping
            ttp_mapping = self._map_to_mitre_attack(indicator)
            apt_analysis['ttp_mapping'][indicator] = ttp_mapping
        
        # Cross-reference with known APT groups
        apt_analysis['attribution_assessment'] = self._attribute_to_apt_groups(indicators)
        
        return apt_analysis
    
    def investigate_malware_family(self, file_hashes: List[str]) -> Dict:
        """Investigate malware family using multiple intelligence sources."""
        malware_analysis = {
            'family_classification': {},
            'variant_analysis': {},
            'c2_infrastructure': {},
            'campaign_tracking': {},
            'evolution_timeline': {}
        }
        
        for file_hash in file_hashes:
            # Multi-source malware analysis
            vt_analysis = self._virustotal_analysis(file_hash)
            hybrid_analysis = self._hybrid_analysis_lookup(file_hash)
            malware_bazaar = self._malware_bazaar_lookup(file_hash)
            
            malware_analysis['family_classification'][file_hash] = {
                'virustotal': vt_analysis,
                'hybrid_analysis': hybrid_analysis,
                'malware_bazaar': malware_bazaar
            }
        
        return malware_analysis
    
    def monitor_threat_feeds(self, duration_hours: int = 24) -> Dict:
        """Monitor threat intelligence feeds for new indicators."""
        monitoring_results = {
            'monitoring_start': datetime.now().isoformat(),
            'duration_hours': duration_hours,
            'feeds_monitored': [],
            'new_indicators': [],
            'trending_threats': [],
            'alerts_generated': []
        }
        
        # This would integrate with real threat intelligence feeds
        # For demo purposes, showing the capability structure
        
        feeds_to_monitor = [
            'alienvault_otx',
            'misp_feeds',
            'malware_bazaar',
            'urlhaus',
            'threatfox',
            'feodo_tracker'
        ]
        
        monitoring_results['feeds_monitored'] = feeds_to_monitor
        
        # Simulate threat feed monitoring
        monitoring_results['new_indicators'] = [
            {'type': 'domain', 'indicator': 'malicious-new-domain.com', 'threat_type': 'c2'},
            {'type': 'ip', 'indicator': '192.168.1.100', 'threat_type': 'botnet'},
            {'type': 'hash', 'indicator': 'abcd1234...', 'threat_type': 'ransomware'}
        ]
        
        return monitoring_results
    
    def _initialize_sources(self):
        """Initialize available OSINT sources."""
        self.sources_available = {
            'virustotal': VIRUSTOTAL_AVAILABLE,
            'shodan': SHODAN_AVAILABLE,
            'censys': CENSYS_AVAILABLE,
            'whois': True,
            'dns': True,
            'passive_dns': False,  # Requires API key
            'hybrid_analysis': False,  # Requires API key
            'malware_bazaar': True,
            'urlhaus': True,
            'threatfox': True,
            'alienvault_otx': False,  # Requires API key
            'misp': False  # Requires configuration
        }
    
    def _load_threat_feeds(self):
        """Load threat intelligence feeds."""
        self.threat_feeds = {
            'malware_families': {
                'emotet': {
                    'c2_domains': ['emotet-c2.com', 'emotet-panel.net'],
                    'file_hashes': ['hash1', 'hash2'],
                    'techniques': ['T1055', 'T1083', 'T1003']
                },
                'trickbot': {
                    'c2_domains': ['trickbot-c2.org', 'trick-panel.net'],
                    'file_hashes': ['hash3', 'hash4'],
                    'techniques': ['T1055', 'T1012', 'T1016']
                }
            },
            'apt_groups': {
                'apt29': {
                    'aliases': ['Cozy Bear', 'The Dukes'],
                    'techniques': ['T1566.001', 'T1059.001', 'T1027'],
                    'infrastructure': ['cozy-bear-c2.com']
                },
                'apt28': {
                    'aliases': ['Fancy Bear', 'Sofacy'],
                    'techniques': ['T1566.002', 'T1055', 'T1083'],
                    'infrastructure': ['fancy-bear-c2.net']
                }
            }
        }
    
    def _setup_attribution_database(self):
        """Setup threat actor attribution database."""
        self.attribution_database = {
            'nation_state': {
                'russia': ['apt28', 'apt29', 'sandworm'],
                'china': ['apt1', 'apt40', 'apt41'],
                'north_korea': ['lazarus', 'apt38'],
                'iran': ['apt33', 'apt34', 'apt39']
            },
            'cybercriminal': {
                'ransomware': ['conti', 'ryuk', 'maze'],
                'banking': ['carbanak', 'fin7'],
                'cryptocurrency': ['lazarus_sub']
            },
            'indicators': {
                'language_artifacts': {
                    'russian': ['cyrillic_strings', 'russian_error_messages'],
                    'chinese': ['chinese_characters', 'gb2312_encoding'],
                    'korean': ['hangul_strings', 'korean_timestamps']
                },
                'operational_patterns': {
                    'working_hours': {'russia': [6, 14], 'china': [1, 9], 'iran': [3, 11]},
                    'holidays': {'russia': ['new_year', 'may_day'], 'china': ['spring_festival']}
                }
            }
        }
    
    def _classify_indicator(self, indicator: str) -> str:
        """Classify the type of indicator."""
        # IP address
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', indicator):
            return 'ip'
        
        # Domain
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$', indicator):
            return 'domain'
        
        # Hash (MD5, SHA1, SHA256)
        if re.match(r'^[a-fA-F0-9]{32}$', indicator) or \
           re.match(r'^[a-fA-F0-9]{40}$', indicator) or \
           re.match(r'^[a-fA-F0-9]{64}$', indicator):
            return 'hash'
        
        # Email
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', indicator):
            return 'email'
        
        # URL
        if indicator.startswith(('http://', 'https://', 'ftp://')):
            return 'url'
        
        return 'unknown'
    
    def _investigate_ip(self, ip_address: str) -> List[OSINTResult]:
        """Investigate IP address using multiple sources."""
        results = []
        
        # Geolocation and ISP information
        geo_intel = self._get_ip_geolocation(ip_address)
        if geo_intel:
            results.append(OSINTResult(
                source='geolocation',
                data_type='ip_intelligence',
                target=ip_address,
                intelligence=geo_intel,
                confidence=0.9
            ))
        
        # Shodan intelligence
        if SHODAN_AVAILABLE:
            shodan_intel = self._shodan_lookup(ip_address)
            if shodan_intel:
                results.append(OSINTResult(
                    source='shodan',
                    data_type='port_scan',
                    target=ip_address,
                    intelligence=shodan_intel,
                    confidence=0.8
                ))
        
        # Reputation checks
        reputation = self._check_ip_reputation(ip_address)
        if reputation:
            results.append(OSINTResult(
                source='reputation_check',
                data_type='threat_intelligence',
                target=ip_address,
                intelligence=reputation,
                confidence=0.7,
                severity=reputation.get('threat_level', 'INFO')
            ))
        
        # Passive DNS
        passive_dns = self._passive_dns_lookup(ip_address)
        if passive_dns:
            results.append(OSINTResult(
                source='passive_dns',
                data_type='dns_resolution',
                target=ip_address,
                intelligence=passive_dns,
                confidence=0.8
            ))
        
        return results
    
    def _investigate_domain(self, domain: str) -> List[OSINTResult]:
        """Investigate domain using multiple sources."""
        results = []
        
        # WHOIS information
        whois_info = self._whois_lookup(domain)
        if whois_info:
            results.append(OSINTResult(
                source='whois',
                data_type='registration_info',
                target=domain,
                intelligence=whois_info,
                confidence=0.9
            ))
        
        # DNS resolution
        dns_info = self._dns_lookup(domain)
        if dns_info:
            results.append(OSINTResult(
                source='dns',
                data_type='dns_records',
                target=domain,
                intelligence=dns_info,
                confidence=0.9
            ))
        
        # Domain reputation
        reputation = self._check_domain_reputation(domain)
        if reputation:
            results.append(OSINTResult(
                source='reputation_check',
                data_type='domain_reputation',
                target=domain,
                intelligence=reputation,
                confidence=0.7,
                severity=reputation.get('threat_level', 'INFO')
            ))
        
        # Certificate transparency
        cert_info = self._certificate_transparency_lookup(domain)
        if cert_info:
            results.append(OSINTResult(
                source='certificate_transparency',
                data_type='ssl_certificates',
                target=domain,
                intelligence=cert_info,
                confidence=0.8
            ))
        
        return results
    
    def _investigate_hash(self, file_hash: str) -> List[OSINTResult]:
        """Investigate file hash using multiple sources."""
        results = []
        
        # VirusTotal analysis
        if VIRUSTOTAL_AVAILABLE:
            vt_analysis = self._virustotal_analysis(file_hash)
            if vt_analysis:
                results.append(OSINTResult(
                    source='virustotal',
                    data_type='malware_analysis',
                    target=file_hash,
                    intelligence=vt_analysis,
                    confidence=0.9,
                    severity=vt_analysis.get('threat_level', 'INFO')
                ))
        
        # Malware Bazaar
        bazaar_info = self._malware_bazaar_lookup(file_hash)
        if bazaar_info:
            results.append(OSINTResult(
                source='malware_bazaar',
                data_type='malware_intelligence',
                target=file_hash,
                intelligence=bazaar_info,
                confidence=0.8
            ))
        
        # Hybrid Analysis
        hybrid_info = self._hybrid_analysis_lookup(file_hash)
        if hybrid_info:
            results.append(OSINTResult(
                source='hybrid_analysis',
                data_type='sandbox_analysis',
                target=file_hash,
                intelligence=hybrid_info,
                confidence=0.8
            ))
        
        return results
    
    def _investigate_email(self, email: str) -> List[OSINTResult]:
        """Investigate email address using OSINT techniques."""
        results = []
        
        # Domain analysis of email
        domain = email.split('@')[1]
        domain_results = self._investigate_domain(domain)
        
        # Adapt domain results for email context
        for result in domain_results:
            email_result = OSINTResult(
                source=result.source,
                data_type=f"email_{result.data_type}",
                target=email,
                intelligence=result.intelligence,
                confidence=result.confidence * 0.8  # Slightly lower confidence for email context
            )
            results.append(email_result)
        
        # Email-specific checks
        email_reputation = self._check_email_reputation(email)
        if email_reputation:
            results.append(OSINTResult(
                source='email_reputation',
                data_type='email_intelligence',
                target=email,
                intelligence=email_reputation,
                confidence=0.7
            ))
        
        return results
    
    def _investigate_url(self, url: str) -> List[OSINTResult]:
        """Investigate URL using multiple sources."""
        results = []
        
        # URL reputation
        url_reputation = self._check_url_reputation(url)
        if url_reputation:
            results.append(OSINTResult(
                source='url_reputation',
                data_type='url_analysis',
                target=url,
                intelligence=url_reputation,
                confidence=0.7,
                severity=url_reputation.get('threat_level', 'INFO')
            ))
        
        # Extract domain and analyze
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            domain_results = self._investigate_domain(domain)
            for result in domain_results:
                url_result = OSINTResult(
                    source=result.source,
                    data_type=f"url_{result.data_type}",
                    target=url,
                    intelligence=result.intelligence,
                    confidence=result.confidence * 0.9
                )
                results.append(url_result)
        
        except Exception:
            pass
        
        return results
    
    # Intelligence source implementations (simplified for demo)
    def _get_ip_geolocation(self, ip: str) -> Optional[Dict]:
        """Get IP geolocation information."""
        # This would integrate with real geolocation APIs
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown',
            'organization': 'Unknown',
            'asn': 'Unknown'
        }
    
    def _shodan_lookup(self, ip: str) -> Optional[Dict]:
        """Lookup IP in Shodan."""
        # This would integrate with Shodan API
        return {
            'open_ports': [80, 443, 22],
            'services': ['HTTP', 'HTTPS', 'SSH'],
            'vulnerabilities': [],
            'last_update': datetime.now().isoformat()
        }
    
    def _check_ip_reputation(self, ip: str) -> Optional[Dict]:
        """Check IP reputation across multiple sources."""
        # This would check multiple reputation sources
        return {
            'threat_level': 'LOW',
            'reputation_score': 0.3,
            'sources_checked': ['virustotal', 'abuseipdb', 'malwaredomainlist'],
            'detections': 0
        }
    
    def _whois_lookup(self, domain: str) -> Optional[Dict]:
        """Perform WHOIS lookup."""
        try:
            # This would use real WHOIS data
            return {
                'registrar': 'Unknown',
                'creation_date': 'Unknown',
                'expiration_date': 'Unknown',
                'registrant': 'Unknown',
                'name_servers': []
            }
        except Exception:
            return None
    
    def _dns_lookup(self, domain: str) -> Optional[Dict]:
        """Perform DNS lookup."""
        try:
            # This would perform real DNS queries
            return {
                'a_records': ['192.168.1.1'],
                'mx_records': ['mail.example.com'],
                'ns_records': ['ns1.example.com'],
                'txt_records': []
            }
        except Exception:
            return None
    
    def _check_domain_reputation(self, domain: str) -> Optional[Dict]:
        """Check domain reputation."""
        return {
            'threat_level': 'LOW',
            'reputation_score': 0.2,
            'category': 'benign',
            'sources_checked': ['virustotal', 'webroot', 'fortinet']
        }
    
    def _certificate_transparency_lookup(self, domain: str) -> Optional[Dict]:
        """Lookup domain in certificate transparency logs."""
        return {
            'certificates_found': 1,
            'issuers': ['Let\'s Encrypt'],
            'validity_periods': ['2024-01-01 to 2024-12-31'],
            'subdomains_discovered': []
        }
    
    def _virustotal_analysis(self, file_hash: str) -> Optional[Dict]:
        """Analyze file hash with VirusTotal."""
        return {
            'detections': 0,
            'total_scans': 70,
            'threat_level': 'CLEAN',
            'family_classification': 'Unknown',
            'first_seen': 'Unknown'
        }
    
    def _malware_bazaar_lookup(self, file_hash: str) -> Optional[Dict]:
        """Lookup file hash in Malware Bazaar."""
        return {
            'malware_family': 'Unknown',
            'threat_type': 'Unknown',
            'first_seen': 'Unknown',
            'tags': []
        }
    
    def _hybrid_analysis_lookup(self, file_hash: str) -> Optional[Dict]:
        """Lookup file hash in Hybrid Analysis."""
        return {
            'verdict': 'Unknown',
            'threat_score': 0,
            'analysis_available': False,
            'environment': 'Unknown'
        }
    
    def _check_email_reputation(self, email: str) -> Optional[Dict]:
        """Check email reputation."""
        return {
            'reputation_score': 0.1,
            'threat_level': 'LOW',
            'breach_exposure': False,
            'sources_checked': ['haveibeenpwned', 'emailrep']
        }
    
    def _check_url_reputation(self, url: str) -> Optional[Dict]:
        """Check URL reputation."""
        return {
            'threat_level': 'LOW',
            'category': 'benign',
            'reputation_score': 0.1,
            'sources_checked': ['virustotal', 'urlvoid', 'safebrowsing']
        }
    
    def _passive_dns_lookup(self, ip: str) -> Optional[Dict]:
        """Perform passive DNS lookup."""
        return {
            'domains_resolved': ['example.com'],
            'first_seen': 'Unknown',
            'last_seen': 'Unknown'
        }
    
    # Analysis methods
    def _correlate_intelligence(self, osint_results: List[OSINTResult]) -> Dict:
        """Correlate intelligence from multiple sources."""
        correlations = {
            'cross_references': [],
            'infrastructure_clusters': [],
            'temporal_correlations': [],
            'attribution_links': []
        }
        
        # Group results by target
        results_by_target = defaultdict(list)
        for result in osint_results:
            results_by_target[result.target].append(result)
        
        # Find cross-references
        for target, results in results_by_target.items():
            if len(results) > 1:
                correlations['cross_references'].append({
                    'target': target,
                    'sources': [r.source for r in results],
                    'confidence': np.mean([r.confidence for r in results])
                })
        
        return correlations
    
    def _assess_threat_level(self, osint_results: List[OSINTResult]) -> Dict:
        """Assess overall threat level from OSINT results."""
        threat_scores = []
        threat_indicators = []
        
        for result in osint_results:
            if result.severity in ['HIGH', 'CRITICAL']:
                threat_scores.append(0.8)
                threat_indicators.append(f"{result.source}: {result.target}")
            elif result.severity == 'MEDIUM':
                threat_scores.append(0.5)
            elif result.severity == 'LOW':
                threat_scores.append(0.2)
        
        overall_score = np.mean(threat_scores) if threat_scores else 0.0
        
        if overall_score >= 0.7:
            threat_level = 'CRITICAL'
        elif overall_score >= 0.5:
            threat_level = 'HIGH'
        elif overall_score >= 0.3:
            threat_level = 'MEDIUM'
        else:
            threat_level = 'LOW'
        
        return {
            'threat_score': overall_score,
            'threat_level': threat_level,
            'high_risk_indicators': threat_indicators,
            'assessment_confidence': 0.8
        }
    
    def _analyze_attribution(self, osint_results: List[OSINTResult]) -> Dict:
        """Analyze threat actor attribution."""
        attribution_analysis = {
            'potential_actors': [],
            'confidence_scores': {},
            'attribution_factors': [],
            'country_indicators': {}
        }
        
        # Analyze infrastructure patterns
        infrastructure_indicators = []
        for result in osint_results:
            if 'country' in result.intelligence:
                country = result.intelligence['country']
                if country in self.attribution_database['nation_state']:
                    attribution_analysis['country_indicators'][country] = \
                        attribution_analysis['country_indicators'].get(country, 0) + 1
        
        # Map to known threat actors
        for country, count in attribution_analysis['country_indicators'].items():
            if count >= 2:  # Threshold for attribution
                potential_actors = self.attribution_database['nation_state'].get(country, [])
                attribution_analysis['potential_actors'].extend(potential_actors)
        
        return attribution_analysis
    
    def _reconstruct_timeline(self, osint_results: List[OSINTResult]) -> List[Dict]:
        """Reconstruct timeline from OSINT intelligence."""
        timeline_events = []
        
        for result in osint_results:
            timeline_events.append({
                'timestamp': result.timestamp,
                'event_type': 'osint_discovery',
                'source': result.source,
                'target': result.target,
                'description': f"OSINT discovery: {result.data_type} for {result.target}",
                'severity': result.severity
            })
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x['timestamp'])
        
        return timeline_events
    
    def _generate_intelligence_summary(self, investigation_results: Dict) -> Dict:
        """Generate intelligence summary."""
        osint_results = investigation_results['osint_results']
        
        summary = {
            'total_sources': len(set(r.source for r in osint_results)),
            'indicators_by_type': Counter(self._classify_indicator(r.target) for r in osint_results),
            'threat_distribution': Counter(r.severity for r in osint_results),
            'high_confidence_findings': len([r for r in osint_results if r.confidence > 0.8]),
            'key_findings': []
        }
        
        # Extract key findings
        high_severity_results = [r for r in osint_results if r.severity in ['HIGH', 'CRITICAL']]
        for result in high_severity_results[:5]:
            summary['key_findings'].append({
                'target': result.target,
                'source': result.source,
                'severity': result.severity,
                'confidence': result.confidence
            })
        
        return summary
    
    def _generate_recommendations(self, investigation_results: Dict) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        threat_assessment = investigation_results.get('threat_assessment', {})
        threat_level = threat_assessment.get('threat_level', 'LOW')
        
        if threat_level in ['CRITICAL', 'HIGH']:
            recommendations.extend([
                "Immediately block identified malicious indicators",
                "Conduct threat hunting for related indicators",
                "Review security controls and monitoring",
                "Consider threat intelligence subscription for ongoing monitoring"
            ])
        
        attribution_analysis = investigation_results.get('attribution_analysis', {})
        if attribution_analysis.get('potential_actors'):
            recommendations.append(
                f"Research TTPs of identified threat actors: {', '.join(attribution_analysis['potential_actors'][:3])}"
            )
        
        if not recommendations:
            recommendations = [
                "Continue monitoring identified indicators",
                "Maintain current security posture",
                "Consider periodic re-evaluation of indicators"
            ]
        
        return recommendations
    
    # Helper methods
    def _is_ip_address(self, indicator: str) -> bool:
        """Check if indicator is an IP address."""
        return self._classify_indicator(indicator) == 'ip'
    
    def _is_domain(self, indicator: str) -> bool:
        """Check if indicator is a domain."""
        return self._classify_indicator(indicator) == 'domain'
    
    def _analyze_apt_infrastructure(self, indicator: str) -> Dict:
        """Analyze infrastructure for APT characteristics."""
        return {
            'infrastructure_type': 'unknown',
            'hosting_provider': 'unknown',
            'registration_patterns': {},
            'operational_security': 'unknown'
        }
    
    def _map_to_mitre_attack(self, indicator: str) -> Dict:
        """Map indicator to MITRE ATT&CK techniques."""
        return {
            'techniques': [],
            'tactics': [],
            'confidence': 0.0
        }
    
    def _attribute_to_apt_groups(self, indicators: List[str]) -> Dict:
        """Attribute indicators to known APT groups."""
        return {
            'potential_groups': [],
            'confidence_scores': {},
            'attribution_factors': []
        }


# Integration functions
def investigate_indicators(indicators: List[str], investigation_type: str = "general") -> Dict:
    """Main function to investigate indicators using OSINT."""
    engine = AdvancedOSINTEngine()
    return engine.investigate_comprehensive(indicators, investigation_type)


def investigate_apt_campaign(indicators: List[str]) -> Dict:
    """Investigate APT campaign using OSINT."""
    engine = AdvancedOSINTEngine()
    return engine.investigate_apt_campaign(indicators)


def monitor_threat_intelligence(duration_hours: int = 24) -> Dict:
    """Monitor threat intelligence feeds."""
    engine = AdvancedOSINTEngine()
    return engine.monitor_threat_feeds(duration_hours)