"""
VirusTotal Checker Module
Integrates with VirusTotal API for malware and phishing detection
"""

import requests
import os
from typing import Dict, Optional
import time

class VirusTotalChecker:
    """Check URLs against VirusTotal database"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self):
        """Initialize with API key from environment"""
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.headers = {
            'x-apikey': self.api_key
        } if self.api_key else {}
    
    def check_url(self, url: str) -> Dict:
        """
        Check URL using VirusTotal API
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with detection results
        """
        
        if not self.api_key:
            return self._no_api_key_response()
        
        try:
            # Encode URL for submission
            data = {'url': url}
            
            # Submit URL for analysis
            response = requests.post(
                f"{self.BASE_URL}/urls",
                data=data,
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code != 200:
                return {
                    'status': 'error',
                    'error': f'Failed to submit URL: {response.status_code}',
                    'is_malicious': False,
                    'malicious_count': 0,
                    'suspicious_count': 0
                }
            
            # Get scan results
            result = response.json()
            scan_id = result.get('data', {}).get('id')
            
            if not scan_id:
                return {
                    'status': 'error',
                    'error': 'No scan ID returned',
                    'is_malicious': False,
                    'malicious_count': 0,
                    'suspicious_count': 0
                }
            
            # Wait a moment and get results
            time.sleep(2)
            analysis_results = self._get_analysis_results(scan_id)
            
            return analysis_results
            
        except requests.exceptions.Timeout:
            return {
                'status': 'error',
                'error': 'VirusTotal request timeout',
                'is_malicious': False,
                'malicious_count': 0,
                'suspicious_count': 0
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'is_malicious': False,
                'malicious_count': 0,
                'suspicious_count': 0
            }
    
    def _get_analysis_results(self, scan_id: str) -> Dict:
        """Get analysis results for a scan"""
        try:
            response = requests.get(
                f"{self.BASE_URL}/analyses/{scan_id}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code != 200:
                return {
                    'status': 'pending',
                    'is_malicious': False,
                    'malicious_count': 0,
                    'suspicious_count': 0,
                    'threat_level': 'UNKNOWN'
                }
            
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            
            is_malicious = malicious > 0
            
            return {
                'status': 'success',
                'is_malicious': is_malicious,
                'malicious_count': malicious,
                'suspicious_count': suspicious,
                'undetected_count': undetected,
                'threat_level': self._calculate_threat_level(malicious, suspicious),
                'scan_id': scan_id
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'is_malicious': False,
                'malicious_count': 0,
                'suspicious_count': 0
            }
    
    def _calculate_threat_level(self, malicious: int, suspicious: int) -> str:
        """Calculate threat level based on detections"""
        if malicious > 0:
            return 'HIGH'
        elif suspicious > 0:
            return 'MEDIUM'
        else:
            return 'SAFE'
    
    def _no_api_key_response(self) -> Dict:
        """Return response when API key is not configured"""
        return {
            'status': 'unavailable',
            'error': 'VirusTotal API key not configured',
            'is_malicious': False,
            'malicious_count': 0,
            'suspicious_count': 0,
            'threat_level': 'UNKNOWN',
            'message': 'Add VIRUSTOTAL_API_KEY environment variable to enable this feature'
        }
    
    def check_url_simple(self, url: str) -> bool:
        """Simple check: returns True if URL is detected as malicious"""
        result = self.check_url(url)
        return result.get('is_malicious', False)