"""
VirusTotal API Integration
Checks URLs against multiple security vendors using VirusTotal
"""

import logging
import os
import requests
import time
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VirusTotalChecker:
    """Check URLs using VirusTotal API"""
    
    def __init__(self):
        """Initialize VirusTotal checker"""
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({'x-apikey': self.api_key})
            logger.info("VirusTotal API initialized with API key")
        else:
            logger.warning("VirusTotal API key not found in environment variables")
    
    def check_url(self, url):
        """
        Check URL with VirusTotal
        
        Args:
            url (str): URL to check
            
        Returns:
            dict: VirusTotal analysis result
        """
        try:
            if not self.api_key:
                logger.warning("No VirusTotal API key configured")
                return self._get_default_result(url, error="API key not configured")
            
            # Check if URL already analyzed
            url_id = self._get_url_id(url)
            result = self._get_url_analysis(url_id)
            
            if result:
                return result
            
            # If not analyzed, submit URL for analysis
            logger.info(f"Submitting URL for analysis: {url}")
            return self._submit_url_analysis(url)
            
        except Exception as e:
            logger.error(f"Error checking URL with VirusTotal: {e}")
            return self._get_default_result(url, error=str(e))
    
    def _get_url_id(self, url):
        """
        Get VirusTotal URL ID for a given URL
        
        Args:
            url (str): URL to get ID for
            
        Returns:
            str: URL ID
        """
        import hashlib
        import base64
        url_id = base64.urlsafe_b64encode(hashlib.sha256(url.encode()).digest()).decode().rstrip('=')
        return url_id
    
    def _get_url_analysis(self, url_id):
        """
        Get existing analysis for URL
        
        Args:
            url_id (str): VirusTotal URL ID
            
        Returns:
            dict: Analysis result or None
        """
        try:
            response = self.session.get(f'{self.base_url}/urls/{url_id}', timeout=10)
            
            if response.status_code == 200:
                return self._parse_vt_response(response.json())
            elif response.status_code == 404:
                logger.info(f"URL not found in VirusTotal database: {url_id}")
                return None
            else:
                logger.warning(f"VirusTotal API returned status {response.status_code}")
                return None
                
        except requests.exceptions.Timeout:
            logger.warning("VirusTotal API request timed out")
            return None
        except Exception as e:
            logger.error(f"Error getting URL analysis: {e}")
            return None
    
    def _submit_url_analysis(self, url):
        """
        Submit URL for analysis to VirusTotal
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Submission result
        """
        try:
            data = {'url': url}
            response = self.session.post(
                f'{self.base_url}/urls',
                data=data,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"URL submitted for analysis: {url}")
                # Parse the response with pending status
                return self._parse_vt_response(response.json(), is_new=True)
            else:
                logger.warning(f"VirusTotal submission failed: {response.status_code}")
                return self._get_default_result(url)
                
        except Exception as e:
            logger.error(f"Error submitting URL to VirusTotal: {e}")
            return self._get_default_result(url, error=str(e))
    
    def _parse_vt_response(self, vt_data, is_new=False):
        """
        Parse VirusTotal API response
        
        Args:
            vt_data (dict): VirusTotal API response
            is_new (bool): Whether this is a new submission
            
        Returns:
            dict: Parsed result
        """
        try:
            attributes = vt_data.get('data', {}).get('attributes', {})
            last_analysis = attributes.get('last_analysis_stats', {})
            
            malicious_count = last_analysis.get('malicious', 0)
            suspicious_count = last_analysis.get('suspicious', 0)
            undetected_count = last_analysis.get('undetected', 0)
            timeout_count = last_analysis.get('timeout', 0)
            
            total_vendors = malicious_count + suspicious_count + undetected_count + timeout_count + last_analysis.get('harmless', 0)
            
            is_malicious = malicious_count > 0
            
            result = {
                'status': 'success',
                'url': vt_data.get('data', {}).get('id', 'unknown'),
                'is_malicious': is_malicious,
                'malicious_count': malicious_count,
                'suspicious_count': suspicious_count,
                'undetected_count': undetected_count,
                'harmless_count': last_analysis.get('harmless', 0),
                'timeout_count': timeout_count,
                'total_vendors': total_vendors,
                'threat_level': self._determine_threat_level(malicious_count, suspicious_count, total_vendors),
                'detection_ratio': f"{malicious_count}/{total_vendors}",
                'last_analysis_date': attributes.get('last_analysis_date'),
                'is_new_submission': is_new,
                'timestamp': datetime.now().isoformat()
            }
            
            if is_malicious:
                logger.warning(f"MALICIOUS URL detected: {malicious_count} vendors flagged it")
            elif suspicious_count > 0:
                logger.warning(f"SUSPICIOUS URL: {suspicious_count} vendors marked it suspicious")
            
            return result
            
        except Exception as e:
            logger.error(f"Error parsing VirusTotal response: {e}")
            return self._get_default_result('unknown', error=str(e))
    
    def _determine_threat_level(self, malicious_count, suspicious_count, total_vendors):
        """
        Determine threat level based on vendor votes
        
        Args:
            malicious_count (int): Number of vendors flagging as malicious
            suspicious_count (int): Number of vendors flagging as suspicious
            total_vendors (int): Total number of vendors
            
        Returns:
            str: Threat level
        """
        if total_vendors == 0:
            return 'UNKNOWN'
        
        malicious_ratio = malicious_count / total_vendors if total_vendors > 0 else 0
        
        if malicious_count >= 5 or malicious_ratio > 0.1:
            return 'HIGH'
        elif malicious_count > 0 or suspicious_count >= 3:
            return 'MEDIUM'
        elif suspicious_count > 0:
            return 'LOW'
        else:
            return 'SAFE'
    
    def _get_default_result(self, url, error=None):
        """
        Return default VirusTotal result when check unavailable
        
        Args:
            url (str): URL
            error (str): Error message
            
        Returns:
            dict: Default result
        """
        return {
            'status': 'unavailable' if error else 'not_found',
            'url': url,
            'is_malicious': False,
            'malicious_count': 0,
            'suspicious_count': 0,
            'undetected_count': 0,
            'harmless_count': 0,
            'total_vendors': 0,
            'threat_level': 'UNKNOWN',
            'detection_ratio': '0/0',
            'error': error,
            'timestamp': datetime.now().isoformat()
        }
