"""
Feature Extraction for Phishing Detection
Extracts relevant features from URLs for analysis
"""

import logging
import re
import urllib.parse
from urllib.parse import urlparse
from datetime import datetime
import math
import requests
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Extract features from URLs for phishing detection"""
    
    SUSPICIOUS_KEYWORDS = [
        'verify', 'confirm', 'update', 'login', 'signin', 'secure',
        'account', 'click', 'urgent', 'suspend', 'confirm', 'validate',
        'authenticate', 'paypal', 'amazon', 'apple', 'microsoft', 'google'
    ]
    
    URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd']
    
    def extract_features(self, url):
        """
        Extract all relevant features from URL
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Dictionary of extracted features
        """
        try:
            parsed_url = urlparse(url)
            
            features = {
                'url': url,
                'url_length': len(url),
                'has_ip_instead_of_domain': self._has_ip_address(url),
                'uses_http_not_https': parsed_url.scheme == 'http',
                'has_multiple_subdomains': self._count_subdomains(parsed_url.netloc) > 2,
                'domain_age_days': self._get_domain_age(parsed_url.netloc),
                'contains_suspicious_keywords': self._has_suspicious_keywords(url),
                'has_double_encoding': self._has_double_encoding(url),
                'has_url_shortener': self._is_shortener_url(parsed_url.netloc),
                'special_char_count': self._count_special_chars(parsed_url.path),
                'digit_percentage': self._calculate_digit_percentage(parsed_url.netloc),
                'entropy_score': self._calculate_entropy(parsed_url.netloc),
                'has_at_symbol': '@' in parsed_url.netloc,
                'subdomain_count': self._count_subdomains(parsed_url.netloc),
                'tld_length': self._get_tld_length(parsed_url.netloc),
                'contains_hyphen_in_domain': '-' in parsed_url.netloc.split('/')[0],
            }
            
            logger.debug(f"Extracted features: {features}")
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features from {url}: {e}")
            return self._get_default_features(url)
    
    def calculate_feature_risk(self, features):
        """
        Calculate risk score based on features (0-1)
        
        Args:
            features (dict): Extracted features
            
        Returns:
            float: Risk score between 0 and 1
        """
        risk_score = 0.0
        
        # URL length risk
        if features.get('url_length', 0) > 100:
            risk_score += 0.15
        
        # IP address instead of domain
        if features.get('has_ip_instead_of_domain', False):
            risk_score += 0.25
        
        # HTTP instead of HTTPS
        if features.get('uses_http_not_https', False):
            risk_score += 0.10
        
        # Multiple subdomains
        if features.get('has_multiple_subdomains', False):
            risk_score += 0.15
        
        # New domain (less than 30 days)
        if features.get('domain_age_days', 365) < 30:
            risk_score += 0.20
        
        # Suspicious keywords
        if features.get('contains_suspicious_keywords', False):
            risk_score += 0.15
        
        # Double encoding
        if features.get('has_double_encoding', False):
            risk_score += 0.20
        
        # URL shortener
        if features.get('has_url_shortener', False):
            risk_score += 0.15
        
        # @ symbol in domain
        if features.get('has_at_symbol', False):
            risk_score += 0.25
        
        # High entropy in domain
        if features.get('entropy_score', 0) > 4.5:
            risk_score += 0.10
        
        # Hyphen in domain
        if features.get('contains_hyphen_in_domain', False):
            risk_score += 0.05
        
        return min(risk_score, 1.0)  # Cap at 1.0
    
    def _has_ip_address(self, url):
        """Check if URL uses IP address instead of domain"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return bool(re.search(ip_pattern, url))
    
    def _count_subdomains(self, netloc):
        """Count number of subdomains"""
        return netloc.count('.')
    
    def _get_domain_age(self, domain):
        """
        Get domain age in days
        
        Args:
            domain (str): Domain name
            
        Returns:
            int: Age in days (default 365 if cannot determine)
        """
        try:
            import whois
            domain_clean = domain.split(':')[0]  # Remove port if present
            whois_data = whois.whois(domain_clean)
            
            if whois_data and whois_data.creation_date:
                if isinstance(whois_data.creation_date, list):
                    creation_date = whois_data.creation_date[0]
                else:
                    creation_date = whois_data.creation_date
                
                age = (datetime.now() - creation_date).days
                return max(age, 0)
        except Exception as e:
            logger.debug(f"Could not determine domain age for {domain}: {e}")
        
        return 365  # Default to 1 year if cannot determine
    
    def _has_suspicious_keywords(self, url):
        """Check if URL contains suspicious keywords"""
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in self.SUSPICIOUS_KEYWORDS)
    
    def _has_double_encoding(self, url):
        """Check for double encoding in URL"""
        return '%25' in url
    
    def _is_shortener_url(self, domain):
        """Check if domain is a URL shortener"""
        return any(shortener in domain for shortener in self.URL_SHORTENERS)
    
    def _count_special_chars(self, path):
        """Count special characters in URL path"""
        return len(re.findall(r'[^a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]', path))
    
    def _calculate_digit_percentage(self, domain):
        """Calculate percentage of digits in domain"""
        if not domain:
            return 0
        digits = sum(1 for c in domain if c.isdigit())
        return (digits / len(domain)) * 100
    
    def _calculate_entropy(self, domain):
        """
        Calculate Shannon entropy of domain
        Higher entropy can indicate randomness (suspicious)
        """
        if not domain:
            return 0
        
        entropy = 0
        for char in set(domain):
            p = domain.count(char) / len(domain)
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _get_tld_length(self, domain):
        """Get TLD length"""
        parts = domain.split('.')
        if len(parts) > 0:
            return len(parts[-1])
        return 0
    
    def _get_default_features(self, url):
        """Return default/safe features"""
        return {
            'url': url,
            'url_length': len(url),
            'has_ip_instead_of_domain': False,
            'uses_http_not_https': False,
            'has_multiple_subdomains': False,
            'domain_age_days': 365,
            'contains_suspicious_keywords': False,
            'has_double_encoding': False,
            'has_url_shortener': False,
            'special_char_count': 0,
            'digit_percentage': 0,
            'entropy_score': 0,
            'has_at_symbol': False,
            'subdomain_count': 1,
            'tld_length': 3,
            'contains_hyphen_in_domain': False,
        }
