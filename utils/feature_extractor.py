"""
Feature Extractor Module
Extracts features from URLs for phishing detection
"""

import re
from urllib.parse import urlparse
import tldextract

class FeatureExtractor:
    """Extract features from URLs for phishing detection"""
    
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'verify', 'account', 'update', 'confirm',
        'click', 'bank', 'secure', 'password', 'check', 'validate'
    ]
    
    SUSPICIOUS_TLDS = [
        'tk', 'ml', 'ga', 'cf', 'gq', 'tk', 'top', 'loan', 'download'
    ]
    
    @staticmethod
    def extract_url_features(url):
        """Extract all URL features"""
        features = {}
        
        try:
            parsed_url = urlparse(url)
            domain = tldextract.extract(url)
            
            # Basic URL features
            features['url_length'] = len(url)
            features['domain_length'] = len(domain.domain)
            features['subdomain_count'] = len(domain.subdomain.split('.')) if domain.subdomain else 0
            
            # Protocol features
            features['has_https'] = 1 if parsed_url.scheme == 'https' else 0
            features['has_http'] = 1 if parsed_url.scheme == 'http' else 0
            
            # Special characters
            features['dot_count'] = url.count('.')
            features['dash_count'] = url.count('-')
            features['underscore_count'] = url.count('_')
            features['at_symbol_count'] = url.count('@')
            features['double_slash_count'] = url.count('//')
            
            # TLD features
            features['tld_length'] = len(domain.suffix)
            features['suspicious_tld'] = 1 if domain.suffix in FeatureExtractor.SUSPICIOUS_TLDS else 0
            
            # IP address detection
            features['is_ip_address'] = 1 if FeatureExtractor._is_ip_address(parsed_url.netloc) else 0
            
            # Suspicious keywords
            url_lower = url.lower()
            features['has_suspicious_keywords'] = 1 if any(kw in url_lower for kw in FeatureExtractor.SUSPICIOUS_KEYWORDS) else 0
            
            # Encoding features
            features['has_url_encoding'] = 1 if '%' in url else 0
            features['has_double_encoding'] = 1 if '%25' in url else 0
            
            # Query string features
            features['has_query_string'] = 1 if parsed_url.query else 0
            features['query_string_length'] = len(parsed_url.query) if parsed_url.query else 0
            
            # Port features
            features['has_port'] = 1 if parsed_url.port else 0
            
            # Hostname features
            hostname = parsed_url.netloc
            features['hostname_length'] = len(hostname)
            features['hostname_entropy'] = FeatureExtractor._calculate_entropy(hostname)
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            features = {k: 0 for k in range(20)}  # Return zeros on error
        
        return features
    
    @staticmethod
    def _is_ip_address(hostname):
        """Check if hostname is an IP address"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, hostname))
    
    @staticmethod
    def _calculate_entropy(text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        entropy = 0
        for char in set(text):
            p = text.count(char) / len(text)
            entropy -= p * (p ** 0.5)
        return entropy
    
    @staticmethod
    def extract_html_features(html_content):
        """Extract features from HTML content"""
        features = {}
        
        try:
            if not html_content:
                return {f'html_feature_{i}': 0 for i in range(10)}
            
            html_lower = html_content.lower()
            
            # Form detection
            features['has_form'] = 1 if '<form' in html_lower else 0
            features['has_password_field'] = 1 if 'type="password"' in html_lower or "type='password'" in html_lower else 0
            
            # Link features
            features['external_links_count'] = html_lower.count('<a ')
            
            # Suspicious keywords in HTML
            features['has_login_form'] = 1 if 'login' in html_lower and '<form' in html_lower else 0
            features['has_banking_keywords'] = 1 if any(kw in html_lower for kw in ['bank', 'account', 'password']) else 0
            
            # Meta tags
            features['has_meta_refresh'] = 1 if '<meta' in html_lower and 'refresh' in html_lower else 0
            
            # JavaScript features
            features['has_javascript'] = 1 if '<script' in html_lower else 0
            
            # Iframe features
            features['has_iframe'] = 1 if '<iframe' in html_lower else 0
            
        except Exception as e:
            print(f"Error extracting HTML features: {e}")
            features = {f'html_feature_{i}': 0 for i in range(10)}
        
        return features
    
    @staticmethod
    def extract_domain_features(domain):
        """Extract domain-level features"""
        features = {}
        
        try:
            # Domain length
            features['domain_length'] = len(domain)
            
            # Character frequency
            features['digit_count'] = sum(1 for c in domain if c.isdigit())
            features['letter_count'] = sum(1 for c in domain if c.isalpha())
            
            # Vowel ratio
            vowels = sum(1 for c in domain.lower() if c in 'aeiou')
            features['vowel_ratio'] = vowels / len(domain) if len(domain) > 0 else 0
            
        except Exception as e:
            print(f"Error extracting domain features: {e}")
            features = {'domain_length': 0, 'digit_count': 0, 'letter_count': 0, 'vowel_ratio': 0}
        
        return features