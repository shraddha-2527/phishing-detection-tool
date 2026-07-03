import unittest
from utils.feature_extractor import FeatureExtractor

class TestFeatureExtractor(unittest.TestCase):
    """Unit tests for feature extractor"""
    
    def test_url_features_extraction(self):
        """Test URL feature extraction"""
        url = "https://example.com/path?query=value"
        features = FeatureExtractor.extract_url_features(url)
        
        self.assertIsNotNone(features)
        self.assertIn('url_length', features)
        self.assertIn('domain_length', features)
        self.assertEqual(features['has_https'], 1)
    
    def test_ip_address_detection(self):
        """Test IP address detection"""
        ip_url = "http://192.168.1.1"
        features = FeatureExtractor.extract_url_features(ip_url)
        
        self.assertEqual(features['is_ip_address'], 1)
    
    def test_suspicious_tld_detection(self):
        """Test suspicious TLD detection"""
        suspicious_url = "https://example.tk"
        features = FeatureExtractor.extract_url_features(suspicious_url)
        
        self.assertEqual(features['suspicious_tld'], 1)
    
    def test_at_symbol_detection(self):
        """Test @ symbol detection"""
        malicious_url = "https://example.com@fake-bank.com"
        features = FeatureExtractor.extract_url_features(malicious_url)
        
        self.assertGreater(features['at_symbol_count'], 0)

if __name__ == '__main__':
    unittest.main()
