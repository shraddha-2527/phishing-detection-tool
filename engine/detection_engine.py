"""
Main Phishing Detection Engine
Combines multiple detection methods to identify phishing URLs
"""

import logging
from utils.feature_extractor import FeatureExtractor
from utils.virustotal_checker import VirusTotalChecker
from models.ml_model import PhishingMLModel
from datetime import datetime
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PhishingDetectionEngine:
    """Main detection engine combining multiple analysis methods"""
    
    def __init__(self):
        """Initialize detection components"""
        self.feature_extractor = FeatureExtractor()
        self.ml_model = PhishingMLModel()
        self.virustotal_checker = VirusTotalChecker()
        self.logger = logging.getLogger(__name__)
    
    def analyze_url(self, url):
        """
        Analyze URL using multiple methods
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Complete analysis result with verdict and confidence
        """
        try:
            self.logger.info(f"Starting analysis for URL: {url}")
            
            # Extract features from URL
            features = self.feature_extractor.extract_features(url)
            self.logger.debug(f"Extracted features: {json.dumps(str(features), indent=2)}")
            
            # ML Model Detection
            ml_result = self.ml_model.predict(features, url)
            self.logger.info(f"ML Model Result: {ml_result}")
            
            # VirusTotal Check
            vt_result = self.virustotal_checker.check_url(url)
            self.logger.info(f"VirusTotal Result: {vt_result}")
            
            # Combine results
            final_result = self._combine_results(ml_result, vt_result, features, url)
            
            self.logger.info(f"Final Verdict: {final_result['overall_verdict']} (Risk Level: {final_result['risk_level']})")
            
            return final_result
            
        except Exception as e:
            self.logger.error(f"Error analyzing URL {url}: {str(e)}")
            return self._create_error_result(str(e))
    
    def _combine_results(self, ml_result, vt_result, features, url):
        """
        Combine results from multiple detection methods
        
        Args:
            ml_result (dict): ML model detection result
            vt_result (dict): VirusTotal check result
            features (dict): Extracted URL features
            url (str): Original URL
            
        Returns:
            dict: Combined analysis result
        """
        try:
            # Calculate threat score (0-100)
            threat_score = 0
            weight_ml = 0.4
            weight_vt = 0.4
            weight_features = 0.2
            
            # ML Model contribution
            ml_phishing_prob = ml_result.get('probability', {}).get('phishing', 0)
            threat_score += ml_phishing_prob * 100 * weight_ml
            
            # VirusTotal contribution
            if vt_result.get('is_malicious'):
                threat_score += 80 * weight_vt
            elif vt_result.get('suspicious_count', 0) > 0:
                threat_score += 50 * weight_vt
            
            # Feature analysis contribution
            feature_risk = self.feature_extractor.calculate_feature_risk(features)
            threat_score += feature_risk * 100 * weight_features
            
            # Determine risk level and verdict
            risk_level, verdict = self._determine_risk_level(threat_score, vt_result)
            
            result = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'overall_verdict': verdict,
                'risk_level': risk_level,
                'confidence_score': round(threat_score, 2),
                'threat_indicators': {
                    'ml_model_threat': round(ml_phishing_prob * 100, 2),
                    'vt_detection_ratio': f"{vt_result.get('malicious_count', 0)}/{vt_result.get('total_vendors', 0)}",
                    'feature_risk_score': round(feature_risk * 100, 2)
                },
                'detections': {
                    'ml_model': {
                        'verdict': ml_result.get('verdict'),
                        'confidence': round(ml_result.get('confidence', 0), 3),
                        'probability': {
                            'phishing': round(ml_result.get('probability', {}).get('phishing', 0), 4),
                            'legitimate': round(ml_result.get('probability', {}).get('legitimate', 0), 4)
                        }
                    }
                },
                'virustotal': vt_result,
                'warnings': self._generate_warnings(features, vt_result, threat_score)
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error combining results: {str(e)}")
            return self._create_error_result(str(e))
    
    def _determine_risk_level(self, threat_score, vt_result):
        """
        Determine risk level and verdict based on threat score
        
        Args:
            threat_score (float): Combined threat score (0-100)
            vt_result (dict): VirusTotal result
            
        Returns:
            tuple: (risk_level, verdict)
        """
        # VirusTotal malicious detection overrides
        if vt_result.get('is_malicious'):
            return 'HIGH', 'PHISHING'
        
        # Score-based determination
        if threat_score >= 70:
            return 'HIGH', 'PHISHING'
        elif threat_score >= 40:
            return 'MEDIUM', 'SUSPICIOUS'
        elif threat_score >= 20:
            return 'LOW', 'WARNING'
        else:
            return 'SAFE', 'SAFE'
    
    def _generate_warnings(self, features, vt_result, threat_score):
        """
        Generate specific warnings based on detected issues
        
        Args:
            features (dict): Extracted URL features
            vt_result (dict): VirusTotal result
            threat_score (float): Combined threat score
            
        Returns:
            list: List of warning messages
        """
        warnings = []
        
        # URL-based warnings
        if features.get('has_ip_instead_of_domain'):
            warnings.append("URL uses IP address instead of domain name")
        
        if features.get('url_length') > 100:
            warnings.append("Unusually long URL - may hide suspicious domain")
        
        if features.get('uses_http_not_https'):
            warnings.append("URL uses HTTP instead of secure HTTPS")
        
        if features.get('has_multiple_subdomains'):
            warnings.append("URL contains multiple suspicious subdomains")
        
        if features.get('domain_age_days', 0) < 30:
            warnings.append("Domain is very new (less than 30 days old)")
        
        # VirusTotal warnings
        if vt_result.get('malicious_count', 0) > 0:
            warnings.append(f"Flagged by {vt_result.get('malicious_count')} security vendors")
        
        if vt_result.get('suspicious_count', 0) > 0:
            warnings.append(f"Marked suspicious by {vt_result.get('suspicious_count')} vendors")
        
        # General threat warnings
        if threat_score >= 70:
            warnings.append("CRITICAL: This URL exhibits strong phishing indicators")
        elif threat_score >= 40:
            warnings.append("WARNING: This URL shows suspicious characteristics")
        
        return warnings
    
    def _create_error_result(self, error_message):
        """
        Create error result response
        
        Args:
            error_message (str): Error message
            
        Returns:
            dict: Error result
        """
        return {
            'status': 'error',
            'error': error_message,
            'overall_verdict': 'UNKNOWN',
            'risk_level': 'UNKNOWN',
            'confidence_score': 0,
            'timestamp': datetime.now().isoformat()
        }
