import logging
from utils.feature_extractor import FeatureExtractor
from utils.virustotal_checker import VirusTotalChecker
from models.ml_model import PhishingDetectionModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PhishingDetectionEngine:
    """Main phishing detection engine combining multiple detection methods"""
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.ml_model = PhishingDetectionModel()
        try:
            self.vt_checker = VirusTotalChecker()
        except ValueError:
            logger.warning("VirusTotal API key not configured")
            self.vt_checker = None
    
    def analyze_url(self, url):
        """Comprehensive URL analysis using multiple methods"""
        results = {
            'url': url,
            'overall_verdict': None,
            'risk_level': 'UNKNOWN',
            'confidence_score': 0,
            'detections': {}
        }
        
        try:
            # 1. URL Feature Analysis
            logger.info(f"Analyzing URL: {url}")
            url_features = self.feature_extractor.extract_url_features(url)
            
            if url_features:
                results['url_features'] = url_features
                logger.info("URL features extracted successfully")
            
            # 2. HTML Content Analysis
            try:
                html_features = self.feature_extractor.extract_html_features(url)
                if html_features:
                    results['html_features'] = html_features
                    logger.info("HTML features extracted successfully")
            except Exception as e:
                logger.warning(f"Could not extract HTML features: {e}")
                html_features = None
            
            # 3. Domain Analysis
            try:
                domain_features = self.feature_extractor.extract_domain_features(url)
                if domain_features:
                    results['domain_features'] = domain_features
                    logger.info("Domain features extracted successfully")
            except Exception as e:
                logger.warning(f"Could not extract domain features: {e}")
                domain_features = None
            
            # 4. VirusTotal Check
            if self.vt_checker:
                try:
                    vt_results = self.vt_checker.check_url(url)
                    results['virustotal'] = vt_results
                    logger.info(f"VirusTotal check completed: {vt_results}")
                except Exception as e:
                    logger.warning(f"VirusTotal check failed: {e}")
            
            # 5. ML Model Prediction
            combined_features = {**url_features}
            if html_features:
                combined_features.update(html_features)
            if domain_features:
                combined_features.update(domain_features)
            
            ml_prediction = self.ml_model.predict(combined_features)
            if ml_prediction:
                results['ml_detection'] = ml_prediction
                logger.info(f"ML prediction: {ml_prediction}")
            
            # 6. Calculate Final Verdict
            results = self._calculate_final_verdict(results)
            
        except Exception as e:
            logger.error(f"Error during URL analysis: {e}")
            results['error'] = str(e)
        
        return results
    
    def _calculate_final_verdict(self, results):
        """Calculate final verdict based on all detection methods"""
        phishing_score = 0
        detection_count = 0
        
        # VirusTotal verdict
        if 'virustotal' in results and results['virustotal'].get('status') == 'success':
            vt = results['virustotal']
            if vt.get('is_malicious'):
                phishing_score += 40
            elif vt.get('is_suspicious'):
                phishing_score += 20
            detection_count += 1
        
        # ML Model verdict
        if 'ml_detection' in results:
            ml = results['ml_detection']
            if ml['is_phishing']:
                phishing_score += 40
            detection_count += 1
            results['detections']['ml_model'] = {
                'verdict': ml['prediction'],
                'confidence': ml['confidence'],
                'probability': ml['probability']
            }
        
        # URL Features verdict
        if 'url_features' in results:
            url_score = self._calculate_url_risk_score(results['url_features'])
            phishing_score += url_score
            detection_count += 1
        
        # HTML Features verdict
        if 'html_features' in results:
            html_score = self._calculate_html_risk_score(results['html_features'])
            phishing_score += html_score
            detection_count += 1
        
        # Normalize score
        if detection_count > 0:
            final_score = phishing_score / detection_count
        else:
            final_score = 0
        
        # Determine overall verdict
        if final_score >= 70:
            results['overall_verdict'] = 'PHISHING'
            results['risk_level'] = 'HIGH'
        elif final_score >= 40:
            results['overall_verdict'] = 'SUSPICIOUS'
            results['risk_level'] = 'MEDIUM'
        elif final_score >= 20:
            results['overall_verdict'] = 'WARNING'
            results['risk_level'] = 'LOW'
        else:
            results['overall_verdict'] = 'SAFE'
            results['risk_level'] = 'SAFE'
        
        results['confidence_score'] = round(final_score, 2)
        
        return results
    
    def _calculate_url_risk_score(self, url_features):
        """Calculate risk score from URL features"""
        score = 0
        
        if url_features.get('has_https') == 0:
            score += 5
        if url_features.get('is_ip_address') == 1:
            score += 10
        if url_features.get('at_symbol_count', 0) > 0:
            score += 15
        if url_features.get('suspicious_tld') == 1:
            score += 10
        if url_features.get('has_double_encoding') == 1:
            score += 15
        if url_features.get('domain_has_digit') == 1:
            score += 5
        
        suspicious_keywords = url_features.get('has_suspicious_keywords', 0)
        score += min(suspicious_keywords * 3, 15)
        
        subdomain_count = url_features.get('subdomain_count', 0)
        if subdomain_count > 3:
            score += 8
        
        return min(score, 40)
    
    def _calculate_html_risk_score(self, html_features):
        """Calculate risk score from HTML features"""
        score = 0
        
        if html_features.get('forms_with_password', 0) > 0:
            score += 15
        if html_features.get('form_count', 0) > 2:
            score += 5
        
        external_links = html_features.get('external_links', 0)
        if external_links > 5:
            score += 5
        
        suspicious_keywords = html_features.get('suspicious_html_keywords', 0)
        score += min(suspicious_keywords * 4, 15)
        
        if html_features.get('has_title') == 0:
            score += 5
        if html_features.get('has_description') == 0:
            score += 3
        
        return min(score, 40)
    
    def close(self):
        """Close connections"""
        if self.vt_checker:
            self.vt_checker.close()
