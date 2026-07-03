"""
Detection Engine Module
Main engine for phishing detection
"""

from utils.feature_extractor import FeatureExtractor
from utils.virustotal_checker import VirusTotalChecker
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import joblib
import os
from urllib.parse import urlparse

class PhishingDetectionEngine:
    """Main phishing detection engine"""
    
    def __init__(self):
        """Initialize detection engine"""
        self.feature_extractor = FeatureExtractor()
        self.virustotal = VirusTotalChecker()
        self.model = self._load_or_create_model()
    
    def analyze_url(self, url: str) -> dict:
        """
        Analyze URL for phishing indicators
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary with detection results
        """
        
        try:
            # Extract features
            url_features = self.feature_extractor.extract_url_features(url)
            
            # Get VirusTotal results
            vt_result = self.virustotal.check_url(url)
            
            # ML Model prediction
            ml_result = self._ml_prediction(url_features)
            
            # Calculate overall score
            overall_score = self._calculate_overall_score(url_features, vt_result, ml_result)
            
            # Determine verdict
            verdict = self._determine_verdict(overall_score)
            risk_level = self._calculate_risk_level(overall_score)
            
            result = {
                'url': url,
                'overall_verdict': verdict,
                'risk_level': risk_level,
                'confidence_score': overall_score,
                'detections': {
                    'url_analysis': {
                        'score': self._calculate_url_score(url_features),
                        'features': url_features
                    },
                    'ml_model': ml_result,
                    'virustotal': vt_result
                }
            }
            
            return result
            
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'overall_verdict': 'ERROR',
                'risk_level': 'UNKNOWN',
                'confidence_score': 0
            }
    
    def _load_or_create_model(self):
        """Load pre-trained model or create a default one"""
        try:
            model_path = os.getenv('MODEL_PATH', './models/phishing_model.pkl')
            if os.path.exists(model_path):
                return joblib.load(model_path)
        except Exception as e:
            print(f"Could not load model: {e}")
        
        # Return a dummy model if not available
        return self._create_dummy_model()
    
    def _create_dummy_model(self):
        """Create a simple dummy model for testing"""
        # Create a simple Random Forest with minimal features
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        # Dummy training data
        X_dummy = np.random.rand(100, 10)
        y_dummy = np.random.randint(0, 2, 100)
        model.fit(X_dummy, y_dummy)
        return model
    
    def _ml_prediction(self, features: dict) -> dict:
        """Get ML model prediction"""
        try:
            # Convert features to array
            feature_array = np.array(list(features.values())).reshape(1, -1)
            
            # Make prediction
            if len(feature_array[0]) < 10:
                # Pad if not enough features
                feature_array = np.pad(feature_array, ((0, 0), (0, 10 - len(feature_array[0]))), mode='constant')
            elif len(feature_array[0]) > 10:
                # Trim if too many features
                feature_array = feature_array[:, :10]
            
            prediction = self.model.predict(feature_array)[0]
            probabilities = self.model.predict_proba(feature_array)[0]
            
            return {
                'verdict': 'PHISHING' if prediction == 1 else 'LEGITIMATE',
                'confidence': float(max(probabilities)),
                'probability': {
                    'phishing': float(probabilities[1]) if len(probabilities) > 1 else 0,
                    'legitimate': float(probabilities[0])
                }
            }
        except Exception as e:
            return {
                'verdict': 'UNKNOWN',
                'confidence': 0,
                'error': str(e)
            }
    
    def _calculate_url_score(self, features: dict) -> float:
        """Calculate phishing score based on URL features"""
        score = 0
        
        # Length analysis
        if features.get('url_length', 0) > 75:
            score += 5
        
        # HTTPS check
        if features.get('has_https', 0) == 0:
            score += 10
        
        # Suspicious TLD
        if features.get('suspicious_tld', 0) == 1:
            score += 15
        
        # Special characters
        if features.get('at_symbol_count', 0) > 0:
            score += 20
        
        if features.get('dash_count', 0) > 2:
            score += 5
        
        # IP address
        if features.get('is_ip_address', 0) == 1:
            score += 25
        
        # Suspicious keywords
        if features.get('has_suspicious_keywords', 0) == 1:
            score += 10
        
        # URL encoding
        if features.get('has_double_encoding', 0) == 1:
            score += 20
        
        return min(score, 100)
    
    def _calculate_overall_score(self, url_features: dict, vt_result: dict, ml_result: dict) -> float:
        """Calculate overall phishing score"""
        
        scores = []
        weights = []
        
        # URL analysis score (30% weight)
        url_score = self._calculate_url_score(url_features)
        scores.append(url_score)
        weights.append(0.3)
        
        # VirusTotal score (40% weight)
        vt_score = 0
        if vt_result.get('is_malicious'):
            vt_score = 90
        elif vt_result.get('suspicious_count', 0) > 0:
            vt_score = 60
        elif vt_result.get('threat_level') == 'HIGH':
            vt_score = 85
        elif vt_result.get('threat_level') == 'MEDIUM':
            vt_score = 50
        
        scores.append(vt_score)
        weights.append(0.4)
        
        # ML Model score (30% weight)
        ml_score = 0
        if ml_result.get('verdict') == 'PHISHING':
            ml_score = ml_result.get('confidence', 0) * 100
        else:
            ml_score = (1 - ml_result.get('confidence', 0)) * 100
        
        scores.append(ml_score)
        weights.append(0.3)
        
        # Calculate weighted average
        overall_score = sum(s * w for s, w in zip(scores, weights))
        
        return round(overall_score, 2)
    
    def _determine_verdict(self, score: float) -> str:
        """Determine verdict based on score"""
        if score >= 70:
            return 'PHISHING'
        elif score >= 40:
            return 'SUSPICIOUS'
        elif score >= 20:
            return 'WARNING'
        else:
            return 'SAFE'
    
    def _calculate_risk_level(self, score: float) -> str:
        """Calculate risk level"""
        if score >= 70:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'SAFE'