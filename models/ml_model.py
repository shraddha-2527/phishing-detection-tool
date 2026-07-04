"""
Machine Learning Model for Phishing Detection
Uses Random Forest classifier with multiple features
"""

import logging
import os
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import pickle
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PhishingMLModel:
    """Machine Learning model for phishing classification"""
    
    def __init__(self):
        """Initialize ML model"""
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.model_path = os.getenv('MODEL_PATH', './models/phishing_model.pkl')
        self.scaler_path = os.getenv('SCALER_PATH', './models/scaler.pkl')
        
        self._load_or_create_model()
    
    def _load_or_create_model(self):
        """Load existing model or create a default one"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                logger.info(f"Loading pre-trained model from {self.model_path}")
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
            else:
                logger.warning(f"Model not found at {self.model_path}, creating default model")
                self._create_default_model()
        except Exception as e:
            logger.error(f"Error loading model: {e}, creating default model")
            self._create_default_model()
    
    def _create_default_model(self):
        """Create a default untrained Random Forest model"""
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        logger.info("Default Random Forest model created")
    
    def predict(self, features, url):
        """
        Predict if URL is phishing using ML model
        
        Args:
            features (dict): Extracted URL features
            url (str): Original URL for logging
            
        Returns:
            dict: Prediction result with confidence and probability
        """
        try:
            # Convert features to numpy array for prediction
            feature_vector = self._extract_feature_vector(features)
            
            if self.model is None or not hasattr(self.model, 'predict_proba'):
                # Return default safe prediction if model is untrained
                logger.warning("Model is untrained, returning neutral prediction")
                return {
                    'verdict': 'UNKNOWN',
                    'confidence': 0.5,
                    'probability': {
                        'phishing': 0.5,
                        'legitimate': 0.5
                    }
                }
            
            # Make prediction
            prediction = self.model.predict([feature_vector])[0]
            probabilities = self.model.predict_proba([feature_vector])[0]
            
            # Map prediction to verdict
            verdict = 'PHISHING' if prediction == 1 else 'LEGITIMATE'
            confidence = max(probabilities)
            
            # Extract phishing and legitimate probabilities
            phishing_prob = probabilities[1] if len(probabilities) > 1 else probabilities[0]
            legitimate_prob = probabilities[0] if len(probabilities) > 1 else 1 - probabilities[0]
            
            result = {
                'verdict': verdict,
                'confidence': float(confidence),
                'probability': {
                    'phishing': float(phishing_prob),
                    'legitimate': float(legitimate_prob)
                }
            }
            
            logger.info(f"ML Prediction for {url}: {verdict} (confidence: {confidence:.2%})")
            return result
            
        except Exception as e:
            logger.error(f"Error in ML prediction: {e}")
            return {
                'verdict': 'ERROR',
                'confidence': 0.0,
                'probability': {
                    'phishing': 0.0,
                    'legitimate': 0.0
                }
            }
    
    def _extract_feature_vector(self, features):
        """
        Extract feature vector from features dictionary
        
        Args:
            features (dict): Extracted URL features
            
        Returns:
            list: Feature vector for model prediction
        """
        # Define feature extraction order - these should match training features
        feature_vector = [
            float(features.get('url_length', 0)),
            float(features.get('has_ip_instead_of_domain', 0)),
            float(features.get('uses_http_not_https', 0)),
            float(features.get('has_multiple_subdomains', 0)),
            float(features.get('domain_age_days', 0)),
            float(features.get('contains_suspicious_keywords', 0)),
            float(features.get('has_double_encoding', 0)),
            float(features.get('has_url_shortener', 0)),
            float(features.get('special_char_count', 0)),
            float(features.get('digit_percentage', 0)),
            float(features.get('entropy_score', 0)),
        ]
        
        return feature_vector
    
    def train(self, X_train, y_train, X_test=None, y_test=None):
        """
        Train the ML model
        
        Args:
            X_train: Training feature vectors
            y_train: Training labels
            X_test: Test feature vectors (optional)
            y_test: Test labels (optional)
        """
        try:
            logger.info(f"Training model with {len(X_train)} samples")
            self.model.fit(X_train, y_train)
            
            # Evaluate if test data provided
            if X_test is not None and y_test is not None:
                score = self.model.score(X_test, y_test)
                logger.info(f"Model accuracy on test set: {score:.2%}")
            
            # Save model
            self._save_model()
            logger.info("Model trained and saved successfully")
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
    
    def _save_model(self):
        """Save model to disk"""
        try:
            # Create directories if needed
            Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            
            logger.info(f"Model saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
    
    def get_feature_importance(self):
        """Get feature importance from trained model"""
        if self.model is None or not hasattr(self.model, 'feature_importances_'):
            return None
        
        return self.model.feature_importances_
