import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import numpy as np
from joblib import dump, load

class PhishingDetectionModel:
    """Machine Learning model for phishing detection"""
    
    def __init__(self, model_path=None, scaler_path=None):
        self.model_path = model_path or './models/phishing_model.pkl'
        self.scaler_path = scaler_path or './models/scaler.pkl'
        self.model = None
        self.scaler = None
        self.feature_names = None
        
        if os.path.exists(self.model_path):
            self.load_model()
        else:
            self.initialize_model()
    
    def initialize_model(self):
        """Initialize a new Random Forest model"""
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
    
    def train_model(self, X_train, y_train, feature_names):
        """Train the phishing detection model"""
        try:
            self.feature_names = feature_names
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X_train)
            
            # Train model
            self.model.fit(X_scaled, y_train)
            
            # Save model and scaler
            dump(self.model, self.model_path)
            dump(self.scaler, self.scaler_path)
            
            print(f"Model trained and saved to {self.model_path}")
            return True
        
        except Exception as e:
            print(f"Error training model: {e}")
            return False
    
    def predict(self, features_dict):
        """Predict if URL is phishing (1) or legitimate (0)"""
        try:
            if self.model is None:
                return None
            
            # Convert features dict to array in correct order
            X = np.array([features_dict.get(name, 0) for name in self.feature_names]).reshape(1, -1)
            
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Predict
            prediction = self.model.predict(X_scaled)[0]
            confidence = max(self.model.predict_proba(X_scaled)[0])
            
            return {
                'prediction': 'PHISHING' if prediction == 1 else 'LEGITIMATE',
                'is_phishing': prediction == 1,
                'confidence': float(confidence),
                'probability': {
                    'phishing': float(self.model.predict_proba(X_scaled)[0][1]),
                    'legitimate': float(self.model.predict_proba(X_scaled)[0][0])
                }
            }
        
        except Exception as e:
            print(f"Error during prediction: {e}")
            return None
    
    def get_feature_importance(self):
        """Get feature importance from the trained model"""
        if self.model is None:
            return None
        
        importance = self.model.feature_importances_
        feature_importance_dict = dict(zip(self.feature_names, importance))
        
        # Sort by importance
        sorted_features = sorted(feature_importance_dict.items(), key=lambda x: x[1], reverse=True)
        return sorted_features
    
    def load_model(self):
        """Load pre-trained model from disk"""
        try:
            self.model = load(self.model_path)
            self.scaler = load(self.scaler_path)
            print(f"Model loaded from {self.model_path}")
        except Exception as e:
            print(f"Error loading model: {e}")
            self.initialize_model()
    
    def save_model(self):
        """Save current model to disk"""
        try:
            dump(self.model, self.model_path)
            dump(self.scaler, self.scaler_path)
            print(f"Model saved to {self.model_path}")
        except Exception as e:
            print(f"Error saving model: {e}")
