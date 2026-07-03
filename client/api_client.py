"""
Client script to test the Phishing Detection API
"""

import requests
import json
from typing import Dict, List

class PhishingDetectionClient:
    """Client for Phishing Detection API"""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
    
    def health_check(self) -> Dict:
        """Check API health"""
        response = self.session.get(f"{self.base_url}/api/health")
        return response.json()
    
    def detect_url(self, url: str) -> Dict:
        """Detect if a single URL is phishing"""
        response = self.session.post(
            f"{self.base_url}/api/detect",
            json={"url": url}
        )
        return response.json()
    
    def detect_batch(self, urls: List[str]) -> Dict:
        """Detect multiple URLs in batch"""
        response = self.session.post(
            f"{self.base_url}/api/batch-detect",
            json={"urls": urls}
        )
        return response.json()
    
    def get_history(self, limit: int = 50) -> Dict:
        """Get detection history"""
        response = self.session.get(
            f"{self.base_url}/api/history",
            params={"limit": limit}
        )
        return response.json()
    
    def get_stats(self) -> Dict:
        """Get detection statistics"""
        response = self.session.get(f"{self.base_url}/api/stats")
        return response.json()
    
    def clear_history(self) -> Dict:
        """Clear detection history"""
        response = self.session.delete(f"{self.base_url}/api/clear-history")
        return response.json()

def main():
    """Example usage of API client"""
    
    # Initialize client
    client = PhishingDetectionClient()
    
    print("🛡️  Phishing Detection API Client\n")
    
    # Health check
    print("1️⃣  Health Check:")
    health = client.health_check()
    print(json.dumps(health, indent=2))
    print()
    
    # Single URL detection
    print("2️⃣  Single URL Detection:")
    url = "https://www.google.com"
    result = client.detect_url(url)
    print(f"URL: {url}")
    print(f"Verdict: {result['result']['overall_verdict']}")
    print(f"Risk Level: {result['result']['risk_level']}")
    print()
    
    # Batch detection
    print("3️⃣  Batch Detection:")
    urls = [
        "https://github.com",
        "https://secure-paypal.tk",
        "https://amazon.com"
    ]
    batch_result = client.detect_batch(urls)
    print(f"Analyzed {batch_result['total_urls']} URLs")
    print()
    
    # Get statistics
    print("4️⃣  Statistics:")
    stats = client.get_stats()
    print(json.dumps(stats['stats'], indent=2))
    print()
    
    # Get history
    print("5️⃣  Detection History:")
    history = client.get_history(limit=5)
    print(f"Total detections: {history['total_detections']}")
    print(f"Last 5 detections: {json.dumps(history['history'], indent=2)}")

if __name__ == "__main__":
    main()
