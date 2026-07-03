"""
Example usage of the Phishing Detection Tool
"""

from engine.detection_engine import PhishingDetectionEngine
import json

def main():
    # Initialize the detection engine
    engine = PhishingDetectionEngine()
    
    # Example URLs to test
    test_urls = [
        "https://www.google.com",
        "https://secure-paypal-verify.tk",
        "http://192.168.1.1",
        "https://amazon-account-verify.ml",
        "https://github.com"
    ]
    
    print("🛡️  Phishing Detection Tool - Examples\n")
    print("=" * 80)
    
    for url in test_urls:
        print(f"\n🔍 Analyzing: {url}")
        print("-" * 80)
        
        # Analyze URL
        result = engine.analyze_url(url)
        
        # Display results
        print(f"✅ Overall Verdict: {result['overall_verdict']}")
        print(f"⚠️  Risk Level: {result['risk_level']}")
        print(f"📊 Confidence Score: {result['confidence_score']}%")
        
        # VirusTotal results
        if 'virustotal' in result and result['virustotal'].get('status') == 'success':
            vt = result['virustotal']
            print(f"🔴 Malicious Detections: {vt.get('malicious_count', 0)}")
            print(f"🟡 Suspicious Detections: {vt.get('suspicious_count', 0)}")
            print(f"🟢 Harmless Detections: {vt.get('harmless_count', 0)}")
        
        # ML Model results
        if 'ml_detection' in result:
            ml = result['ml_detection']
            print(f"🤖 ML Prediction: {ml['prediction']} (Confidence: {ml['confidence']*100:.2f}%)")
        
        # Warning
        if result['overall_verdict'] in ['PHISHING', 'SUSPICIOUS']:
            print(f"\n⚠️  WARNING: This URL has been flagged as {result['overall_verdict']}")
            print(f"   Do not visit this website!")
    
    print("\n" + "=" * 80)
    print("✅ Analysis complete!")
    
    # Cleanup
    engine.close()

if __name__ == "__main__":
    main()
