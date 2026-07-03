# Phishing Detection Tool

An AI-powered phishing detection system that combines multiple detection methods to identify and warn users about malicious URLs.

## Features

✅ **Multi-Method Detection**
- URL structural analysis
- HTML content inspection
- Domain age and WHOIS analysis
- Machine Learning classification
- VirusTotal integration

✅ **AI-Powered Analysis**
- Random Forest ML model
- Feature extraction and normalization
- Automated threat scoring
- Real-time predictions

✅ **VirusTotal Integration**
- Multi-vendor threat intelligence
- Malicious site detection
- Comprehensive vendor analysis

✅ **REST API**
- Single URL detection
- Batch URL analysis
- Detection history tracking
- Statistics and analytics

✅ **Warning System**
- Real-time alerts
- Risk level classification (HIGH, MEDIUM, LOW, SAFE)
- Confidence scoring

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- VirusTotal API key (optional but recommended)

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/shraddha-2527/phishing-detection-tool.git
cd phishing-detection-tool
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**
```bash
cp .env.example .env
```

Edit `.env` and add your VirusTotal API key:
```
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
FLASK_ENV=development
FLASK_DEBUG=True
```

Get your VirusTotal API key from: https://www.virustotal.com/gui/home/upload

## Usage

### Running the Application

```bash
python app.py
```

The API will be available at: `http://localhost:5000`

### API Endpoints

#### 1. Health Check
```bash
GET /api/health
```

**Response:**
```json
{
  "status": "ok",
  "service": "Phishing Detection Tool",
  "version": "1.0.0",
  "timestamp": "2026-07-03T10:30:00"
}
```

#### 2. Detect Single URL
```bash
POST /api/detect
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "status": "success",
  "result": {
    "url": "https://example.com",
    "overall_verdict": "SAFE",
    "risk_level": "SAFE",
    "confidence_score": 15.5,
    "detections": {
      "ml_model": {
        "verdict": "LEGITIMATE",
        "confidence": 0.92,
        "probability": {
          "phishing": 0.08,
          "legitimate": 0.92
        }
      }
    },
    "virustotal": {
      "status": "success",
      "is_malicious": false,
      "malicious_count": 0,
      "suspicious_count": 0,
      "threat_level": "SAFE"
    }
  },
  "timestamp": "2026-07-03T10:30:00"
}
```

#### 3. Batch Detection
```bash
POST /api/batch-detect
Content-Type: application/json

{
  "urls": [
    "https://example1.com",
    "https://example2.com",
    "https://example3.com"
  ]
}
```

#### 4. Get Detection History
```bash
GET /api/history?limit=50
```

#### 5. Get Statistics
```bash
GET /api/stats
```

**Response:**
```json
{
  "status": "success",
  "stats": {
    "total_detections": 100,
    "phishing_detected": 12,
    "safe_urls": 76,
    "suspicious_urls": 8,
    "warning_urls": 4,
    "average_confidence": 68.5
  }
}
```

#### 6. Clear History
```bash
DELETE /api/clear-history
```

## Detection Methods

### 1. **URL Feature Analysis**
- URL length and structure
- Special characters analysis
- Protocol validation (HTTPS vs HTTP)
- Domain and subdomain analysis
- Suspicious keywords detection
- Double encoding detection

### 2. **HTML Content Analysis**
- Form detection (especially password forms)
- Link analysis
- Suspicious keywords in content
- Meta tags validation
- JavaScript analysis

### 3. **Domain Analysis**
- Domain age calculation
- WHOIS information
- New domain detection
- Registration details

### 4. **VirusTotal Integration**
- Multi-vendor threat analysis
- Malware detection
- Real-time threat intelligence
- Detailed vendor reports

### 5. **Machine Learning Model**
- Random Forest classifier
- 100+ feature extraction
- Confidence scoring
- Probability estimation

## Risk Level Classification

| Level | Score Range | Description |
|-------|-------------|-------------|
| **HIGH** | 70-100 | Likely phishing - Block access |
| **MEDIUM** | 40-69 | Suspicious - Warn user |
| **LOW** | 20-39 | Minor warnings - Proceed with caution |
| **SAFE** | 0-19 | Legitimate URL - Safe to visit |

## Project Structure

```
phishing-detection-tool/
├── app.py                          # Flask application
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment template
├── models/
│   └── ml_model.py                # ML model implementation
├── utils/
│   ├── feature_extractor.py       # Feature extraction utilities
│   └── virustotal_checker.py      # VirusTotal API integration
├── engine/
│   └── detection_engine.py        # Main detection engine
└── README.md                       # Documentation
```

## Configuration

### Environment Variables

```env
# VirusTotal API Configuration
VIRUSTOTAL_API_KEY=your_api_key_here

# Flask Configuration
FLASK_ENV=development          # development or production
FLASK_DEBUG=True              # Enable debug mode
FLASK_PORT=5000               # Server port

# Model Configuration
MODEL_PATH=./models/phishing_model.pkl
SCALER_PATH=./models/scaler.pkl

# Logging
LOG_FILE=./logs/phishing_detection.log
```

## Security Considerations

1. **API Key Protection**: Keep your VirusTotal API key secure
2. **Rate Limiting**: Implement rate limiting in production
3. **HTTPS Only**: Always use HTTPS in production
4. **Input Validation**: All URLs are validated before analysis
5. **Error Handling**: Sensitive information is not exposed in error messages

## Performance Tips

1. Use batch detection for multiple URLs
2. Implement caching for frequently checked URLs
3. Run as a background service for network integration
4. Use connection pooling with VirusTotal

## Troubleshooting

### VirusTotal Connection Issues
- Verify API key is valid
- Check internet connectivity
- Ensure API quota is not exceeded

### Model Not Found
- Train a new model or provide pre-trained model
- Check MODEL_PATH in .env

### Feature Extraction Failures
- Verify URL format
- Check if website is accessible
- Review error logs

## Future Enhancements

- [ ] Browser extension integration
- [ ] Real-time network traffic monitoring
- [ ] Custom ML model training
- [ ] Email phishing detection
- [ ] Advanced analytics dashboard
- [ ] Database integration
- [ ] Multi-language support
- [ ] Mobile app integration

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add improvement'`)
4. Push to branch (`git push origin feature/improvement`)
5. Create Pull Request

## License

This project is licensed under the MIT License - see LICENSE file for details.

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Contact: shraddhab2527@gmail.com

## Disclaimer

This tool is designed for educational and security purposes. Always verify URLs through multiple sources before accessing suspicious links. The tool provides recommendations but should not be the sole basis for security decisions.

---

**Made with ❤️ by Shraddha**
