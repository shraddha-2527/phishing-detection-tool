# Phishing Detection Tool - Setup & Usage Guide

## 🚀 Quick Start

### Step 1: Clone the Repository
```bash
git clone https://github.com/shraddha-2527/phishing-detection-tool.git
cd phishing-detection-tool
```

### Step 2: Create Virtual Environment
```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment
```bash
# Copy the example environment file
cp .env.example .env

# Edit .env file with your settings
# Add your VirusTotal API key (get it from: https://www.virustotal.com/gui/home/upload)
```

**Edit `.env` file:**
```env
VIRUSTOTAL_API_KEY=your_api_key_here
FLASK_ENV=development
FLASK_DEBUG=True
FLASK_PORT=5000
```

### Step 5: Run the Application
```bash
python app.py
```

You should see:
```
 * Running on http://127.0.0.1:5000
 * Debug mode: on
```

---

## 🌐 Access Your Tool

### Local Access
Once the server is running, you can:

1. **Open in Browser:**
   ```
   http://localhost:5000
   http://127.0.0.1:5000
   ```

2. **API Endpoint (for testing):**
   ```
   http://localhost:5000/api/health
   ```

### Network Access (From Another Device)
If you want to access from another computer on your network:

```
http://<your-computer-ip>:5000
```

**Find your IP address:**
- **Windows:** `ipconfig` (look for IPv4 Address)
- **macOS/Linux:** `ifconfig` or `hostname -I`

Example:
```
http://192.168.1.100:5000
```

---

## 📱 Using the Tool

### Method 1: REST API (Recommended for Automation)

#### Check Single URL
```bash
curl -X POST http://localhost:5000/api/detect \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Response Example:**
```json
{
  "status": "success",
  "result": {
    "url": "https://example.com",
    "overall_verdict": "SAFE",
    "risk_level": "SAFE",
    "confidence_score": 15.5,
    "threat_indicators": {
      "ml_model_threat": 5.0,
      "vt_detection_ratio": "0/0",
      "feature_risk_score": 25.0
    },
    "warnings": []
  }
}
```

#### Batch Check Multiple URLs
```bash
curl -X POST http://localhost:5000/api/batch-detect \
  -H "Content-Type: application/json" \
  -d '{
    "urls": [
      "https://example1.com",
      "https://example2.com",
      "https://suspicious-site.com"
    ]
  }'
```

#### Get Detection History
```bash
curl http://localhost:5000/api/history?limit=50
```

#### Get Statistics
```bash
curl http://localhost:5000/api/stats
```

---

## 🧪 Test Cases

### Safe URL
```bash
curl -X POST http://localhost:5000/api/detect \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'
```

### Suspicious URL (HTTP, Not HTTPS)
```bash
curl -X POST http://localhost:5000/api/detect \
  -H "Content-Type: application/json" \
  -d '{"url": "http://fake-bank.com"}'
```

### URL with IP Address
```bash
curl -X POST http://localhost:5000/api/detect \
  -H "Content-Type: application/json" \
  -d '{"url": "http://192.168.1.1/admin"}'
```

### Shortened URL
```bash
curl -X POST http://localhost:5000/api/detect \
  -H "Content-Type: application/json" \
  -d '{"url": "https://bit.ly/suspicious"}'
```

---

## 📊 Response Verdicts

| Verdict | Risk Level | Score | Meaning |
|---------|-----------|-------|---------|
| **SAFE** | SAFE | 0-19 | Legitimate URL - Safe to visit |
| **WARNING** | LOW | 20-39 | Minor warnings - Proceed with caution |
| **SUSPICIOUS** | MEDIUM | 40-69 | Shows suspicious characteristics - Warn user |
| **PHISHING** | HIGH | 70-100 | Strong phishing indicators - Block access |

---

## 🔌 Integration Examples

### Python Integration
```python
import requests
import json

url = "http://localhost:5000/api/detect"
data = {"url": "https://example.com"}

response = requests.post(url, json=data)
result = response.json()

print(f"Verdict: {result['result']['overall_verdict']}")
print(f"Risk Level: {result['result']['risk_level']}")
print(f"Confidence: {result['result']['confidence_score']}%")
```

### JavaScript Integration
```javascript
async function checkURL(url) {
  const response = await fetch('http://localhost:5000/api/detect', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ url: url })
  });
  
  const data = await response.json();
  console.log(`Verdict: ${data.result.overall_verdict}`);
  console.log(`Risk Level: ${data.result.risk_level}`);
  return data.result;
}

checkURL('https://example.com');
```

---

## 🌍 Deployment (Production)

### Using Gunicorn
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Using Docker
Create `Dockerfile`:
```dockerfile
FROM python:3.9
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

Build and run:
```bash
docker build -t phishing-detection .
docker run -p 5000:5000 -e VIRUSTOTAL_API_KEY=your_key phishing-detection
```

### Cloud Deployment (Heroku)
```bash
# Install Heroku CLI
heroku login
heroku create your-app-name

# Add environment variable
heroku config:set VIRUSTOTAL_API_KEY=your_key

# Deploy
git push heroku main
```

Access at: `https://your-app-name.herokuapp.com`

---

## 🔐 Security Configuration

### Enable HTTPS (Production)
Edit `app.py`:
```python
if __name__ == '__main__':
    ssl_context = 'adhoc'  # or provide cert.pem and key.pem
    app.run(host='0.0.0.0', port=5000, ssl_context=ssl_context)
```

### Add Rate Limiting
```bash
pip install flask-limiter
```

### API Authentication
Add to `app.py`:
```python
@app.before_request
def check_api_key():
    api_key = request.headers.get('X-API-Key')
    if not api_key or api_key != os.getenv('API_KEY'):
        return {'error': 'Unauthorized'}, 401
```

---

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Change port in .env
FLASK_PORT=5001

# Or kill the process
# Windows: netstat -ano | findstr :5000
# Linux/Mac: lsof -i :5000
```

### VirusTotal API Errors
- Verify API key is correct
- Check API quota at: https://www.virustotal.com/gui/user/account
- Ensure internet connection is active

### Module Import Errors
```bash
# Reinstall all dependencies
pip install --upgrade -r requirements.txt
```

### SSL/Certificate Errors
```bash
# Disable SSL verification (development only)
export REQUESTS_CA_BUNDLE=""
```

---

## 📈 Monitoring

### Check Service Health
```bash
curl http://localhost:5000/api/health
```

### View Logs
```bash
tail -f ./logs/phishing_detection.log
```

### Statistics
```bash
curl http://localhost:5000/api/stats
```

---

## 📞 Support

- **Documentation:** See README.md
- **Issues:** https://github.com/shraddha-2527/phishing-detection-tool/issues
- **Contact:** shraddhab2527@gmail.com

---

## 🎯 Next Steps

1. ✅ Setup and run the tool locally
2. 📊 Test with sample URLs
3. 🔌 Integrate with your network
4. 🚀 Deploy to production
5. 📈 Monitor and optimize

**Your phishing detection tool is ready to protect!** 🛡️
