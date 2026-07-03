from flask import Flask, request, jsonify
from flask_cors import CORS
from engine.detection_engine import PhishingDetectionEngine
from datetime import datetime
import logging
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize detection engine
detection_engine = PhishingDetectionEngine()

# Store detection history
detection_history = []

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'service': 'Phishing Detection Tool',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/api/detect', methods=['POST'])
def detect_phishing():
    """Main phishing detection endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'URL is required',
                'status': 'error'
            }), 400
        
        url = data['url'].strip()
        
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        logger.info(f"Processing detection request for: {url}")
        
        # Run analysis
        result = detection_engine.analyze_url(url)
        
        # Add to history
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'verdict': result.get('overall_verdict'),
            'risk_level': result.get('risk_level'),
            'confidence_score': result.get('confidence_score')
        }
        detection_history.append(history_entry)
        
        return jsonify({
            'status': 'success',
            'result': result,
            'timestamp': datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Error in detection endpoint: {e}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/batch-detect', methods=['POST'])
def batch_detect():
    """Batch detection endpoint for multiple URLs"""
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({
                'error': 'URLs list is required',
                'status': 'error'
            }), 400
        
        urls = data['urls']
        if not isinstance(urls, list):
            return jsonify({
                'error': 'URLs must be a list',
                'status': 'error'
            }), 400
        
        results = []
        for url in urls:
            try:
                url = url.strip()
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                
                result = detection_engine.analyze_url(url)
                results.append({
                    'url': url,
                    'result': result
                })
            except Exception as e:
                logger.error(f"Error processing {url}: {e}")
                results.append({
                    'url': url,
                    'error': str(e)
                })
        
        return jsonify({
            'status': 'success',
            'results': results,
            'total_urls': len(urls),
            'timestamp': datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Error in batch detection: {e}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    """Get detection history"""
    try:
        limit = request.args.get('limit', 50, type=int)
        return jsonify({
            'status': 'success',
            'history': detection_history[-limit:],
            'total_detections': len(detection_history)
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving history: {e}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get detection statistics"""
    try:
        if not detection_history:
            return jsonify({
                'status': 'success',
                'stats': {
                    'total_detections': 0,
                    'phishing_detected': 0,
                    'safe_urls': 0,
                    'suspicious_urls': 0
                }
            }), 200
        
        verdicts = [entry['verdict'] for entry in detection_history]
        
        stats = {
            'total_detections': len(detection_history),
            'phishing_detected': verdicts.count('PHISHING'),
            'safe_urls': verdicts.count('SAFE'),
            'suspicious_urls': verdicts.count('SUSPICIOUS'),
            'warning_urls': verdicts.count('WARNING'),
            'average_confidence': round(
                sum([entry['confidence_score'] for entry in detection_history]) / len(detection_history),
                2
            )
        }
        
        return jsonify({
            'status': 'success',
            'stats': stats
        }), 200
    
    except Exception as e:
        logger.error(f"Error calculating stats: {e}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/clear-history', methods=['DELETE'])
def clear_history():
    """Clear detection history"""
    try:
        global detection_history
        detection_history = []
        return jsonify({
            'status': 'success',
            'message': 'History cleared'
        }), 200
    except Exception as e:
        logger.error(f"Error clearing history: {e}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'status': 'error'
    }), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({
        'error': 'Internal server error',
        'status': 'error'
    }), 500

if __name__ == '__main__':
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', False)
    app.run(host='0.0.0.0', port=port, debug=debug)
