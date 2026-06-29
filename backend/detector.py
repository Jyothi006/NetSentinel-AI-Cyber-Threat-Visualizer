import os
import logging
import joblib
import numpy as np

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Find model path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(project_root, "models", "isolation_forest.pkl")

pipeline = None
scaler = None
model = None

def load_detector():
    """Loads the model and scaler pipeline, training a new one if missing."""
    global pipeline, scaler, model
    
    if not os.path.exists(MODEL_PATH):
        logging.warning("Isolation Forest model file not found. Training model first...")
        try:
            from backend.model import train_and_save_model
            train_and_save_model()
        except ImportError:
            # If path issue in relative import, try direct import
            from model import train_and_save_model
            train_and_save_model()
            
    try:
        pipeline = joblib.load(MODEL_PATH)
        scaler = pipeline['scaler']
        model = pipeline['model']
        logging.info("Isolation Forest model and scaler loaded successfully.")
    except Exception as e:
        logging.error(f"Error loading the machine learning model: {e}")
        # Reset to None so it safely falls back to heuristics
        model = None
        scaler = None

def get_protocol_encoded(protocol_str):
    """Maps protocol string to standard integer representation."""
    p_upper = str(protocol_str).upper()
    if "TCP" in p_upper:
        return 1
    elif "UDP" in p_upper:
        return 2
    elif "ICMP" in p_upper:
        return 3
    else:
        return 4

def analyze_packet(packet_data):
    """
    Analyzes a packet using the Isolation Forest model (4-feature schema).
    
    packet_data schema:
    {
        "src_ip": "192.168.1.50",
        "dest_ip": "10.0.0.1",
        "protocol": "TCP",
        "packet_size": 1500,
        "connection_count": 12, (or conn_freq)
        "duration": 0.45,
        "src_port": 54203,
        "dest_port": 80
    }
    """
    global model, scaler
    if model is None or scaler is None:
        load_detector()
        
    # Extract numerical features
    packet_size = float(packet_data.get("packet_size", 0))
    duration = float(packet_data.get("duration", 0))
    connection_count = float(packet_data.get("connection_count", packet_data.get("conn_freq", 0)))
    protocol_enc = float(get_protocol_encoded(packet_data.get("protocol", "TCP")))
    
    features = np.array([[
        packet_size,
        duration,
        connection_count,
        protocol_enc
    ]])
    
    prediction = 1 # Default normal
    threat_score = 10.0
    
    # Check if model is loaded (handles DLL security policy blocks)
    if model is not None and scaler is not None:
        try:
            # Scale features
            features_scaled = scaler.transform(features)
            
            # Predict outlier (-1 = anomaly, 1 = normal)
            prediction = int(model.predict(features_scaled)[0])
            
            # Get anomaly score (negative = outlier, positive = inlier)
            raw_score = model.decision_function(features_scaled)[0]
            
            # Map raw score to 0 - 100 percentage scale
            if raw_score >= 0:
                threat_score = max(5.0, 45.0 - (raw_score * 120.0))
            else:
                threat_score = min(99.9, 50.0 + (abs(raw_score) * 180.0))
                
            threat_score = round(float(threat_score), 2)
        except Exception as e:
            logging.error(f"Prediction failed, falling back to heuristics: {e}")
            prediction, threat_score = _heuristic_predict(packet_size, duration, connection_count)
    else:
        # Heuristics fallback if scikit-learn model loading fails
        prediction, threat_score = _heuristic_predict(packet_size, duration, connection_count)
        
    # Standardize predictions: Threat Score >= 45 is anomalous (-1)
    if threat_score >= 45.0:
        prediction = -1
    else:
        prediction = 1
        
    # Determine Threat Level & Category
    if prediction == 1:
        threat_level = "Normal"
        category = "Normal"
        reason = "Traffic matches normal baseline network profile."
    else:
        threat_level = "High-Risk" if threat_score >= 75.0 else "Suspicious"
        if connection_count >= 500:
            category = "DDoS Attack"
            reason = f"Critical Threat: Heavy flooding behavior detected ({int(connection_count)} conn/min)."
        elif connection_count > 100:
            category = "Port Scan"
            reason = f"Intrusive scanning detected. Rapid connection attempts ({int(connection_count)} conn/min)."
        elif packet_size >= 1000000:
            category = "Data Exfiltration"
            reason = f"High volume payload exfiltration attempt. Packet size: {round(packet_size/(1024*1024), 2)} MB."
        else:
            category = "Zero-Day Anomaly"
            reason = f"Out-of-distribution network signature with abnormal duration-to-size ratio."

    return {
        "prediction": prediction, # 1 = normal, -1 = anomaly
        "threat_level": threat_level,
        "threat_score": threat_score,
        "category": category,
        "reason": reason
    }

def _heuristic_predict(packet_size, duration, connection_count):
    """Fallback heuristic classifier if ML model is unavailable."""
    score = 10.0
    
    # Check DDoS behavior
    if connection_count > 500:
        score += 70.0
    elif connection_count > 100:
        score += 25.0
        
    # Check exfiltration behavior
    if packet_size > 2000000:
        score += 65.0
    elif packet_size > 500000:
        score += 25.0
        
    # Check scanning behavior
    if connection_count > 150 and packet_size < 128:
        score += 40.0
        
    score = min(99.9, score)
    prediction = -1 if score >= 45.0 else 1
    return prediction, score
