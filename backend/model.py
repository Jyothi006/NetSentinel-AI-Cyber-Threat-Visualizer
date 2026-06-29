import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

def generate_synthetic_data(n_samples=5000):
    """Generates synthetic network traffic dataset with 4 required features."""
    # Set seed for reproducible data generation
    np.random.seed(42)
    
    n_normal = int(n_samples * 0.90)
    n_anomaly = n_samples - n_normal
    
    # 1. Normal web/DNS/SSH traffic
    normal_data = {
        'packet_size': np.random.normal(500, 200, n_normal).clip(64, 1500),
        'duration': np.random.exponential(0.5, n_normal).clip(0.001, 10.0),
        'connection_count': np.random.poisson(5, n_normal).clip(1, 20),
        'protocol_encoded': np.random.choice([1, 2, 3], n_normal, p=[0.75, 0.20, 0.05]) # 1: TCP, 2: UDP, 3: ICMP
    }
    df_normal = pd.DataFrame(normal_data)
    
    # 2. DDoS Attack (High connection count, uniform small packets, short duration)
    n_ddos = n_anomaly // 3
    ddos_data = {
        'packet_size': np.random.normal(64, 10, n_ddos).clip(40, 100),
        'duration': np.random.uniform(0.001, 0.05, n_ddos),
        'connection_count': np.random.normal(800, 150, n_ddos).clip(500, 2000),
        'protocol_encoded': np.random.choice([1, 2], n_ddos, p=[0.9, 0.1])
    }
    df_ddos = pd.DataFrame(ddos_data)
    
    # 3. Port Scan (High connection count, small packet size, short duration)
    n_scan = n_anomaly // 3
    scan_data = {
        'packet_size': np.random.normal(40, 5, n_scan).clip(40, 80),
        'duration': np.random.uniform(0.001, 0.01, n_scan),
        'connection_count': np.random.normal(300, 50, n_scan).clip(100, 600),
        'protocol_encoded': [1] * n_scan # TCP
    }
    df_scan = pd.DataFrame(scan_data)
    
    # 4. Data Exfiltration (Huge packet size, long connection, low frequency)
    n_exfil = n_anomaly - n_ddos - n_scan
    exfil_data = {
        'packet_size': np.random.normal(5000000, 1000000, n_exfil).clip(1000000, 20000000),
        'duration': np.random.normal(300, 80, n_exfil).clip(60, 1200),
        'connection_count': np.random.poisson(1, n_exfil).clip(1, 2),
        'protocol_encoded': [1] * n_exfil # TCP
    }
    df_exfil = pd.DataFrame(exfil_data)
    
    # Merge and Shuffle
    df = pd.concat([df_normal, df_ddos, df_scan, df_exfil], ignore_index=True)
    df = df.sample(frac=1.0).reset_index(drop=True)
    return df

def train_and_save_model():
    """Trains the Isolation Forest model and saves it to disk."""
    print("Generating synthetic network traffic data...")
    df = generate_synthetic_data(n_samples=5000)
    
    feature_cols = ['packet_size', 'duration', 'connection_count', 'protocol_encoded']
    X = df[feature_cols].values
    
    print("Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print("Training Isolation Forest (Expected anomaly rate: 10%)...")
    model = IsolationForest(n_estimators=150, contamination=0.10, random_state=42, n_jobs=-1)
    model.fit(X_scaled)
    
    # Make sure target directory exists
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    models_dir = os.path.join(project_root, "models")
    os.makedirs(models_dir, exist_ok=True)
    
    model_path = os.path.join(models_dir, "isolation_forest.pkl")
    
    print(f"Saving trained model pipeline to: {model_path}")
    pipeline = {
        'scaler': scaler,
        'model': model,
        'feature_names': feature_cols
    }
    joblib.dump(pipeline, model_path)
    print("Model training completed successfully!")

if __name__ == "__main__":
    train_and_save_model()
