# NetSentinel: AI-Powered Network Intrusion & Cyber Threat Visualizer

NetSentinel is a full-stack cybersecurity application that combines machine learning (Isolation Forest anomaly detection) with real-time vector visualization. It is designed to simulate, inspect, classify, and visualize network traffic in real time.

The application features a sleek, dark-themed operations center dashboard built with Vanilla CSS and D3.js.

---

## Key Features

1. **AI Threat Detection Layer**:
   - Uses an **Isolation Forest** model trained on synthetic network profiles.
   - Evaluates: Packet Size, Connection Duration, Connection Frequency, Protocols (TCP/UDP/ICMP), and Source/Destination Ports.
   - Outputs a normalized Threat Score (0–100%) and categorizes incidents (e.g., DDoS, Port Scan, Data Exfiltration, or Zero-Day Anomalies).

2. **Interactive Topology Visualization**:
   - Uses **D3.js Force-Directed Graphs** to map system infrastructure (Gateway, Firewall, Web Servers, Database, Domain Controller, Workstations).
   - Animates packet transitions as colored particles (green/cyan for normal, glowing red for threat alerts).
   - Dynamically highlights compromised nodes in real time based on active database alerts.

3. **Multi-threaded Traffic Simulator**:
   - Injects normal background traffic flows continuously.
   - Schedules random threat vectors periodically.
   - Includes manual overrides to trigger targeted incidents (DDoS, Port Scan, Data Exfiltration) instantly from the UI.

4. **Dual Database Engine (MongoDB with SQLite Fallback)**:
   - Tries connecting to local MongoDB (`mongodb://localhost:27017/netsentinel`) on startup.
   - **Auto-fallback**: If MongoDB is not running or available, it seamlessly falls back to a local SQLite database (`netsentinel.db`) without crashing, ensuring zero-configuration execution.

---

## Project Structure

```text
NetSentinel/
│
├── backend/
│   ├── app.py              # Flask server, API endpoints, background traffic simulator
│   ├── database.py         # MongoDB connection & SQLite fallback logic
│   ├── detector.py         # Isolation Forest prediction and threat classification
│   ├── model.py            # Synthetic dataset generation & Isolation Forest trainer
│   └── requirements.txt    # Python backend package dependencies
│
├── frontend/
│   ├── index.html          # Dashboard HTML skeleton & HUD controls
│   ├── style.css           # Modern SOC dark-mode stylesheet & glow animations
│   └── script.js           # API poll controller, D3 topology renderer & particle flows
│
├── models/
│   └── isolation_forest.pkl # Serialized scikit-learn model and scaling pipeline
│
└── README.md               # Setup and project documentation (this file)
```

---

## Installation & Setup

### Prerequisites
- Python 3.8 or higher.
- MongoDB (optional, the system automatically falls back to SQLite if MongoDB is not running).

### Steps

1. **Clone or Navigate to the Directory**:
   ```bash
   cd "NetSentinel – AI Cyber Threat Visualizer"
   ```

2. **Install Python Dependencies**:
   ```bash
   pip install -r backend/requirements.txt
   ```

3. **Train the ML Model** (Already pre-trained, but can be retrained at any time):
   ```bash
   python backend/model.py
   ```

4. **Start the Flask Backend Server**:
   ```bash
   python backend/app.py
   ```
   *Note: On startup, the terminal will log whether it connected to MongoDB or fell back to SQLite.*

5. **Access the Dashboard**:
   Open your browser and navigate to:
   ```text
   http://localhost:5000
   ```
   The Flask server hosts the static frontend files directly at `/`.

---

## API Specifications

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `GET /` | `GET` | Serves the main frontend dashboard (`index.html`) |
| `GET /api/status` | `GET` | Returns aggregate metrics (Total packets, Normal packets, Threats count, Risk level) |
| `GET /api/threats` | `GET` | Returns recent threat records retrieved from the database |
| `GET /api/traffic` | `GET` | Returns the rolling sliding-window log of evaluated traffic (both normal & anomalies) |
| `GET /api/network` | `GET` | Returns topology nodes and links with active alert statuses |
| `POST /api/analyze` | `POST` | Evaluates a custom packet payload through the machine learning model |
| `POST /api/simulator/toggle` | `POST` | Pauses or resumes the background simulated traffic generator |
| `POST /api/simulator/trigger` | `POST` | Forcibly triggers an attack sequence (payload: `{"type": "ddos" \| "scan" \| "exfil"}`) |
| `POST /api/clear` | `POST` | Truncates threat logs and resets all telemetry counters |

---

## AI Layer & Feature Engineering

### Feature Schema
Each packet is converted into a 6-dimensional numeric feature vector before feeding into the Isolation Forest:
1. `packet_size` (numeric, in bytes)
2. `duration` (numeric, in seconds)
3. `conn_freq` (numeric, connections per minute from the source IP)
4. `protocol_numeric` (1 = TCP, 2 = UDP, 3 = ICMP, 4 = Other)
5. `src_port` (numeric port value)
6. `dest_port` (numeric port value)

### Anomaly Decision Mapping
The Isolation Forest returns a raw decision score `raw_score` in the range `[-0.5, 0.5]`. The raw score is mapped to a normalized threat score percentage:
- **Inlier (`raw_score >= 0`)**: `threat_score = max(5.0, 45.0 - (raw_score * 120.0))` (Range: 5% – 45%)
- **Outlier (`raw_score < 0`)**: `threat_score = min(99.9, 50.0 + (abs(raw_score) * 180.0))` (Range: 50% – 99.9%)

### Incident Categorization Rules
If the threat score exceeds **45%**, the AI layer classifies the severity (Suspicious / High-Risk) and runs heuristic checks on the feature vector to explain the threat:
- **DDoS Attack**: `conn_freq >= 500` connections/minute.
- **Port Scan**: `conn_freq > 100` and target port in lower range (`< 1024`), showing sweeping behavior.
- **Data Exfiltration**: `packet_size >= 1,000,000` bytes (1MB+) and long connection duration.
- **Zero-Day Anomaly**: A unique combination of size, duration, and ports that is out-of-distribution compared to the baseline traffic.
