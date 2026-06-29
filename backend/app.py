import os
import time
import random
import datetime
import logging
import threading
from flask import Flask, jsonify, request, send_from_directory, session, redirect, url_for
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from dotenv import load_dotenv
from groq import Groq

# Load environment variables
load_dotenv()

# Initialize Groq client
groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))

from database import init_db, increment_stats, save_alert, get_recent_alerts, get_stats, clear_logs, create_user, get_user_by_username, SQLITE_PATH
from detector import load_detector, analyze_packet

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__, static_folder="../frontend")
app.secret_key = os.environ.get("SECRET_KEY", "netsentinel_secret_cyber_key_2026")
CORS(app)

simulation_active = True
triggered_attack = None  # Buffer for manual attacks
recent_packets = []      # Memory ring buffer for live evaluation stream
recent_packets_lock = threading.Lock()

def run_simulator():
    """Background simulator thread generating normal traffic and attacks every 2 seconds."""
    global simulation_active, triggered_attack
    
    internal_ips = [
        "10.0.0.10",  # Web-01
        "10.0.0.11",  # Web-02
        "10.0.0.20",  # DB-Server
        "10.0.0.30",  # DC-01
        "10.0.1.50",  # Workstation-A
        "10.0.1.51"   # Workstation-B
    ]
    
    while True:
        # Loop exactly every 2 seconds as requested
        time.sleep(2.0)
        
        if not simulation_active and triggered_attack is None:
            continue
            
        # Determine if we should generate an attack
        is_attack = False
        attack_type = None
        
        if triggered_attack:
            is_attack = True
            attack_type = triggered_attack
            triggered_attack = None
            logging.info(f"Simulator executing manual attack: {attack_type}")
        else:
            # 8% chance of standard random threat packet injection
            if random.random() < 0.08:
                is_attack = True
                attack_type = random.choice(["ddos", "scan", "exfil"])
                
        # Generate packet parameters
        if is_attack:
            # Malicious external IP
            src = f"{random.choice([185, 45, 91, 103, 194])}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(1,254)}"
            
            if attack_type == "ddos":
                dest = random.choice(["10.0.0.10", "10.0.0.11"]) # Web Servers
                protocol = random.choice(["TCP", "UDP"])
                packet_size = random.randint(40, 90)
                connection_count = random.randint(700, 1600)
                duration = round(random.uniform(0.001, 0.04), 4)
                src_port = random.randint(49152, 65535)
                dest_port = random.choice([80, 443])
            elif attack_type == "scan":
                dest = random.choice(["10.0.0.30", "10.0.0.20"]) # DC or DB
                protocol = "TCP"
                packet_size = random.randint(40, 70)
                connection_count = random.randint(250, 500)
                duration = round(random.uniform(0.001, 0.01), 4)
                src_port = random.randint(1024, 65535)
                dest_port = random.randint(1, 1024)
            else: # exfil
                # Compromised node exfiltrating to external server
                src = random.choice(["10.0.0.20", "10.0.0.30"])
                dest = f"{random.choice([198, 52, 23, 8])}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(1,254)}"
                protocol = "TCP"
                packet_size = random.randint(2500000, 9500000) # 2.5MB - 9.5MB
                connection_count = random.randint(1, 2)
                duration = round(random.uniform(90.0, 450.0), 2)
                src_port = random.randint(49152, 65535)
                dest_port = 443
        else:
            # Generate normal network traffic
            flow_type = random.choice(["internal", "ingress", "egress"])
            if flow_type == "internal":
                src = random.choice(["10.0.1.50", "10.0.1.51"]) # Workstations
                dest = random.choice(["10.0.0.20", "10.0.0.10", "10.0.0.30"]) # DB, Web, DC
                protocol = "TCP"
                src_port = random.randint(49152, 65535)
                dest_port = random.choice([80, 443, 8080, 1433, 3306])
            elif flow_type == "ingress":
                src = f"{random.randint(12, 172)}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(1,254)}"
                dest = random.choice(["10.0.0.10", "10.0.0.11"])
                protocol = random.choice(["TCP", "UDP"])
                src_port = random.randint(1024, 65535)
                dest_port = random.choice([80, 443])
            else: # egress
                src = random.choice(internal_ips)
                dest = f"{random.randint(8, 220)}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(1,254)}"
                protocol = "TCP"
                src_port = random.randint(49152, 65535)
                dest_port = random.choice([80, 443])
                
            packet_size = random.randint(64, 1450)
            connection_count = random.randint(1, 15)
            # Use standard random.expovariate for connection durations
            duration = round(random.expovariate(1.0 / 0.25), 4)
            if duration < 0.001:
                duration = 0.001
            src_port = random.randint(1024, 65535)
            dest_port = random.choice([80, 443, 53])
            
        packet = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src,
            "dest_ip": dest,
            "protocol": protocol,
            "packet_size": packet_size,
            "connection_count": connection_count,
            "conn_freq": connection_count, # compatibility key
            "duration": duration,
            "src_port": src_port,
            "dest_port": dest_port
        }
        
        # Analyze using machine learning model (detector is updated to 4-feature logic)
        analysis = analyze_packet(packet)
        packet.update(analysis)
        
        # Save results to DB
        is_threat = packet["threat_level"] in ["Suspicious", "High-Risk"]
        increment_stats(is_threat=is_threat)
        if is_threat:
            save_alert(packet)
            
        # Append to recent packets buffer for the live UI stream
        with recent_packets_lock:
            recent_packets.append(packet)
            if len(recent_packets) > 20:
                recent_packets.pop(0)
                
        logging.info(f"Simulated: {src} -> {dest} [{protocol}] | Score: {packet['threat_score']}% | Pred: {packet['prediction']}")

@app.before_request
def check_auth():
    # If the user is logged in, let them access anything
    if 'user_id' in session:
        return None
        
    # Unauthenticated user access check
    # Allow authentication endpoints
    if request.endpoint in ['login', 'signup', 'logout']:
        return None
        
    # Allow static assets except index.html
    if request.endpoint == 'serve_static':
        path = request.view_args.get('path', '')
        if path not in ['index.html', '']:
            return None
            
    # For any other resource:
    # If it is an API call, return 401 Unauthorized
    if request.path.startswith('/api/'):
        return jsonify({"error": "Unauthorized"}), 401
        
    # Otherwise, redirect to login page
    return redirect(url_for('login'))

# --- Authentication Endpoints ---

@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Handles user registration."""
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
            username = data.get("username", "").strip()
            email = data.get("email", "").strip()
            password = data.get("password", "")
        else:
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            
        if not username or not email or not password:
            return jsonify({"error": "All fields are required"}), 400
            
        # Check if username or email already exists
        if get_user_by_username(username):
            return jsonify({"error": "Username already exists"}), 400
            
        conn = sqlite3.connect(SQLITE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return jsonify({"error": "Email already registered"}), 400
            
        # Create user
        password_hash = generate_password_hash(password)
        success = create_user(username, email, password_hash)
        if success:
            return jsonify({"success": True, "redirect": url_for("login")})
        else:
            return jsonify({"error": "Registration failed"}), 500
            
    return send_from_directory(app.static_folder, "signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles user login."""
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
            username = data.get("username", "").strip()
            password = data.get("password", "")
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
            
        user = get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return jsonify({"success": True, "redirect": url_for("index")})
        else:
            return jsonify({"error": "Invalid username or password"}), 401
            
    return send_from_directory(app.static_folder, "login.html")

@app.route("/logout")
def logout():
    """Logs out the current user and clears session."""
    session.clear()
    return redirect(url_for("login"))

# --- API Endpoints ---

@app.route("/")
def index():
    """Serves the dashboard index HTML."""
    return send_from_directory(app.static_folder, "index.html")

@app.route("/<path:path>")
def serve_static(path):
    """Serves other static files (style.css, script.js, libraries)."""
    return send_from_directory(app.static_folder, path)

@app.route("/api/status", methods=["GET"])
def get_dashboard_status():
    """Gets aggregate traffic metrics."""
    stats = get_stats()
    # Format according to user schema:
    # { total_packets, normal_packets, threats_detected, risk_percentage }
    response = {
        "total_packets": stats.get("total_packets", 0),
        "normal_packets": stats.get("normal_packets", 0),
        "threats_detected": stats.get("threats_detected", 0),
        "threat_packets": stats.get("threats_detected", 0), # compat key
        "risk_percentage": stats.get("risk_percentage", 0.0),
        "status": "Active" if simulation_active else "Paused",
        "simulation_active": simulation_active
    }
    return jsonify(response)

@app.route("/api/threats", methods=["GET"])
def get_threats():
    """Gets recent threat logs."""
    limit = request.args.get("limit", default=50, type=int)
    alerts = get_recent_alerts(limit=limit)
    return jsonify(alerts)

@app.route("/api/traffic", methods=["GET"])
def get_traffic_feed():
    """Gets the rolling memory buffer of recent network evaluations."""
    with recent_packets_lock:
        return jsonify(list(recent_packets))

@app.route("/api/analyze", methods=["POST"])
def analyze():
    """Evaluates arbitrary packet payload submitted by API client."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing payload data"}), 400
        
    # Analyze
    analysis = analyze_packet(data)
    result = dict(data)
    result.update(analysis)
    
    # Save if suspicious/malicious
    is_threat = result["threat_level"] in ["Suspicious", "High-Risk"]
    increment_stats(is_threat=is_threat)
    if is_threat:
        result = save_alert(result)
        
    return jsonify(result)

@app.route("/api/network", methods=["GET"])
def get_network_topology():
    """Generates D3 topology nodes and edges with alert states."""
    recent = get_recent_alerts(limit=15)
    alert_ips = set()
    attacker_flows = []
    now = datetime.datetime.now()
    
    for alert in recent:
        try:
            alert_time = datetime.datetime.strptime(alert["timestamp"], "%Y-%m-%d %H:%M:%S")
            # Consider alerts in the last 20 seconds as active
            if (now - alert_time).total_seconds() < 20:
                alert_ips.add(alert["src_ip"])
                alert_ips.add(alert["dest_ip"])
                attacker_flows.append((alert["src_ip"], alert["dest_ip"]))
        except Exception:
            alert_ips.add(alert["src_ip"])
            alert_ips.add(alert["dest_ip"])
            attacker_flows.append((alert["src_ip"], alert["dest_ip"]))
            
    # Base nodes
    nodes = [
        {"id": "Gateway", "label": "External Gateway", "type": "gateway", "ip": "10.0.0.1", "status": "normal"},
        {"id": "Firewall", "label": "NetSentinel UTM", "type": "firewall", "ip": "10.0.0.2", "status": "normal"},
        {"id": "Web-01", "label": "Web Host 01", "type": "server", "ip": "10.0.0.10", "status": "normal"},
        {"id": "Web-02", "label": "Web Host 02", "type": "server", "ip": "10.0.0.11", "status": "normal"},
        {"id": "DB-Server", "label": "SQL DB Cluster", "type": "database", "ip": "10.0.0.20", "status": "normal"},
        {"id": "DC-01", "label": "Active Directory", "type": "server", "ip": "10.0.0.30", "status": "normal"},
        {"id": "Workstation-A", "label": "End User PC A", "type": "endpoint", "ip": "10.0.1.50", "status": "normal"},
        {"id": "Workstation-B", "label": "End User PC B", "type": "endpoint", "ip": "10.0.1.51", "status": "normal"}
    ]
    
    # Base edges
    edges = [
        {"source": "Gateway", "target": "Firewall"},
        {"source": "Firewall", "target": "Web-01"},
        {"source": "Firewall", "target": "Web-02"},
        {"source": "Web-01", "target": "DB-Server"},
        {"source": "Web-02", "target": "DB-Server"},
        {"source": "Firewall", "target": "DC-01"},
        {"source": "DC-01", "target": "Workstation-A"},
        {"source": "DC-01", "target": "Workstation-B"}
    ]
    
    # Attacker IPs tracking helper to avoid duplication
    added_attackers = set()
    internal_ips_list = ["10.0.0.10", "10.0.0.11", "10.0.0.20", "10.0.0.30", "10.0.1.50", "10.0.1.51", "10.0.0.2", "10.0.0.1"]
    
    # Map IP to D3 Node ID
    ip_to_id = {node["ip"]: node["id"] for node in nodes}
    
    def get_node_id_by_ip(ip_addr):
        return ip_to_id.get(ip_addr, "Gateway")
        
    for src_ip, dest_ip in attacker_flows:
        if src_ip not in internal_ips_list:
            attacker_id = f"Attacker-{src_ip}"
            if attacker_id not in added_attackers:
                nodes.append({
                    "id": attacker_id,
                    "label": f"Attacker ({src_ip})",
                    "type": "threat",
                    "ip": src_ip,
                    "status": "danger"
                })
                added_attackers.add(attacker_id)
                
                target_id = get_node_id_by_ip(dest_ip)
                edges.append({
                    "source": attacker_id,
                    "target": target_id
                })
        else:
            # Internal node exfiltrating to external server
            if dest_ip not in internal_ips_list:
                rogue_id = f"Rogue-{dest_ip}"
                if rogue_id not in added_attackers:
                    nodes.append({
                        "id": rogue_id,
                        "label": f"Rogue Server ({dest_ip})",
                        "type": "threat",
                        "ip": dest_ip,
                        "status": "danger"
                    })
                    added_attackers.add(rogue_id)
                    
                    src_id = get_node_id_by_ip(src_ip)
                    edges.append({
                        "source": src_id,
                        "target": rogue_id
                    })
                    
    # Update nodes status if targeted
    for node in nodes:
        if node["ip"] in alert_ips and node["type"] != "threat":
            node["status"] = "danger"
            
    return jsonify({
        "nodes": nodes,
        "edges": edges,
        "links": edges  # Keep links for client compatibility
    })

@app.route("/api/simulate_attack", methods=["POST"])
def simulate_attack():
    """Triggers specific simulated attack vectors."""
    global triggered_attack
    data = request.get_json()
    if not data or "type" not in data:
        return jsonify({"error": "Missing attack type"}), 400
        
    attack_type = data["type"].lower()
    if attack_type not in ["ddos", "scan", "exfil"]:
        return jsonify({"error": "Invalid attack type"}), 400
        
    triggered_attack = attack_type
    return jsonify({
        "triggered": True,
        "type": attack_type,
        "message": f"Queued {attack_type} attack for simulator execution."
    })

@app.route("/api/simulator/trigger", methods=["POST"])
def trigger_simulator_attack():
    """For compatibility with legacy scripts."""
    return simulate_attack()

@app.route("/api/simulator/toggle", methods=["POST"])
def toggle_simulator():
    """Enables or pauses the background traffic simulator."""
    global simulation_active
    simulation_active = not simulation_active
    return jsonify({
        "simulation_active": simulation_active,
        "status": "Active" if simulation_active else "Paused"
    })

@app.route("/api/clear", methods=["POST"])
def clear_db_logs():
    """Truncates log history and counters."""
    clear_logs()
    return jsonify({"success": True, "message": "Threat tables and telemetry stats reset successfully."})

if __name__ == "__main__":
    # 1. Initialize Database
    init_db()
    
    # 2. Preload/Train ML Detector
    load_detector()
    
    # 3. Start Traffic Simulation Thread
    sim_thread = threading.Thread(target=run_simulator, daemon=True)
    sim_thread.start()
    logging.info("Traffic simulator background thread started.")
    
    # 4. Launch Flask App on port 5000
    app.run(host="0.0.0.0", port=5000, debug=False)
