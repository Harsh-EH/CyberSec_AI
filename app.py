import eventlet
eventlet.monkey_patch()
import os
import json
import time
import scapy.all as scapy
import threading
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from sqlalchemy.sql import text
import logging
import re
import socket
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
import numpy as np
import pandas as pd
import traceback
try:
    from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
    from langchain_community.vectorstores import FAISS
    from langchain_community.embeddings import HuggingFaceEmbeddings
    from langchain_huggingface import HuggingFacePipeline
    from langchain.chains import RetrievalQA
    import torch
except ImportError as e:
    logger.error(f"[ERROR] Failed to import RAG dependencies: {e}\n{traceback.format_exc()}")
    raise

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Verify PyTorch installation at startup
try:
    x = torch.rand(5, 3)
    logger.info(f"[INFO] PyTorch installed correctly. Random tensor:\n{x}")
    cuda_available = torch.cuda.is_available()
    logger.info(f"[INFO] CUDA available: {cuda_available}")
except Exception as e:
    logger.error(f"[ERROR] PyTorch verification failed: {e}\n{traceback.format_exc()}")
    raise

# Flask app setup
app = Flask(__name__)
CORS(app, resources={
    r"/devices": {"origins": ["http://localhost:5500", "http://127.0.0.1:5500"]},
    r"/packets/*": {"origins": ["http://localhost:5500", "http://127.0.0.1:5500"]},
    r"/scan": {"origins": ["http://localhost:5500", "http://127.0.0.1:5500"]},
    r"/insights": {"origins": ["http://localhost:5500", "http://127.0.0.1:5500"]}
}, supports_credentials=True)
app.config["SECRET_KEY"] = os.urandom(16)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///C:/Users/harsh/OneDrive/Desktop/CyberSec_AI/backend/network.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet", ping_timeout=1200, ping_interval=180, logger=True, engineio_logger=True)

# Database models
class DeviceLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), nullable=False, unique=True)
    hostname = db.Column(db.String(100), default="Unknown")
    mac = db.Column(db.String(50), nullable=True)
    username = db.Column(db.String(100), default="Unknown")

class PacketLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(50), nullable=False)
    protocol = db.Column(db.String(50), nullable=False)
    src_port = db.Column(db.String(10), nullable=True)
    dest_port = db.Column(db.String(10), nullable=True)
    length = db.Column(db.Integer, nullable=False)
    details = db.Column(db.String(500), nullable=True)

# Global variables
scanned_devices = []
is_scanning = False
OUTPUT_DIR = r"C:\\Users\\harsh\\OneDrive\\Desktop\\CyberSec_AI\\backend\\Outputs"

# Load the trained threat detection model
model_path = "C:/Users/harsh/OneDrive/Desktop/CyberSec_AI/backend/models/network_monitor_model.h5"
try:
    threat_model = tf.keras.models.load_model(model_path)
    logger.info(f"[INFO] Loaded threat detection model from {model_path}")
except Exception as e:
    logger.error(f"[ERROR] Failed to load threat detection model: {e}")
    threat_model = None

# Define feature columns used during training (adjust based on 2.py)
TRAINING_FEATURES = [
    "Src Port", "Dst Port", "Idle Max", "Idle Min",
    "Traffic Type_TCP", "Traffic Type_UDP", "Traffic Type_Unknown"
]

def get_latest_devices():
    try:
        device_files = [f for f in os.listdir(OUTPUT_DIR) if f.startswith("devices_") and f.endswith(".txt")]
        if not device_files:
            return []
        latest_file = max(device_files, key=lambda x: os.path.getctime(os.path.join(OUTPUT_DIR, x)))
        devices = []
        with open(os.path.join(OUTPUT_DIR, latest_file), "r") as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                if "Nmap scan report" in line:
                    ip = line.split()[-1].strip("()") if "(" in line else line.split()[-1]
                    mac_line = next((l for l in lines[i:] if "MAC Address" in l), None)
                    hostname = line.split()[-2] if "(" in line else "Unknown"
                    mac = mac_line.split("MAC Address:")[1].split()[0] if mac_line else "N/A"
                    devices.append({"ip": ip, "mac": mac, "hostname": hostname, "username": "Unknown"})
            logger.debug(f"[DEBUG] Parsed devices from {latest_file}: {devices}")
        return devices
    except Exception as e:
        logger.error(f"[ERROR] Failed to load devices: {e}")
        return []

def parse_pcap_file(pcap_file):
    try:
        packets = scapy.rdpcap(pcap_file)
        packet_logs = []
        for pkt in packets:
            if pkt.haslayer(scapy.IP):
                ips = [pkt[scapy.IP].src, pkt[scapy.IP].dst]
                for ip in ips:
                    if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                        protocol = "TCP" if pkt[scapy.IP].proto == 6 else "UDP" if pkt[scapy.IP].proto == 17 else "Unknown"
                        details = "N/A"
                        if pkt.haslayer(scapy.Raw):
                            details = str(pkt[scapy.Raw].load)[:500] if pkt[scapy.Raw].load else "No payload"
                        packet_logs.append({
                            "timestamp": str(pkt.time),
                            "ip": ip,
                            "protocol": protocol,
                            "src_port": str(pkt.sport) if hasattr(pkt, "sport") else "N/A",
                            "dest_port": str(pkt.dport) if hasattr(pkt, "dport") else "N/A",
                            "length": len(pkt),
                            "details": details
                        })
        return packet_logs
    except Exception as e:
        logger.error(f"[ERROR] Failed to parse PCAP file: {e}")
        return []

def get_latest_packets():
    try:
        pcap_files = [f for f in os.listdir(OUTPUT_DIR) if f.startswith("capture_") and f.endswith(".pcap")]
        if not pcap_files:
            return []
        latest_file = max(pcap_files, key=lambda x: os.path.getctime(os.path.join(OUTPUT_DIR, x)))
        packets = parse_pcap_file(os.path.join(OUTPUT_DIR, latest_file))
        return packets
    except Exception as e:
        logger.error(f"[ERROR] Failed to load packets: {e}")
        return []

def preprocess_packet_for_model(packet):
    try:
        features = {
            "Src Port": float(packet["src_port"]) if packet["src_port"] != "N/A" else 0.0,
            "Dst Port": float(packet["dest_port"]) if packet["dest_port"] != "N/A" else 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0
        }
        protocol = packet["protocol"]
        for col in TRAINING_FEATURES:
            if col.startswith("Traffic Type_"):
                features[col] = 1.0 if col == f"Traffic Type_{protocol}" else 0.0
            elif col not in features:
                features[col] = 0.0
        
        df_packet = pd.DataFrame([features])
        df_packet = df_packet.reindex(columns=TRAINING_FEATURES, fill_value=0.0)
        scaler = StandardScaler()
        packet_scaled = scaler.fit_transform(df_packet)
        packet_reshaped = packet_scaled.reshape((1, packet_scaled.shape[1], 1))
        return packet_reshaped
    except Exception as e:
        logger.error(f"[ERROR] Failed to preprocess packet: {e}")
        return None

def get_ai_insights(devices, packets):
    try:
        # Load GPT-2 model (ungated, no authentication needed)
        model_name = "gpt2"
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForCausalLM.from_pretrained(model_name)
        pipe = pipeline("text-generation", model=model, tokenizer=tokenizer, max_new_tokens=200)
        
        # Load embeddings for retrieval
        embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
        
        # Load or create FAISS vector store
        try:
            vector_store = FAISS.load_local("network_knowledge", embeddings)
        except:
            documents = [
                "High UDP traffic on a device may indicate a DDoS attack.",
                "Open port 445 on a device suggests SMB vulnerability risk.",
                "Unusual TCP traffic may indicate a compromised device.",
                "Multiple unknown devices could suggest an intrusion.",
                "High packet rates may indicate network congestion or attack."
            ]
            vector_store = FAISS.from_texts(documents, embeddings)
            vector_store.save_local("C:/Users/harsh/OneDrive/Desktop/CyberSec_AI/backend/network_knowledge")

        # Set up retriever
        retriever = vector_store.as_retriever(search_kwargs={"k": 3})

        # RAG chain
        qa_chain = RetrievalQA.from_chain_type(
            llm=HuggingFacePipeline(pipeline=pipe),
            chain_type="stuff",
            retriever=retriever,
            return_source_documents=False
        )

        # Analyze packets with your TensorFlow model
        threat_insights = []
        if threat_model:
            for packet in packets[:10]:
                packet_input = preprocess_packet_for_model(packet)
                if packet_input is not None:
                    prediction = threat_model.predict(packet_input, verbose=0)
                    predicted_class = np.argmax(prediction, axis=1)[0]
                    class_labels = ['Normal', 'Malware', 'Attack', 'Vulnerability']
                    threat_label = class_labels[predicted_class]
                    if threat_label != 'Normal':
                        threat_insights.append(f"Threat detected: {threat_label} at {packet['ip']} (Protocol: {packet['protocol']})")
        
        # Prepare prompt
        device_count = len(devices)
        packet_count = len(packets)
        threat_summary = "\n".join(threat_insights) if threat_insights else "No threats detected."
        prompt = (
            f"Given the following network activity data: {device_count} devices, {packet_count} packets.\n"
            f"TensorFlow model insights: {threat_summary}\n"
            "Using the provided context, generate a concise summary (max 200 words) of the network activity and any potential security concerns. "
            "Focus only on the analysis and avoid including tutorials or unrelated content."
        )
        logger.debug(f"[DEBUG] RAG prompt: {prompt}")

        # Generate response with RAG
        rag_response = qa_chain.invoke({"query": prompt})["result"]
        logger.debug(f"[DEBUG] Raw RAG response: {rag_response}")

        # Extract only the summary
        summary_start = rag_response.find("Question:") + len("Question:") if "Question:" in rag_response else 0
        summary = rag_response[summary_start:].split("\n\n", 1)[-1].strip() if summary_start else rag_response.strip()
        
        # Ensure relevance and brevity
        if "Tutorial" in summary or "tutorial" in summary or len(summary) > 400:
            summary = f"Analyzed {device_count} devices and {packet_count} packets. {threat_summary.replace('\n', ' ')} Network appears {'inactive' if device_count == 0 else 'active'}."
        return summary
    except Exception as e:
        logger.error(f"[ERROR] Failed to generate AI insights: {e}\n{traceback.format_exc()}")
        return f"Error generating AI insights: {str(e)}"

def emit_packets(ip):
    with app.app_context():
        try:
            packets = PacketLog.query.filter_by(ip=ip).order_by(PacketLog.timestamp.desc()).limit(50).all()
            packet_data = [
                {
                    "id": p.id,
                    "timestamp": p.timestamp,
                    "ip": p.ip,
                    "protocol": p.protocol,
                    "src_port": p.src_port,
                    "dest_port": p.dest_port,
                    "length": p.length,
                    "details": p.details
                } for p in packets
            ]
            socketio.emit("packet_data", {"ip": ip, "packets": packet_data})
            logger.debug(f"[DEBUG] Emitted packet data for IP {ip}")
        except Exception as e:
            logger.error(f"[ERROR] Failed to emit packets for IP {ip}: {e}")

def update_database():
    global scanned_devices
    devices = get_latest_devices()
    packets = get_latest_packets()
    
    with app.app_context():
        try:
            for device in devices:
                existing_device = DeviceLog.query.filter_by(ip=device["ip"]).first()
                if not existing_device:
                    db.session.add(DeviceLog(ip=device["ip"], mac=device["mac"], hostname=device["hostname"], username=device["username"]))
                else:
                    existing_device.mac = device["mac"]
                    existing_device.hostname = device["hostname"]
                    existing_device.username = device["username"]
            
            for packet in packets:
                existing_packet = PacketLog.query.filter_by(timestamp=packet["timestamp"], ip=packet["ip"], protocol=packet["protocol"]).first()
                if not existing_packet:
                    db.session.add(PacketLog(**packet))
            
            db.session.commit()
            scanned_devices = devices
            logger.info("[INFO] Database updated with latest tool outputs")
            
            for device in devices:
                emit_packets(device["ip"])
            
            if time.time() % 600 == 0:
                insights = get_ai_insights(devices, packets)
                socketio.emit("ai_insights", {"insights": insights})
                logger.debug(f"[DEBUG] Emitted AI insights: {insights[:100]}...")
        except Exception as e:
            logger.error(f"[ERROR] Failed to update database: {e}")
            db.session.rollback()

def security_monitor():
    while True:
        update_database()
        time.sleep(30)

@socketio.on("connect")
def handle_connect(auth=None):
    logger.info(f"[INFO] WebSocket client connected from IP: {request.remote_addr}, SID: {request.sid}, Auth: {auth}")
    socketio.emit("connected", {"message": "WebSocket connected successfully"})

@socketio.on("disconnect")
def handle_disconnect():
    logger.warning(f"[WARNING] WebSocket client disconnected, SID: {request.sid}")

@socketio.on("connect_error")
def handle_connect_error(error):
    logger.error(f"[ERROR] WebSocket connect error: {error}, SID: {request.sid if hasattr(request, 'sid') else 'Unknown'}")

@socketio.on("packet_data")
def handle_packet_data(data):
    if data and "ip" in data and "packets" in data:
        logger.debug(f"[DEBUG] Received packet data for IP {data['ip']}: {data['packets']}")

@socketio.on("ai_insights")
def handle_ai_insights(data):
    if data and "insights" in data:
        logger.debug(f"[DEBUG] Received AI insights: {data['insights'][:100]}...")

@app.route("/devices")
def get_devices():
    logger.info("[INFO] API request received for /devices")
    return jsonify({"devices": scanned_devices if not is_scanning else [], "status": "Scanning..." if is_scanning else "Idle"})

@app.route("/packets/<ip>")
def get_packets(ip):
    with app.app_context():
        try:
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                logger.error(f"[ERROR] Invalid IP format: {ip}")
                return jsonify({"error": "Invalid IP address format"}), 400
            
            packets = PacketLog.query.filter_by(ip=ip).order_by(PacketLog.timestamp.desc()).limit(50).all()
            if not packets:
                logger.debug(f"[DEBUG] No packets found for IP {ip}")
                return jsonify([]), 200
            return jsonify([
                {
                    "id": p.id,
                    "timestamp": p.timestamp,
                    "ip": p.ip,
                    "protocol": p.protocol,
                    "src_port": p.src_port,
                    "dest_port": p.dest_port,
                    "length": p.length,
                    "details": p.details
                } for p in packets
            ])
        except Exception as e:
            logger.error(f"[ERROR] Failed to fetch packets for IP {ip}: {e}")
            return jsonify({"error": "Internal server error"}), 500

@app.route("/scan", methods=["POST"])
def trigger_scan():
    logger.info("[INFO] API request received for /scan")
    global is_scanning
    if is_scanning:
        return jsonify({"status": "Scan already in progress"}), 429
    is_scanning = True
    threading.Thread(target=update_database, daemon=True).start()
    is_scanning = False
    return jsonify({"status": "Scan completed (simulated)"}), 200

@app.route("/insights", methods=["GET"])
def get_insights():
    logger.info("[INFO] API request received for /insights")
    devices = get_latest_devices()
    packets = get_latest_packets()
    insights = get_ai_insights(devices, packets)
    return jsonify({"insights": insights})

if __name__ == "__main__":
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', 5000))
        sock.close()

        with app.app_context():
            try:
                db.create_all()
                logger.info("[INFO] Database initialized.")
                result = db.session.execute(text("PRAGMA table_info(packet_log)")).fetchall()
                columns = [row[1] for row in result]
                if "details" not in columns:
                    logger.warning("[WARNING] 'details' column missing in packet_log. Attempting to add it...")
                    db.session.execute(text("ALTER TABLE packet_log ADD COLUMN details TEXT"))
                    db.session.commit()
                    logger.info("[INFO] Successfully added 'details' column to packet_log.")
                logger.debug(f"[DEBUG] Database schema verified: {columns}")
            except Exception as e:
                logger.error(f"[ERROR] Failed to initialize or verify database: {e}")
                exit(1)
        
        threading.Thread(target=security_monitor, daemon=True).start()
        logger.info(f"[INFO] Starting server on http://0.0.0.0:5000...")
        socketio.run(app, host="0.0.0.0", port=5000, use_reloader=False, debug=True)
    except KeyboardInterrupt:
        logger.info("[INFO] Server stopped by user (Ctrl+C)")
    except Exception as e:
        logger.error(f"[ERROR] Unhandled exception in main: {e}\n{traceback.format_exc()}")
        exit(1)