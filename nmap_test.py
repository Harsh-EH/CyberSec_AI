import os
import subprocess
import time
import logging
import re
import sys
import ctypes
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
import numpy as np
import pandas as pd
import scapy.all as scapy
import psutil  # For CPU and memory usage
from collections import defaultdict

# Check admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        logger.warning("[WARNING] Script is not running with admin privileges. Attempting to elevate...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

# Define output directory
OUTPUT_DIR = r"Outputs"
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(os.path.join(OUTPUT_DIR, "tools.log")), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Load the trained threat detection model
model_path = r"models\network_monitor_model.h5"
try:
    threat_model = tf.keras.models.load_model(model_path)
    logger.info(f"[INFO] Loaded threat detection model from {model_path}")
except Exception as e:
    logger.error(f"[ERROR] Failed to load threat detection model: {e}")
    threat_model = None

# Define feature columns used during training
TRAINING_FEATURES = [
    "Src Port", "Dst Port", "Idle Max", "Idle Min",
    "Traffic Type_TCP", "Traffic Type_UDP", "Traffic Type_Unknown"
]

# Sequence length for the model (number of packets to process at once)
SEQUENCE_LENGTH = 78  # Adjusted to produce 1152 features after flattening for the Dense layer

def check_tools():
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, check=True, shell=True)
        logger.info("[INFO] tshark is available.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.error(f"[ERROR] tshark not found or inaccessible: {e}")
        exit(1)

    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True, shell=True)
        logger.info("[INFO] nmap is available.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.error(f"[ERROR] nmap not found or inaccessible: {e}")
        exit(1)

def list_interfaces():
    try:
        result = subprocess.run(["tshark", "-D"], capture_output=True, text=True, check=True, shell=True)
        interfaces = [line.strip().split(".", 1)[1].strip() for line in result.stdout.splitlines()]
        if not interfaces:
            raise ValueError("No interfaces found")
        return interfaces
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError) as e:
        logger.error(f"[ERROR] Failed to list interfaces: {e}")
        return []

def get_user_input_subnet():
    while True:
        subnet = input("Enter the subnet to scan (e.g., 192.168.112.0/21): ").strip()
        if not subnet:
            print("Subnet cannot be empty. Please enter a valid subnet.")
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", subnet):
            logger.info(f"[INFO] Using subnet: {subnet}")
            return subnet
        else:
            logger.error(f"[ERROR] Invalid subnet format: {subnet}. Please use format like 192.168.112.0/21.")
            print("Invalid subnet format. Please use format like 192.168.112.0/21.")

def get_user_input_interface():
    interfaces = list_interfaces()
    if not interfaces:
        logger.error("[ERROR] No interfaces available. Exiting.")
        exit(1)
    
    print("\nAvailable network interfaces:")
    for i, iface in enumerate(interfaces, 1):
        print(f"{i}. {iface}")
    
    while True:
        try:
            choice = int(input("\nEnter the number of the interface to use (e.g., 1): "))
            if 1 <= choice <= len(interfaces):
                selected_interface = interfaces[choice - 1].split("(")[1].split(")")[0]
                logger.info(f"[INFO] Selected interface: {selected_interface}")
                return selected_interface
            else:
                print(f"Please enter a number between 1 and {len(interfaces)}.")
        except ValueError:
            print("Please enter a valid number.")

def scan_devices(subnet):
    try:
        output_file = os.path.join(OUTPUT_DIR, f"devices_{int(time.time())}.txt")
        command = ["nmap", "-sn", subnet, "-oN", output_file]
        logger.info(f"[INFO] Running nmap scan on subnet: {subnet}")
        
        # Run nmap command and capture output for parsing
        result = subprocess.run(command, check=True, shell=True, capture_output=True, text=True)
        
        # Parse the nmap output to extract only active IPs
        active_ips = []
        lines = result.stdout.splitlines()
        for line in lines:
            if "Nmap scan report for" in line:
                ip = line.split()[-1]
                # Ensure it's a valid IP (not a hostname)
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    active_ips.append(ip)
        
        # Display only the active IPs in the terminal
        print("\nActive IPs:")
        for ip in active_ips:
            print(ip)
        print(f"\nTotal active hosts: {len(active_ips)}")

        logger.info(f"[INFO] nmap scan results saved to {output_file}")

        # Parse the saved file for devices (ensure file is closed after reading)
        devices = []
        with open(output_file, "r") as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                if "Nmap scan report" in line:
                    ip = line.split()[4] if len(line.split()) > 4 else "N/A"
                    mac_line = next((l for l in lines[i:] if "MAC Address" in l), None)
                    hostname_line = next((l for l in lines[i:] if "(" in l and ")" in l), None)
                    mac = mac_line.split("MAC Address:")[1].split()[0] if mac_line else "N/A"
                    hostname = hostname_line.split()[3] if hostname_line and "(" in hostname_line and ")" in hostname_line else "Unknown"
                    devices.append({"ip": ip, "mac": mac, "hostname": hostname, "username": "Unknown"})
        logger.debug(f"[DEBUG] Parsed devices: {devices}")
        return devices
    except subprocess.CalledProcessError as e:
        logger.error(f"[ERROR] nmap scan failed: {e}")
        return []
    except Exception as e:
        logger.error(f"[ERROR] Device parsing failed: {e}")
        return []

def convert_bytes_to_readable(size_bytes):
    """
    Convert bytes to a readable format (KB, MB, GB, TB).
    Args:
        size_bytes: Size in bytes
    Returns:
        String representing size in KB, MB, GB, or TB
    """
    if size_bytes < 1024:  # Less than 1 KB
        return f"{size_bytes:.2f} bytes"
    elif size_bytes < 1024**2:  # Less than 1 MB
        return f"{size_bytes / 1024:.4f} KB"
    elif size_bytes < 1024**3:  # Less than 1 GB
        return f"{size_bytes / (1024**2):.4f} MB"
    elif size_bytes < 1024**4:  # Less than 1 TB
        return f"{size_bytes / (1024**3):.4f} GB"
    else:
        return f"{size_bytes / (1024**4):.4f} TB"

def preprocess_packet_sequence(packets):
    try:
        # Extract features for each packet in the sequence
        features_list = []
        timestamps = [pkt.time for pkt in packets]  # Get packet timestamps
        
        # Calculate idle times between consecutive packets
        idle_times = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        idle_max = max(idle_times) if idle_times else 0.0
        idle_min = min(idle_times) if idle_times else 0.0

        for packet in packets:
            src_port = float(packet.sport) if hasattr(packet, "sport") else 0.0
            dst_port = float(packet.dport) if hasattr(packet, "dport") else 0.0
            features = {
                "Src Port": src_port,
                "Dst Port": dst_port,
                "Idle Max": idle_max,
                "Idle Min": idle_min
            }
            protocol = "TCP" if packet.haslayer(scapy.TCP) else "UDP" if packet.haslayer(scapy.UDP) else "Unknown"
            for col in TRAINING_FEATURES:
                if col.startswith("Traffic Type_"):
                    features[col] = 1.0 if col == f"Traffic Type_{protocol}" else 0.0
                elif col not in features:
                    features[col] = 0.0
            features_list.append([features[col] for col in TRAINING_FEATURES])
        
        # Convert to DataFrame and scale
        df_packets = pd.DataFrame(features_list, columns=TRAINING_FEATURES)
        scaler = StandardScaler()
        packets_scaled = scaler.fit_transform(df_packets)
        
        # Sum the features into a single value per packet
        packets_summed = np.sum(packets_scaled, axis=1, keepdims=True)  # Shape: (sequence_length, 1)
        
        # Ensure the sequence length matches SEQUENCE_LENGTH
        current_length = packets_summed.shape[0]
        if current_length < SEQUENCE_LENGTH:
            # Pad with zeros
            padding = np.zeros((SEQUENCE_LENGTH - current_length, 1))
            packets_summed = np.vstack((packets_summed, padding))
        elif current_length > SEQUENCE_LENGTH:
            # Truncate to SEQUENCE_LENGTH
            packets_summed = packets_summed[:SEQUENCE_LENGTH]
        
        packet_reshaped = packets_summed.reshape((1, SEQUENCE_LENGTH, 1))  # Shape: (1, SEQUENCE_LENGTH, 1)
        return packet_reshaped
    except Exception as e:
        logger.error(f"[ERROR] Failed to preprocess packet sequence: {e}")
        return None

def calculate_network_usage(packets, duration):
    """
    Calculate network usage in bytes per second.
    Args:
        packets: List of captured packets
        duration: Duration of capture in seconds
    Returns:
        Network usage in bytes per second
    """
    total_bytes = sum(len(packet) for packet in packets)
    if duration == 0:
        return 0
    network_usage = total_bytes / duration  # Bytes per second
    return network_usage

def calculate_traffic_data_size(packets):
    """
    Calculate the total data size of packets in bytes.
    Args:
        packets: List of captured packets
    Returns:
        Total data size in bytes
    """
    total_size = sum(len(packet) for packet in packets)
    return total_size

def get_system_usage():
    """
    Get CPU and memory usage percentages.
    Returns:
        Tuple of (cpu_usage_percent, memory_usage_percent)
    """
    try:
        # CPU usage
        cpu_usage = psutil.cpu_percent(interval=1)
        
        # Memory usage
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        memory_usage = (memory_info.rss / psutil.virtual_memory().total) * 100  # Percentage of total memory
        
        return cpu_usage, memory_usage
    except Exception as e:
        logger.error(f"[ERROR] Failed to get system usage: {e}")
        return 0, 0

def analyze_traffic(capture_file, active_ips):
    if not threat_model:
        logger.warning("[WARNING] Threat model not loaded. Skipping analysis.")
        return
    
    try:
        packets = scapy.rdpcap(capture_file)
        ip_packets = [pkt for pkt in packets if pkt.haslayer(scapy.IP)]
        logger.info(f"[INFO] Captured {len(ip_packets)} IP packets in {capture_file}")

        if not ip_packets:
            logger.warning(f"[WARNING] No IP packets found in {capture_file}")
            return

        # Sort all captured packets by timestamp
        ip_packets.sort(key=lambda pkt: pkt.time)

        # Calculate total traffic data size
        total_traffic_size = calculate_traffic_data_size(ip_packets)
        logger.info(f"[INFO] Total Traffic Data Size: {convert_bytes_to_readable(total_traffic_size)} (Raw Bytes: {total_traffic_size})")

        # Calculate network usage (bytes per second over 30 seconds)
        capture_duration = 30  # Duration of capture in seconds (matches tshark -a duration:30)
        network_usage = calculate_network_usage(ip_packets, capture_duration)
        logger.info(f"[INFO] Network Usage: {network_usage:.2f} bytes/second")

        # Get CPU and memory usage
        cpu_usage, memory_usage = get_system_usage()
        logger.info(f"[INFO] CPU Usage: {cpu_usage:.2f}%")
        logger.info(f"[INFO] Memory Usage: {memory_usage:.2f}%")

        # Track active users (IPs with packets > 0), connected devices (all IPs), and warned IPs
        active_users = []
        packet_counts = defaultdict(int)
        traffic_sizes = defaultdict(int)
        connected_devices = active_ips.copy()
        warned_ips = set()  # Track IPs that trigger a warning

        # Analyze traffic for each active IP
        for ip in active_ips:
            if ip == "N/A":
                continue
            logger.info(f"[INFO] Analyzing traffic for IP {ip}")

            # Filter packets where the active IP is the source or destination
            ip_specific_packets = [pkt for pkt in ip_packets if (pkt[scapy.IP].src == ip or pkt[scapy.IP].dst == ip)]
            packet_count = len(ip_specific_packets)
            packet_counts[ip] = packet_count

            # Calculate traffic size for this IP
            traffic_size = calculate_traffic_data_size(ip_specific_packets)
            traffic_sizes[ip] = traffic_size

            logger.info(f"[INFO] Found {packet_count} packets involving IP {ip} (Traffic Size: {convert_bytes_to_readable(traffic_size)}, Raw Bytes: {traffic_size})")

            if packet_count == 0:
                logger.warning(f"[WARNING] No packets found for IP {ip}")
                continue

            # Add to active users if packet count > 0
            active_users.append(ip)

            # Process packets in sequences of SEQUENCE_LENGTH
            for i in range(0, len(ip_specific_packets), SEQUENCE_LENGTH):
                pkt_sequence = ip_specific_packets[i:i + SEQUENCE_LENGTH]
                if len(pkt_sequence) == 0:
                    continue

                packet_input = preprocess_packet_sequence(pkt_sequence)
                if packet_input is not None:
                    prediction = threat_model.predict(packet_input, verbose=0)
                    predicted_class = np.argmax(prediction, axis=1)[0]
                    class_labels = ['Normal', 'Malware', 'Attack', 'Vulnerability']
                    threat_label = class_labels[predicted_class]
                    if threat_label != 'Normal':
                        warned_ips.add(ip)  # Add this IP to the set of warned IPs
                        src_ip = pkt_sequence[0][scapy.IP].src
                        dst_ip = pkt_sequence[0][scapy.IP].dst
                        logger.warning(f"[WARNING] Threat detected: {threat_label} from {src_ip} to {dst_ip} (IP under analysis: {ip}, Packets: {packet_count})")
                        print(f"ALERT: {threat_label} detected from {src_ip} to {dst_ip} (IP under analysis: {ip})")

        # Log active users and connected devices
        logger.info(f"[INFO] Number of Active Users (IPs with packets > 0): {len(active_users)}")
        logger.info(f"[INFO] Active Users: {', '.join(active_users)}")
        logger.info(f"[INFO] Total Connected Devices: {len(connected_devices)}")
        logger.info(f"[INFO] Connected Devices: {', '.join(connected_devices)}")

        # Log the number of warned IPs and the list of IPs that triggered warnings
        logger.info(f"[INFO] Number of Warned IPs: {len(warned_ips)}")
        if warned_ips:
            logger.info(f"[INFO] IPs with Detected Threats: {', '.join(sorted(warned_ips))}")
        else:
            logger.info("[INFO] IPs with Detected Threats: None")

    except Exception as e:
        logger.error(f"[ERROR] Failed to analyze traffic: {e}")

def capture_traffic(interface, active_ips):
    capture_file = os.path.join(OUTPUT_DIR, f"capture_{int(time.time())}.pcap")
    try:
        logger.info(f"[INFO] Capturing all traffic on interface {interface}...")
        # Capture all traffic without an IP filter
        command = ["tshark", "-i", interface, "-a", "duration:30", "-w", capture_file]
        process = subprocess.run(command, check=False, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if process.returncode != 0:
            logger.error(f"[ERROR] Traffic capture failed: {process.stderr.decode().strip()}")
        else:
            logger.info(f"[INFO] Traffic captured to {capture_file}")
            analyze_traffic(capture_file, [device["ip"] for device in active_ips])
    except Exception as e:
        logger.error(f"[ERROR] Unexpected error in traffic capture: {e}")

if __name__ == "__main__":
    run_as_admin()
    check_tools()
    subnet = get_user_input_subnet()
    interface = get_user_input_interface()

    while True:
        devices = scan_devices(subnet)
        if devices:
            capture_traffic(interface, devices)
        logger.info("[INFO] Monitoring cycle completed. Waiting 30 seconds...")
        time.sleep(30)