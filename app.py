import os
import sys
import time
import json
import joblib
import threading
import numpy as np
import logging
import traceback
import socket
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response, send_file
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.arch import get_if_list
from tensorflow.keras.models import load_model
import psutil
import geoip2.database
import requests
import nmap
import re
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from io import BytesIO
import base64
from collections import defaultdict, deque
from math import sqrt
import numpy as np

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('app_debug.log')
    ]
)
logger = logging.getLogger('AI-IDS')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, async_mode='threading', logger=False, engineio_logger=False)

# Global detection statistics
detection_stats = {
    'total_packets': 0,
    'malicious_packets': 0,
    'attack_types': {},
    'recent_alerts': [],
    'attack_locations': [],
    'start_time': time.time(),
    'last_updated': time.time(),
    'system_stats': {},
    'status': 'initializing',
    'interfaces': [],
    'active_interface': '',
    'errors': [],
    'traffic_data': [],
    'network_devices': [],
    'threat_intel': [],
    'traffic_history': {'timestamps': [], 'normal': [], 'threat': []}
}

# Configuration
CONFIG_FILE = 'config.json'
DEFAULT_CONFIG = {
    'sensitivity': 'medium',
    'interface': 'auto',
    'sound_alerts': True,
    'desktop_notifications': True,
    'geoip_enabled': True,
    'max_alerts': 1000,
    'max_history': 100,
    'confidence_threshold': 0.75,
    'model_path': 'models/model.keras',
    'scaler_path': 'models/scaler.pkl',
    'encoder_path': 'models/label_encoder.pkl',
    'abuseipdb_key': '5303920efcff8af5daa6e27b138b1dcc180fc11d496b60c218308e8ab805d49e086a9b2bbdf2e26f',
    'threat_intel_enabled': True,
    'alert_sound': 'default',
    'max_ui_alerts': 100,
    'flow_timeout': 120  # seconds
}

# Attack severity mapping
SEVERITY_MAP = {
    'Benign': 'info',
    'Bot': 'critical',
    'DDoS': 'high',
    'DoS GoldenEye': 'high',
    'DoS Hulk': 'high',
    'DoS Slowhttptest': 'high',
    'DoS slowloris': 'high',
    'FTP-Patator': 'high',
    'Heartbleed': 'critical',
    'Infiltration': 'critical',
    'PortScan': 'medium',
    'SSH-Patator': 'high',
    'Web Attack - Brute Force': 'critical',
    'Web Attack - Sql Injection': 'critical',
    'Web Attack - XSS': 'critical'
}
last_traffic_update = time.time()
# Helper classes for flow tracking
class IncrementalStats:
    def __init__(self):
        self.count = 0
        self.total = 0.0
        self.mean = 0.0
        self.M2 = 0.0  # For variance calculation
        self.min = float('inf')
        self.max = float('-inf')
    
    def update(self, value):
        self.count += 1
        self.total += value
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.M2 += delta * delta2
        
        if value < self.min:
            self.min = value
        if value > self.max:
            self.max = value
    
    @property
    def variance(self):
        if self.count < 2:
            return 0.0
        return self.M2 / (self.count - 1)
    
    @property
    def std(self):
        return sqrt(self.variance) if self.variance > 0 else 0.0

class BulkState:
    def __init__(self):
        self.bulk_start = None
        self.bulk_size = 0
        self.bulk_packets = 0
        self.bulk_duration = 0
        self.bulk_count = 0
        self.total_bytes = 0
        self.total_packets = 0
    
    def update(self, packet_size, timestamp):
        if packet_size > 0:
            if self.bulk_start is None:
                self.bulk_start = timestamp
            self.bulk_size += packet_size
            self.bulk_packets += 1
        else:
            if self.bulk_start is not None:
                self.bulk_duration = timestamp - self.bulk_start
                self.bulk_count += 1
                self.total_bytes += self.bulk_size
                self.total_packets += self.bulk_packets
                self.bulk_start = None
                self.bulk_size = 0
                self.bulk_packets = 0
    
    @property
    def avg_bytes(self):
        if self.bulk_count > 0:
            return self.total_bytes / self.bulk_count
        return 0
    
    @property
    def avg_packets(self):
        if self.bulk_count > 0:
            return self.total_packets / self.bulk_count
        return 0
    
    @property
    def avg_rate(self):
        if self.bulk_duration > 0 and self.bulk_count > 0:
            return (self.total_bytes / self.bulk_count) / self.bulk_duration
        return 0

# Flow-based feature tracker
class FlowTracker:
    def __init__(self, flow_timeout=120):
        self.flow_timeout = flow_timeout
        self.flows = {}
        self.active_flows = {}
        self.last_cleanup = time.time()
        self.lock = threading.Lock()
        
    def get_flow_key(self, pkt):
        if not pkt.haslayer(IP):
            return None
            
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        
        # Handle protocol-specific ports
        src_port = 0
        dst_port = 0
        protocol = ip.proto
        
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
        
        # Create canonical flow key (sorted by IP and port)
        if src_ip < dst_ip or (src_ip == dst_ip and src_port <= dst_port):
            return (src_ip, src_port, dst_ip, dst_port, protocol)
        else:
            return (dst_ip, dst_port, src_ip, src_port, protocol)
    
    def update_flow(self, pkt, direction,timestamp):
        # Clean up old flows periodically
       # Clean up old flows periodically
        if timestamp - self.last_cleanup > 30:
            self.cleanup_flows(timestamp)
            self.last_cleanup = timestamp
        
        flow_key = self.get_flow_key(pkt)
        if flow_key is None:
            return None
            
        with self.lock:
            if flow_key not in self.flows:
                self.create_new_flow(flow_key, pkt, direction, timestamp)
            
            flow = self.flows[flow_key]
            # Map direction to bulk key
            bulk_key = 'fwd' if direction == 'forward' else 'bwd'
            self.update_flow_stats(flow, pkt, direction, bulk_key, timestamp)
            return flow
    
    def create_new_flow(self, flow_key, pkt, direction, timestamp):
        ip = pkt[IP]
        new_flow = {
            'start_time': timestamp,
            'last_updated': timestamp,
            'fwd_packets': 0,
            'bwd_packets': 0,
            'fwd_bytes': 0,
            'bwd_bytes': 0,
            'fwd_packet_lengths': [],
            'bwd_packet_lengths': [],
            'fwd_packet_times': [],
            'bwd_packet_times': [],
            'fwd_iat': IncrementalStats(),
            'bwd_iat': IncrementalStats(),
            'flow_iat': IncrementalStats(),
            'fwd_psh_flags': 0,
            'bwd_psh_flags': 0,
            'fwd_urg_flags': 0,
            'bwd_urg_flags': 0,
            'fwd_header_length': 0,
            'bwd_header_length': 0,
            'fin_flag': 0,
            'syn_flag': 0,
            'rst_flag': 0,
            'psh_flag': 0,
            'ack_flag': 0,
            'urg_flag': 0,
            'cwe_flag': 0,
            'ece_flag': 0,
            'fwd_init_win_bytes': -1,
            'bwd_init_win_bytes': -1,
            'active_times': [],
            'idle_times': [],
            'last_packet_time': timestamp,
            'last_fwd_time': None,
            'last_bwd_time': None,
            'bulk_states': {'fwd': BulkState(), 'bwd': BulkState()},
            'subflows': {'fwd_packets': 0, 'fwd_bytes': 0, 'bwd_packets': 0, 'bwd_bytes': 0},
            'min_win_bytes_fwd': float('inf'),
            'min_win_bytes_bwd': float('inf'),
            'act_data_pkt_fwd': 0,
            'min_seg_size_fwd': float('inf'),
            'key': flow_key
        }
        self.flows[flow_key] = new_flow
        self.active_flows[flow_key] = True
        return new_flow
    
    def update_flow_stats(self, flow, pkt, direction,bulk_key, timestamp):
        ip = pkt[IP]
        packet_length = len(pkt)
        flow['last_updated'] = timestamp
        
        # Update packet counts and byte counts
        if direction == 'forward':
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += packet_length
            flow['fwd_packet_lengths'].append(packet_length)
            flow['fwd_packet_times'].append(timestamp)
            
            # Update IAT for forward direction
            if flow['last_fwd_time'] is not None:
                iat = timestamp - flow['last_fwd_time']
                flow['fwd_iat'].update(iat)
            flow['last_fwd_time'] = timestamp
            
            # Set initial window size
            if flow['fwd_init_win_bytes'] == -1 and pkt.haslayer(TCP):
                flow['fwd_init_win_bytes'] = pkt[TCP].window
                flow['min_win_bytes_fwd'] = pkt[TCP].window
            
            # Update min window size
            if pkt.haslayer(TCP) and pkt[TCP].window < flow['min_win_bytes_fwd']:
                flow['min_win_bytes_fwd'] = pkt[TCP].window
            
            # Update actual data packets
            if pkt.haslayer(TCP) and len(pkt[TCP].payload) > 0:
                flow['act_data_pkt_fwd'] += 1
                
                # Update min segment size
                seg_size = len(pkt[TCP].payload)
                if seg_size < flow['min_seg_size_fwd']:
                    flow['min_seg_size_fwd'] = seg_size
        else:
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += packet_length
            flow['bwd_packet_lengths'].append(packet_length)
            flow['bwd_packet_times'].append(timestamp)
            
            # Update IAT for backward direction
            if flow['last_bwd_time'] is not None:
                iat = timestamp - flow['last_bwd_time']
                flow['bwd_iat'].update(iat)
            flow['last_bwd_time'] = timestamp
            
            # Set initial window size
            if flow['bwd_init_win_bytes'] == -1 and pkt.haslayer(TCP):
                flow['bwd_init_win_bytes'] = pkt[TCP].window
                flow['min_win_bytes_bwd'] = pkt[TCP].window
            
            # Update min window size
            if pkt.haslayer(TCP) and pkt[TCP].window < flow['min_win_bytes_bwd']:
                flow['min_win_bytes_bwd'] = pkt[TCP].window
        
        # Update flow IAT
        if flow['last_packet_time'] is not None:
            flow_iat = timestamp - flow['last_packet_time']
            flow['flow_iat'].update(flow_iat)
        flow['last_packet_time'] = timestamp
        
        # Update header length
        header_length = len(ip) - (len(ip.payload) if ip.payload else 0)
        if direction == 'forward':
            flow['fwd_header_length'] += header_length
        else:
            flow['bwd_header_length'] += header_length
        
        # Update TCP flags
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = tcp.flags
            
            if flags & 0x01:  # FIN
                flow['fin_flag'] += 1
            if flags & 0x02:  # SYN
                flow['syn_flag'] += 1
            if flags & 0x04:  # RST
                flow['rst_flag'] += 1
            if flags & 0x08:  # PSH
                flow['psh_flag'] += 1
                if direction == 'forward':
                    flow['fwd_psh_flags'] += 1
                else:
                    flow['bwd_psh_flags'] += 1
            if flags & 0x10:  # ACK
                flow['ack_flag'] += 1
            if flags & 0x20:  # URG
                flow['urg_flag'] += 1
                if direction == 'forward':
                    flow['fwd_urg_flags'] += 1
                else:
                    flow['bwd_urg_flags'] += 1
            if flags & 0x40:  # ECE
                flow['ece_flag'] += 1
            if flags & 0x80:  # CWE
                flow['cwe_flag'] += 1
        
        # Update active/idle times
        if flow['last_packet_time'] is not None:
            idle_time = timestamp - flow['last_packet_time']
            flow['idle_times'].append(idle_time)
            if idle_time > 1.0:  # Considered new active period
                if flow['last_packet_time'] != flow['start_time']:
                    active_time = flow['last_packet_time'] - flow['start_time']
                    flow['active_times'].append(active_time)
                flow['start_time'] = timestamp
        
        # Update bulk state
        
            bulk_key = 'fwd' if direction == 'forward' else 'bwd'
            bulk_state = flow['bulk_states'][bulk_key]
            bulk_state.update(packet_length, timestamp)
    
    def get_flow_features(self, flow, timestamp):
        features = [0.0] * 78
        flow_duration = timestamp - flow['start_time']
        
        # Basic flow features
        features[0] = flow['key'][4]  # Protocol
        features[1] = flow_duration * 1000  # Flow Duration (ms)
        features[2] = flow['fwd_packets']  # Total Fwd Packets
        features[3] = flow['bwd_packets']  # Total Backward Packets
        features[4] = sum(flow['fwd_packet_lengths'])  # Fwd Packets Length Total
        features[5] = sum(flow['bwd_packet_lengths'])  # Bwd Packets Length Total
        
        # Forward packet length stats
        if flow['fwd_packets'] > 0:
            features[6] = max(flow['fwd_packet_lengths'])  # Fwd Packet Length Max
            features[7] = min(flow['fwd_packet_lengths'])  # Fwd Packet Length Min
            features[8] = features[4] / flow['fwd_packets']  # Fwd Packet Length Mean
            features[9] = np.std(flow['fwd_packet_lengths']) if flow['fwd_packets'] > 1 else 0  # Fwd Packet Length Std
        
        # Backward packet length stats
        if flow['bwd_packets'] > 0:
            features[10] = max(flow['bwd_packet_lengths'])  # Bwd Packet Length Max
            features[11] = min(flow['bwd_packet_lengths'])  # Bwd Packet Length Min
            features[12] = features[5] / flow['bwd_packets']  # Bwd Packet Length Mean
            features[13] = np.std(flow['bwd_packet_lengths']) if flow['bwd_packets'] > 1 else 0  # Bwd Packet Length Std
        
        # Flow rate stats
        total_bytes = features[4] + features[5]
        total_packets = features[2] + features[3]
        if flow_duration > 0:
            features[14] = total_bytes / flow_duration  # Flow Bytes/s
            features[15] = total_packets / flow_duration  # Flow Packets/s
        
        # Flow IAT stats
        features[16] = flow['flow_iat'].mean if flow['flow_iat'].count > 0 else 0  # Flow IAT Mean
        features[17] = flow['flow_iat'].std if flow['flow_iat'].count > 1 else 0  # Flow IAT Std
        features[18] = flow['flow_iat'].max if flow['flow_iat'].count > 0 else 0  # Flow IAT Max
        features[19] = flow['flow_iat'].min if flow['flow_iat'].count > 0 else 0  # Flow IAT Min
        
        # Forward IAT stats
        features[20] = flow['fwd_iat'].total  # Fwd IAT Total
        features[21] = flow['fwd_iat'].mean if flow['fwd_iat'].count > 0 else 0  # Fwd IAT Mean
        features[22] = flow['fwd_iat'].std if flow['fwd_iat'].count > 1 else 0  # Fwd IAT Std
        features[23] = flow['fwd_iat'].max if flow['fwd_iat'].count > 0 else 0  # Fwd IAT Max
        features[24] = flow['fwd_iat'].min if flow['fwd_iat'].count > 0 else 0  # Fwd IAT Min
        
        # Backward IAT stats
        features[25] = flow['bwd_iat'].total  # Bwd IAT Total
        features[26] = flow['bwd_iat'].mean if flow['bwd_iat'].count > 0 else 0  # Bwd IAT Mean
        features[27] = flow['bwd_iat'].std if flow['bwd_iat'].count > 1 else 0  # Bwd IAT Std
        features[28] = flow['bwd_iat'].max if flow['bwd_iat'].count > 0 else 0  # Bwd IAT Max
        features[29] = flow['bwd_iat'].min if flow['bwd_iat'].count > 0 else 0  # Bwd IAT Min
        
        # Flag counts
        features[30] = flow['fwd_psh_flags']  # Fwd PSH Flags
        features[31] = flow['bwd_psh_flags']  # Bwd PSH Flags
        features[32] = flow['fwd_urg_flags']  # Fwd URG Flags
        features[33] = flow['bwd_urg_flags']  # Bwd URG Flags
        features[34] = flow['fwd_header_length']  # Fwd Header Length
        features[35] = flow['bwd_header_length']  # Bwd Header Length
        
        # Packet rate stats
        if flow_duration > 0:
            features[36] = flow['fwd_packets'] / flow_duration  # Fwd Packets/s
            features[37] = flow['bwd_packets'] / flow_duration  # Bwd Packets/s
        
        # Packet length stats
        all_packet_lengths = flow['fwd_packet_lengths'] + flow['bwd_packet_lengths']
        if all_packet_lengths:
            features[38] = min(all_packet_lengths)  # Min Packet Length
            features[39] = max(all_packet_lengths)  # Max Packet Length
            features[40] = sum(all_packet_lengths) / len(all_packet_lengths)  # Packet Length Mean
            features[41] = np.std(all_packet_lengths) if len(all_packet_lengths) > 1 else 0  # Packet Length Std
            features[42] = features[41] ** 2 if len(all_packet_lengths) > 1 else 0  # Packet Length Variance
        
        # TCP flag counts
        features[43] = flow['fin_flag']  # FIN Flag Count
        features[44] = flow['syn_flag']  # SYN Flag Count
        features[45] = flow['rst_flag']  # RST Flag Count
        features[46] = flow['psh_flag']  # PSH Flag Count
        features[47] = flow['ack_flag']  # ACK Flag Count
        features[48] = flow['urg_flag']  # URG Flag Count
        features[49] = flow['cwe_flag']  # CWE Flag Count
        features[50] = flow['ece_flag']  # ECE Flag Count
        
        # Ratio and size stats
        if features[4] > 0:
            features[51] = features[5] / features[4]  # Down/Up Ratio
        features[52] = total_bytes / total_packets if total_packets > 0 else 0  # Average Packet Size
        features[53] = features[4] / flow['fwd_packets'] if flow['fwd_packets'] > 0 else 0  # Avg Fwd Segment Size
        features[54] = features[5] / flow['bwd_packets'] if flow['bwd_packets'] > 0 else 0  # Avg Bwd Segment Size
        
        # Header length (already calculated)
        features[55] = features[34]  # Fwd Header Length.1
        
        # Bulk data stats
        fwd_bulk = flow['bulk_states']['fwd']
        bwd_bulk = flow['bulk_states']['bwd']
        
        features[56] = fwd_bulk.avg_bytes  # Fwd Avg Bytes/Bulk
        features[57] = fwd_bulk.avg_packets  # Fwd Avg Packets/Bulk
        features[58] = fwd_bulk.avg_rate  # Fwd Avg Bulk Rate
        features[59] = bwd_bulk.avg_bytes  # Bwd Avg Bytes/Bulk
        features[60] = bwd_bulk.avg_packets  # Bwd Avg Packets/Bulk
        features[61] = bwd_bulk.avg_rate  # Bwd Avg Bulk Rate
        
        # Subflow stats
        features[62] = flow['subflows']['fwd_packets']  # Subflow Fwd Packets
        features[63] = flow['subflows']['fwd_bytes']  # Subflow Fwd Bytes
        features[64] = flow['subflows']['bwd_packets']  # Subflow Bwd Packets
        features[65] = flow['subflows']['bwd_bytes']  # Subflow Bwd Bytes
        
        # Initial window sizes
        features[66] = flow['fwd_init_win_bytes'] if flow['fwd_init_win_bytes'] != -1 else 0  # Init_Win_bytes_forward
        features[67] = flow['bwd_init_win_bytes'] if flow['bwd_init_win_bytes'] != -1 else 0  # Init_Win_bytes_backward
        features[68] = flow['act_data_pkt_fwd']  # act_data_pkt_fwd
        features[69] = flow['min_seg_size_fwd'] if flow['min_seg_size_fwd'] != float('inf') else 0  # min_seg_size_forward
        
        # Active/Idle stats
        if flow['active_times']:
            features[70] = np.mean(flow['active_times'])  # Active Mean
            features[71] = np.std(flow['active_times']) if len(flow['active_times']) > 1 else 0  # Active Std
            features[72] = max(flow['active_times'])  # Active Max
            features[73] = min(flow['active_times'])  # Active Min
        
        if flow['idle_times']:
            features[74] = np.mean(flow['idle_times'])  # Idle Mean
            features[75] = np.std(flow['idle_times']) if len(flow['idle_times']) > 1 else 0  # Idle Std
            features[76] = max(flow['idle_times'])  # Idle Max
            features[77] = min(flow['idle_times'])  # Idle Min
        
        return features
    
    def cleanup_flows(self, current_time):
        with self.lock:
            expired_flows = []
            for flow_key, flow in list(self.flows.items()):
                if current_time - flow['last_updated'] > self.flow_timeout:
                    expired_flows.append(flow_key)
            
            for flow_key in expired_flows:
                del self.flows[flow_key]
                del self.active_flows[flow_key]

# Global flow tracker
flow_tracker = None

def log_error(message):
    """Log error and add to stats"""
    logger.error(message)
    detection_stats['errors'].append({
        'timestamp': datetime.now().isoformat(),
        'message': message,
        'status': detection_stats['status']
    })
    if len(detection_stats['errors']) > 20:
        detection_stats['errors'].pop(0)

def load_config():
    """Load or create configuration"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return {**DEFAULT_CONFIG, **json.load(f)}
        return DEFAULT_CONFIG
    except Exception as e:
        log_error(f"Config load error: {str(e)}")
        return DEFAULT_CONFIG

def save_config(config):
    """Save configuration to file"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        log_error(f"Config save error: {str(e)}")
        return False

def get_network_interfaces():
    """Get available network interfaces with IP addresses and descriptions"""
    try:
        interfaces = []
        for iface in get_if_list():
            try:
                addresses = psutil.net_if_addrs().get(iface, [])
                ipv4 = next((addr.address for addr in addresses if addr.family == socket.AF_INET), 'N/A')
                
                # Get interface statistics for description
                stats = psutil.net_io_counters(pernic=True).get(iface, None)
                if stats:
                    sent = stats.bytes_sent // 1024
                    recv = stats.bytes_recv // 1024
                    traffic_info = f"↑{sent}KB ↓{recv}KB"
                else:
                    traffic_info = "No traffic"
                
                interfaces.append({
                    'name': iface,
                    'description': f"{iface} ({ipv4}) - {traffic_info}",
                    'ip': ipv4,
                    'traffic': traffic_info
                })
            except Exception:
                interfaces.append({
                    'name': iface,
                    'description': f"{iface} - No IP address",
                    'ip': 'N/A',
                    'traffic': 'No data'
                })
        return interfaces
    except Exception as e:
        log_error(f"Interface detection error: {str(e)}")
        return []

def initialize_components():
    """Initialize AI model and other components"""
    global model, scaler, label_encoder, geoip_reader, config, flow_tracker
    
    config = load_config()
    
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    
    # Initialize AI model
    try:
        model = load_model(config['model_path'])
        scaler = joblib.load(config['scaler_path'])
        label_encoder = joblib.load(config['encoder_path'])
        logger.info("AI model loaded successfully")
    except Exception as e:
        log_error(f"Model load error: {str(e)}")
        logger.error(traceback.format_exc())
        return False
    
    # Initialize flow tracker
    flow_tracker = FlowTracker(flow_timeout=config.get('flow_timeout', 120))
    
    # Initialize GeoIP
    if config['geoip_enabled']:
        try:
            if os.path.exists('GeoLite2-City.mmdb'):
                geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
                logger.info("Geolocation database loaded")
            else:
                logger.warning("Geolocation database not found")
        except Exception as e:
            log_error(f"GeoIP init error: {str(e)}")
    
    # Get network interfaces
    detection_stats['interfaces'] = get_network_interfaces()
    
    return True

def extract_features(pkt):
    """Extract all 78 features from packet using flow-based tracking"""
    if not pkt.haslayer(IP) or detection_stats['status'] != 'running':
        return None

    try:
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        timestamp = time.time()
        
        # Determine direction
        flow_key = flow_tracker.get_flow_key(pkt)
        if flow_key is None:
            return None
            
        # Get source port correctly
        src_port = 0
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
        
        # Get canonical direction
        if (src_ip, src_port) == (flow_key[0], flow_key[1]):
           direction = 'forward'
           bulk_key = 'fwd'
        else:
           direction = 'backward'
           bulk_key = 'bwd'
        
        # Update flow
        flow = flow_tracker.update_flow(pkt, direction,timestamp)
        if flow is None:
            return None
        
        # Get all 78 features
        features = flow_tracker.get_flow_features(flow, timestamp)
        return features[:-1]
    except Exception as e:
        log_error(f"Feature extraction error: {str(e)}")
        logger.error(traceback.format_exc())
        return None

def get_location(ip):
    """Get location from IP address"""
    if not geoip_reader or not ip or ip == 'N/A' or ip.startswith(('192.168.', '10.', '172.')):
        return None
    
    try:
        response = geoip_reader.city(ip)
        return {
            'ip': ip,
            'country': response.country.name or "Unknown",
            'city': response.city.name or "Unknown",
            'latitude': response.location.latitude or 0,
            'longitude': response.location.longitude or 0
        }
    except Exception:
        return None

def check_threat_intelligence(ip):
    """Check IP against threat intelligence databases"""
    if not config.get('threat_intel_enabled', False) or not config.get('abuseipdb_key'):
        return None
        
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {
            'Key': config['abuseipdb_key'], 
            'Accept': 'application/json'
        }
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                'source': 'AbuseIPDB',
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'is_public': data.get('isPublic', False),
                'is_whitelisted': data.get('isWhitelisted', False),
                'last_reported': data.get('lastReportedAt', ''),
                'total_reports': data.get('totalReports', 0),
                'isp': data.get('isp', 'Unknown'),
                'domain': data.get('domain', 'Unknown')
            }
        else:
            logger.error(f"AbuseIPDB API error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        log_error(f"Threat intel error: {str(e)}")
        return None

def handle_packet(pkt):
    """Process network packets"""
    global last_traffic_update  # Add this line
    if detection_stats['status'] != 'running':
        return
        
    # Count ALL packets (including benign)
    detection_stats['total_packets'] += 1
    
    features = extract_features(pkt)
    if features is None:
        return

    try:
        if len(features) != 77:
         log_error(f"Unexpected feature count: {len(features)} (expected 77)")
         return

        # Scale and reshape features
        scaled = scaler.transform([features])
        reshaped = np.expand_dims(scaled, axis=2)

        # Predict
        probs = model.predict(reshaped, verbose=0)
        pred_idx = np.argmax(probs)
        label = label_encoder.classes_[pred_idx]
        confidence = probs[0][pred_idx]

        # Get packet info
        ip_layer = pkt[IP] if pkt.haslayer(IP) else None
        src_ip = ip_layer.src if ip_layer else "N/A"
        dst_ip = ip_layer.dst if ip_layer else "N/A"
        
        src_port = 0
        dst_port = 0
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        # Prepare alert info
        severity = SEVERITY_MAP.get(label, 'medium')
        packet_info = {
            'type': label,
            'confidence': float(confidence),
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'severity': severity,
            'threat_intel': None
        }

        # Check threat intelligence for malicious IPs
        if severity != 'info' and confidence > config['confidence_threshold']:
            threat_info = check_threat_intelligence(src_ip)
            if threat_info:
                packet_info['threat_intel'] = threat_info
                detection_stats['threat_intel'].append({
                    'ip': src_ip,
                    'info': threat_info,
                    'timestamp': datetime.now().isoformat()
                })
                if len(detection_stats['threat_intel']) > 50:
                    detection_stats['threat_intel'].pop(0)

        # Update traffic data for visualization
        traffic_entry = {
            'timestamp': datetime.now().isoformat(),
            'packet_size': len(pkt),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'type': label,
            'severity': severity
        }
        detection_stats['traffic_data'].append(traffic_entry)
        if len(detection_stats['traffic_data']) > 100:
            detection_stats['traffic_data'].pop(0)
            
        # Update traffic history
        current_time = time.time()
        if current_time - last_traffic_update > 1:  # Update once per second
            update_traffic_history()
        
        # Get confidence threshold based on sensitivity
        threshold = {
            'low': 0.95,
            'medium': 0.85,
            'high': 0.70
        }.get(config['sensitivity'], 0.85)
        
        # Create alert for all packets with sufficient confidence
        if confidence >= threshold:
            create_alert(packet_info)
    except Exception as e:
        log_error(f"Packet processing error: {str(e)}")

def update_traffic_history():
    """Update traffic history for visualization"""
    global last_traffic_update
    
    current_time = time.time()
    time_str = datetime.now().strftime("%H:%M:%S")
    
    # Count normal and threat packets in the last second
    threat_count = 0
    normal_count = 0
    
    for entry in detection_stats['traffic_data']:
        if entry['severity'] in ['medium', 'high', 'critical']:
            threat_count += 1
        else:
            normal_count += 1
    
    # Add to history
    detection_stats['traffic_history']['timestamps'].append(time_str)
    detection_stats['traffic_history']['normal'].append(normal_count)
    detection_stats['traffic_history']['threat'].append(threat_count)
    
    # Keep only last 60 seconds
    if len(detection_stats['traffic_history']['timestamps']) > 60:
        detection_stats['traffic_history']['timestamps'].pop(0)
        detection_stats['traffic_history']['normal'].pop(0)
        detection_stats['traffic_history']['threat'].pop(0)
    
    last_traffic_update = current_time

def create_alert(packet_info):
    """Create and log an alert"""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Format log entry with pipe separator
        log_entry = (
            f"{timestamp}|{packet_info['type']}|"
            f"{packet_info['src_ip']}:{packet_info['src_port']}|"
            f"{packet_info['dst_ip']}:{packet_info['dst_port']}|"
            f"{packet_info['confidence']:.2f}|"
            f"{packet_info['severity']}"
        )
        
        # Log to file for non-benign alerts
        if packet_info['severity'] != 'info':
            with open('logs/alerts.log', 'a') as f:
                f.write(f"{log_entry}\n")
        
        # Get location if enabled
        location = None
        if config.get('geoip_enabled', True):
            location = get_location(packet_info['src_ip'])
        
        # Prepare alert data for UI
        alert_data = {
            'timestamp': timestamp,
            'type': packet_info['type'],
            'src_ip': packet_info['src_ip'],
            'src_port': packet_info['src_port'],
            'dst_ip': packet_info['dst_ip'],
            'dst_port': packet_info['dst_port'],
            'confidence': f"{packet_info['confidence']:.2f}",
            'severity': packet_info['severity'],
            'location': location,
            'threat_intel': packet_info.get('threat_intel')
        }
        
        # Update dashboard
        update_dashboard(alert_data)
    except Exception as e:
        log_error(f"Alert creation error: {str(e)}")

def update_dashboard(alert_data):
    """Update dashboard with new alert"""
    try:
        socketio.emit('new_alert', alert_data)
        
        # Update stats
        detection_stats['last_updated'] = time.time()
        
        # Only count actual threats (not benign/info)
        if alert_data['severity'] != 'info':
            detection_stats['malicious_packets'] += 1
            detection_stats['attack_types'][alert_data['type']] = detection_stats['attack_types'].get(alert_data['type'], 0) + 1
            
        # Maintain recent alerts (max configured)
        detection_stats['recent_alerts'].insert(0, alert_data)
        if len(detection_stats['recent_alerts']) > config['max_ui_alerts']:
            detection_stats['recent_alerts'].pop()
        
        # Maintain attack locations (max 50)
        if alert_data.get('location') and alert_data['location'].get('latitude'):
                detection_stats['attack_locations'].append(alert_data['location'])
                if len(detection_stats['attack_locations']) > 50:
                    detection_stats['attack_locations'].pop(0)
    except Exception as e:
        log_error(f"Dashboard update error: {str(e)}")

def update_system_stats():
    """Update system statistics"""
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Memory usage
        mem = psutil.virtual_memory()
        
        # Disk usage
        disk = psutil.disk_usage('/')
        
        # Network
        net_io = psutil.net_io_counters()
        
        # Security processes
        security_processes = ["ids_service", "firewall", "antivirus"]
        running_processes = []
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] in security_processes:
                running_processes.append(proc.info['name'])
        
        detection_stats['system_stats'] = {
            'cpu': cpu_percent,
            'memory': {
                'total': mem.total,
                'available': mem.available,
                'used': mem.used,
                'percent': mem.percent
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': disk.percent
            },
            'network': {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv
            },
            'security_status': {
                'processes_running': running_processes,
                'missing_processes': list(set(security_processes) - set(running_processes))
            }
        }
    except Exception as e:
        log_error(f"System stats error: {str(e)}")

def scan_network():
    """Scan the local network for devices"""
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts='192.168.1.0/24', arguments='-sn')
        
        devices = []
        for host in scanner.all_hosts():
            if scanner[host].state() == 'up':
                devices.append({
                    'ip': host,
                    'status': 'online',
                    'hostname': scanner[host].hostname() or 'Unknown',
                    'mac': scanner[host]['addresses'].get('mac', 'Unknown')
                })
        
        detection_stats['network_devices'] = devices
        return devices
    except Exception as e:
        log_error(f"Network scan error: {str(e)}")
        return []

def start_sniffing():
    """Start packet sniffing"""
    try:
        interface = config['interface'] if config['interface'] != 'auto' else None
        detection_stats['active_interface'] = interface if interface else "Default"
        logger.info(f"Starting packet capture on interface: {interface if interface else 'default'}")
        sniff(iface=interface, prn=handle_packet, store=False)
    except Exception as e:
        log_error(f"Sniffing error: {str(e)}")
        logger.error(traceback.format_exc())
        detection_stats['status'] = 'error'

def generate_traffic_graph():
    """Generate a traffic graph for the UI with improved visibility"""
    try:
        # Create figure with light theme
        plt.figure(figsize=(10, 4), facecolor='#f8f9fa')
        ax = plt.gca()
        ax.set_facecolor('#ffffff')
        
        # Set colors
        normal_color = '#4cc9f0'
        threat_color = '#f72585'
        
        # Plot data
        timestamps = detection_stats['traffic_history']['timestamps']
        normal = detection_stats['traffic_history']['normal']
        threat = detection_stats['traffic_history']['threat']
        
        plt.plot(timestamps, normal, label='Normal Traffic', color=normal_color, linewidth=2)
        plt.plot(timestamps, threat, label='Threat Traffic', color=threat_color, linewidth=2)
        plt.fill_between(timestamps, normal, color=normal_color, alpha=0.2)
        plt.fill_between(timestamps, threat, color=threat_color, alpha=0.2)
        
        # Style the plot
        plt.title('Network Traffic Analysis', color='#212529', fontsize=14)
        plt.xlabel('Time', color='#495057')
        plt.ylabel('Packets per Second', color='#495057')
        plt.xticks(color='#6c757d', rotation=45, fontsize=8)
        plt.yticks(color='#6c757d')
        plt.legend(facecolor='#ffffff', labelcolor='#212529', edgecolor='#dee2e6')
        plt.grid(color=(0, 0, 0, 0.1), linestyle='--', linewidth=0.5)

        
        # Set spine colors
        for spine in ax.spines.values():
            spine.set_edgecolor('#adb5bd')
        
        # Save to buffer
        buf = BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', pad_inches=0.1, dpi=100)
        plt.close()
        buf.seek(0)
        
        # Encode image
        image_base64 = base64.b64encode(buf.read()).decode('utf-8')
        return f"data:image/png;base64,{image_base64}"
    except Exception as e:
        log_error(f"Traffic graph error: {str(e)}")
        return None

# Flask Routes
@app.route('/')
def dashboard():
    try:
        # Ensure we have the latest interface info
        detection_stats['interfaces'] = get_network_interfaces()
        detection_stats['active_interface'] = config['interface'] if config['interface'] != 'auto' else "Default"
        
        # Generate traffic graph
        traffic_graph = generate_traffic_graph() or ''
        
        return render_template('dashboard.html', detection_stats=detection_stats, traffic_graph=traffic_graph)
    except Exception as e:
        log_error(f"Dashboard render error: {str(e)}")
        return render_template('error.html', error_message=str(e), detection_stats=detection_stats)

@app.route('/history')
def history():
    try:
        alerts = []
        if os.path.exists('logs/alerts.log'):
            with open('logs/alerts.log', 'r') as f:
                alerts = f.readlines()[-config['max_history']:]
        return render_template('history.html', alerts=alerts, detection_stats=detection_stats)
    except Exception as e:
        log_error(f"History error: {str(e)}")
        return render_template('error.html', error_message=str(e), detection_stats=detection_stats)

@app.route('/export-logs')
def export_logs():
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ids_logs_{timestamp}.csv"
        
        # Create CSV content with headers
        csv_content = "Timestamp,Attack Type,Source IP,Source Port,Destination IP,Destination Port,Confidence,Severity\n"
        
        if os.path.exists('logs/alerts.log'):
            with open('logs/alerts.log', 'r') as f:
                for line in f:
                    parts = line.strip().split('|')
                    if len(parts) >= 6:
                        # Parse source and destination
                        source = parts[2].split(':')
                        dest = parts[3].split(':')
                        
                        csv_content += (
                            f"{parts[0]},{parts[1]},"
                            f"{(source[0] if len(source) > 0 else '')},"
                            f"{(source[1] if len(source) > 1 else '')},"
                            f"{(dest[0] if len(dest) > 0 else '')},"
                            f"{(dest[1] if len(dest) > 1 else '')},"
                            f"{parts[4]},{parts[5]}\n"
                        )
        
        # Create response
        return Response(
            csv_content,
            mimetype='text/csv',
            headers={'Content-disposition': f'attachment; filename={filename}'}
        )
    except Exception as e:
        log_error(f"Export logs error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/generate-report')
def generate_report():
    try:
        # Create a simple text report for now
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.txt"
        
        report_content = f"AI-Powered IDS Security Report\n"
        report_content += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
        
        report_content += f"Total Packets: {detection_stats['total_packets']}\n"
        report_content += f"Malicious Packets: {detection_stats['malicious_packets']}\n"
        report_content += f"Protection Level: {100 - (detection_stats['malicious_packets'] / max(1, detection_stats['total_packets']) * 100):.1f}%\n"
        report_content += f"Uptime: {detection_stats.get('uptime', 'N/A')}\n"
        report_content += f"System Status: {detection_stats['status']}\n\n"
        
        report_content += "Attack Distribution:\n"
        for attack, count in detection_stats['attack_types'].items():
            report_content += f"- {attack}: {count}\n"
        
        report_content += "\nRecent Alerts:\n"
        for alert in detection_stats['recent_alerts'][:10]:
            report_content += f"[{alert['timestamp']}] {alert['type']} - {alert['src_ip']} -> {alert['dst_ip']} (Confidence: {alert['confidence']}%)\n"
        
        return Response(
            report_content,
            mimetype='text/plain',
            headers={'Content-disposition': f'attachment; filename={filename}'}
        )
    except Exception as e:
        log_error(f"Report generation error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/stats')
def get_stats():
    try:
        # Calculate uptime
        uptime_seconds = int(time.time() - detection_stats['start_time'])
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        detection_stats['uptime'] = f"{hours}h {minutes}m {seconds}s"
        
        # Update system stats
        update_system_stats()
        
        # Generate traffic graph
        detection_stats['traffic_graph'] = generate_traffic_graph() or ''
        
        return jsonify(detection_stats)
    except Exception as e:
        log_error(f"Stats error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/clear-logs', methods=['POST'])
def clear_logs():
    try:
        open('logs/alerts.log', 'w').close()
        # Reset stats
        detection_stats['malicious_packets'] = 0
        detection_stats['attack_types'] = {}
        detection_stats['recent_alerts'] = []
        detection_stats['attack_locations'] = []
        detection_stats['threat_intel'] = []
        return jsonify({'status': 'success'})
    except Exception as e:
        log_error(f"Clear logs error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/get-config')
def get_config():
    return jsonify(config)

@app.route('/save-config', methods=['POST'])
def save_config_route():
    try:
        new_config = request.get_json()
        for key in new_config:
            if key in config:
                # Convert string booleans to actual booleans
                if key in ['sound_alerts', 'desktop_notifications', 'geoip_enabled', 'threat_intel_enabled']:
                    config[key] = new_config[key] in ['true', 'True', True]
                elif key in ['max_alerts', 'max_history', 'max_ui_alerts', 'flow_timeout']:
                    config[key] = int(new_config[key])
                else:
                    config[key] = new_config[key]
        
        save_config(config)
        
        # Update components that need restart
        if 'interface' in new_config:
            detection_stats['interfaces'] = get_network_interfaces()
            detection_stats['active_interface'] = config['interface'] if config['interface'] != 'auto' else "Default"
        
        # Update flow tracker timeout
        if 'flow_timeout' in new_config and flow_tracker:
            flow_tracker.flow_timeout = config['flow_timeout']
        
        return jsonify({'status': 'success'})
    except Exception as e:
        log_error(f"Save config error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/pause-monitoring', methods=['POST'])
def pause_monitoring():
    detection_stats['status'] = 'paused'
    return jsonify({'status': 'success', 'state': 'paused'})

@app.route('/resume-monitoring', methods=['POST'])
def resume_monitoring():
    detection_stats['status'] = 'running'
    return jsonify({'status': 'success', 'state': 'running'})

@app.route('/system-status')
def system_status():
    return jsonify({
        'status': detection_stats['status'],
        'errors': detection_stats['errors'][-5:],
        'components': {
            'model_loaded': model is not None,
            'geoip_loaded': geoip_reader is not None,
            'sniffing_active': detection_stats['status'] == 'running'
        }
    })

@app.route('/scan-network', methods=['POST'])
def scan_network_route():
    try:
        devices = scan_network()
        return jsonify({'status': 'success', 'devices': devices})
    except Exception as e:
        log_error(f"Network scan error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/settings')
def settings():
    # Add download instructions for GeoLite DB
    geoip_status = "Available" if os.path.exists('GeoLite2-City.mmdb') else "Not available (download required)"
    return render_template(
        'settings.html', 
        config=config, 
        detection_stats=detection_stats,
        geoip_status=geoip_status
    )

@app.route('/threat-intel')
def threat_intel():
    # Add download instructions for GeoLite DB
    geoip_status = "Available" if os.path.exists('GeoLite2-City.mmdb') else "Not available (download required)"
    return render_template(
        'threat_intel.html', 
        threat_intel=detection_stats['threat_intel'], 
        detection_stats=detection_stats,
        geoip_status=geoip_status
    )

@app.route('/download-geoip')
def download_geoip():
    return send_file('GeoIP_Instructions.txt', as_attachment=True)

@socketio.on('connect')
def handle_connect():
    socketio.emit('initial_data', detection_stats)

# Initialize system
if initialize_components():
    detection_stats['status'] = 'ready'
else:
    detection_stats['status'] = 'initialization_failed'

# Start threads when app runs
if __name__ == '__main__':
    if detection_stats['status'] == 'ready':
        # Start packet sniffing in a thread
        sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        sniff_thread.start()
        detection_stats['status'] = 'running'

        # Start system monitor thread
        def monitor_loop():
            while True:
                update_system_stats()
                time.sleep(2)
                
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()

    # Startup message
    print("\n" + "="*60)
    print(f"{'AI INTRUSION DETECTION SYSTEM':^60}")
    print("="*60)
    print(f"{'>> Dashboard:':<20} http://127.0.0.1:5000")
    print(f"{'>> Status:':<20} {detection_stats['status'].capitalize()}")
    
    if detection_stats['status'] == 'running':
        print(f"{'>> Interface:':<20} {config['interface'] if config['interface'] != 'auto' else 'auto'}")
        print(f"{'>> Geolocation:':<20} {'Enabled' if config['geoip_enabled'] else 'Disabled'}")
    elif detection_stats['status'] == 'initialization_failed':
        print(f"{'>> Error:':<20} Initialization failed - check logs")
    
    print("="*60)
    
    if detection_stats['status'] == 'running':
        print("[+] Monitoring network traffic...")
    
    print("[+] Press Ctrl+C to stop\n")
    
    try:
        socketio.run(app, host='127.0.0.1', port=5000, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[+] Shutting down IDS...")
        print("[+] System stopped gracefully")
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}")
        logger.error(traceback.format_exc())
        sys.exit(1)