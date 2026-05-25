# capture_heavy.py
"""
Fast, batch-friendly flow extractor + inference for heavy traffic.
- Live capture uses Scapy (fast)
- Offline PCAP uses scapy.rdpcap
- Bounded queue with drop-oldest-on-full
- Batch inference (reduce model calls)
- Aligns to scaler.feature_names_in_ if present
"""

auto_block_enabled=False
import argparse
import time
import queue
import threading
import traceback
import joblib
import pandas as pd
import numpy as np
from collections import defaultdict
from datetime import datetime
import csv
import os
import sys

# Scapy import (fast capture)
from scapy.all import sniff, rdpcap, IP, TCP, UDP  # requires Npcap on Windows

# ----------------------
# Custom Data Structures
# ----------------------
class Node:
    def __init__(self, key, flow_data):
        self.key = key
        self.flow = flow_data
        self.ts = time.time()
        self.prev = None
        self.next = None

class DoublyLinkedFlowList:
    def __init__(self):
        self.head = None
        self.tail = None
        self.size = 0

    def append(self, key, flow_data):
        node = Node(key, flow_data)
        if self.tail is None:
            self.head = self.tail = node
        else:
            self.tail.next = node
            node.prev = self.tail
            self.tail = node
        self.size += 1
        return node

    def move_to_tail(self, node):
        if node is self.tail:
            return
        # Unlink node
        if node.prev:
            node.prev.next = node.next
        if node.next:
            node.next.prev = node.prev
        if node is self.head:
            self.head = node.next
        # If list became empty, reset
        if self.head is None:
            self.tail = None
        # Append to tail
        if self.tail is None:
            self.head = self.tail = node
        else:
            self.tail.next = node
            node.prev = self.tail
            node.next = None
            self.tail = node

    def pop_oldest(self):
        if self.head is None:
            return None
        node = self.head
        self.head = node.next
        if self.head:
            self.head.prev = None
        else:
            self.tail = None
        self.size -= 1
        return node.key, node.flow

class Stack:
    def __init__(self, max_size=100):
        self.items = []
        self.max_size = max_size

    def push(self, item):
        if len(self.items) >= self.max_size:
            self.items.pop(0)
        self.items.append(item)

    def get_all(self):
        return self.items[::-1]

# ----------------------
# Configurable params
# ----------------------
AUTO_BLOCK_THRESHOLD = 0.8  # 80% confidence

QUEUE_MAXSIZE = 20000        # max packets buffered (burst tolerance)
BATCH_SIZE = 32              # model batch size
PREDICT_INTERVAL = 1.0       # seconds between attempting predictions
FLOW_IDLE_TIMEOUT = 4.0      # seconds to consider a flow finished (tunable)
ACTIVE_TIMEOUT = 1.0         # seconds for active segmentation
FLOW_DURATION_UNIT = 1.0     # 1.0 => seconds, set 1e6 if model expects microseconds
DROP_OLDEST_ON_FULL = True   # drop oldest packet when queue full
LOG_CSV = "predictions_log.csv"  # output CSV file (appends)

PROTO_MAP = {"TCP": 6, "UDP": 17}
LABELS_BINARY = ["BENIGN", "ATTACK"]  # 0->BENIGN, 1->ATTACK

# ----------------------
# Globals
# ----------------------
packet_q = queue.Queue(maxsize=QUEUE_MAXSIZE)
flow_list = DoublyLinkedFlowList()
flow_nodes = {}
flows_lock = threading.Lock()
recent_alerts = Stack()
stop_event = threading.Event()

def safe_stats(arr):
    if not arr:
        return 0.0, 0.0, 0.0, 0.0
    a = np.array(arr, dtype=float)
    return float(a.mean()), float(a.std()), float(a.min()), float(a.max())

import subprocess

import threading
def log_prevention_action(ip, confidence, reason="Auto-block: High confidence attack"):
    """Log prevention action to the prevention actions CSV file."""
    try:
        import csv
        import os
        from datetime import datetime, timedelta
        import time
        
        # Get current settings for duration
        settings = get_current_prevention_settings()
        duration = settings.get("blockDuration", 600)
        
        action_id = str(int(time.time() * 1000))
        timestamp = datetime.now().isoformat()
        expires_at = (datetime.now() + timedelta(seconds=duration)).isoformat()
        
        prevention_file = "prevention_actions.csv"
        
        # Ensure CSV file exists with headers
        if not os.path.exists(prevention_file):
            with open(prevention_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['id', 'timestamp', 'ip', 'action', 'reason', 'duration', 'status', 'expires_at'])
        
        # Append new action
        with open(prevention_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([action_id, timestamp, ip, 'IP_BLOCKED', reason, duration, 'active', expires_at])
        
        print(f"[PREVENTION] Logged action: {ip} blocked with {confidence*100:.2f}% confidence for {duration}s")
        return action_id
    except Exception as e:
        print(f"[PREVENTION ERROR] Failed to log action for IP {ip}: {e}")
        return None

def get_current_prevention_settings():
    """Load current prevention settings dynamically."""
    try:
        import json
        import os
        
        settings_file = "prevention_settings.json"
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                settings = json.load(f)
                return settings
        else:
            # Return default settings
            return {
                "autoPreventionEnabled": True,
                "blockDuration": 600,
                "threatThreshold": 0.8
            }
    except Exception as e:
        print(f"[PREVENTION ERROR] Failed to load settings: {e}")
        return {
            "autoPreventionEnabled": False,
            "blockDuration": 600,
            "threatThreshold": 0.8
        }

def block_ip_with_duration(ip, duration=600):
    """Block IP with custom duration using consistent rule naming."""
    try:
        # Use consistent rule naming: BlockIP_{ip}
        cmd = f'netsh advfirewall firewall add rule name="BlockIP_{ip}" dir=in action=block remoteip={ip}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[PREVENTION] Blocked IP: {ip} for {duration} seconds")
            # Start unblock timer with custom duration
            threading.Thread(target=unblock_after_delay, args=(ip, duration), daemon=True).start()
            return True
        else:
            print(f"[PREVENTION ERROR] Failed to block IP {ip}: {result.stderr}")
            return False
    except Exception as e:
        print(f"[PREVENTION ERROR] Could not block IP {ip}: {e}")
        return False

def unblock_after_delay(ip, delay=300):
    """
    Unblocks a specific IP after `delay` seconds.
    Uses the exact same rule name format as when blocking.
    """
    time.sleep(delay)
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=BlockIP_{ip}"],
            check=False, capture_output=True, text=True
        )
        
        if result.returncode == 0:
            print(f"[PREVENTION] Auto-unblocked IP: {ip} after {delay} seconds")
            # Update the prevention action status in the CSV
            update_prevention_action_status(ip, 'expired')
        else:
            print(f"[PREVENTION WARNING] Failed to auto-unblock IP {ip}: {result.stderr}")
    except Exception as e:
        print(f"[PREVENTION ERROR] Exception during auto-unblock of IP {ip}: {e}")

def update_prevention_action_status(ip, new_status):
    """Update the status of a prevention action for a specific IP."""
    try:
        prevention_file = "prevention_actions.csv"
        if not os.path.exists(prevention_file):
            return False
        
        # Read all actions
        actions = []
        updated = False
        with open(prevention_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['ip'] == ip and row['status'] == 'active':
                    row['status'] = new_status
                    updated = True
                    print(f"[PREVENTION] Updated status for IP {ip} to {new_status}")
                actions.append(row)
        
        # Write back updated actions if any changes were made
        if updated and actions:
            with open(prevention_file, 'w', newline='') as f:
                fieldnames = ['id', 'timestamp', 'ip', 'action', 'reason', 'duration', 'status', 'expires_at']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(actions)
        
        return updated
    except Exception as e:
        print(f"[PREVENTION ERROR] Failed to update prevention action status for IP {ip}: {e}")
        return False    

def normalize_scapy_pkt(pkt):
    
    try:
        ts = float(pkt.time)
        length = int(len(pkt))
        if not pkt.haslayer(IP):
            return None
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ip_hdr_len = int(getattr(ip_layer, "ihl", 0) * 4) if hasattr(ip_layer, "ihl") else 0

        proto_str = None
        src_port = None
        dst_port = None
        tcp_hdr_len = 0
        tcp_flags = ""
        tcp_window = None
        tcp_seg_len = None

        if pkt.haslayer(TCP):
            proto_str = "TCP"
            tcp = pkt[TCP]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            tcp_hdr_len = int(getattr(tcp, "dataofs", 0) * 4) if hasattr(tcp, "dataofs") else 0
            tcp_flags = str(tcp.flags)
            tcp_window = int(getattr(tcp, "window", 0) or 0)
            try:
                tcp_seg_len = int(len(bytes(tcp.payload))) if tcp.payload else 0
            except Exception:
                tcp_seg_len = 0

        elif pkt.haslayer(UDP):
            proto_str = "UDP"
            udp = pkt[UDP]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            tcp_hdr_len = 0
            tcp_flags = ""
        else:
            return None  # not TCP/UDP => ignore

        return {
            'ts': ts, 'length': length,
            'src_ip': src_ip, 'dst_ip': dst_ip,
            'proto': proto_str,
            'src_port': src_port, 'dst_port': dst_port,
            'ip_hdr_len': ip_hdr_len, 'tcp_hdr_len': tcp_hdr_len,
            'tcp_flags': tcp_flags, 'tcp_window': tcp_window, 'tcp_seg_len': tcp_seg_len
        }
    except Exception:
        return None

def get_flow_key_from_norm(p):
    """Canonical flow key from normalized packet dict."""
    try:
        a = (p['src_ip'], int(p['src_port']))
        b = (p['dst_ip'], int(p['dst_port']))
        key = tuple(sorted([a, b])) + (p['proto'],)
        return key
    except Exception:
        return None

# ----------------------
# Flow aggregation (compatible with previous logic)
# ----------------------
def update_flow_from_normalized(p):
    key = get_flow_key_from_norm(p)
    if not key:
        return
    ts = p['ts']
    pkt_len = p['length']
    ip_hdr_len = p['ip_hdr_len'] or 0
    tcp_hdr_len = p['tcp_hdr_len'] or 0
    proto = p['proto']
    src_ip = p['src_ip']
    dst_ip = p['dst_ip']
    src_port = int(p['src_port'])
    dst_port = int(p['dst_port'])
    payload_len = pkt_len - (ip_hdr_len + tcp_hdr_len)

    with flows_lock:
        node = flow_nodes.get(key)
        if node is None:
            flow = {
                'start_time': ts, 'end_time': ts,
                'total_fwd_packets': 0, 'total_bwd_packets': 0,
                'total_fwd_bytes': 0, 'total_bwd_bytes': 0,
                'fwd_packet_lengths': [], 'bwd_packet_lengths': [],
                'fwd_header_lengths': [], 'bwd_header_lengths': [],
                'packet_times': [], 'flow_iat': [], 'fwd_iat': [], 'bwd_iat': [],
                'last_fwd_time': None, 'last_bwd_time': None,
                'active_times': [], 'idle_times': [], 'last_packet_time': None,
                'fin_flags_fwd': 0, 'fin_flags_bwd': 0,
                'syn_flags_fwd': 0, 'syn_flags_bwd': 0,
                'rst_flags_fwd': 0, 'rst_flags_bwd': 0,
                'psh_flags_fwd': 0, 'psh_flags_bwd': 0,
                'ack_flags_fwd': 0, 'ack_flags_bwd': 0,
                'urg_flags_fwd': 0, 'urg_flags_bwd': 0,
                'cwe_flags_fwd': 0, 'ece_flags_fwd': 0,
                'init_fwd_win_bytes': [], 'init_bwd_win_bytes': [],
                'act_data_pkt_fwd': 0, 'min_seg_size_fwd': None,
                'subflow_fwd_packets': 0, 'subflow_bwd_packets': 0, 'subflow_fwd_bytes': 0, 'subflow_bwd_bytes': 0,
                'protocol': proto, 'min_packet_len': None, 'max_packet_len': None,
                'current_active_start': None,
                'fwd_bulk_state': {'bytes_since_bulk': 0, 'pkts_since_bulk': 0, 'bulk_bytes': [], 'bulk_pkts': []},
                'bwd_bulk_state': {'bytes_since_bulk': 0, 'pkts_since_bulk': 0, 'bulk_bytes': [], 'bulk_pkts': []},
                'src_ip': src_ip, 'dst_ip': dst_ip, 'src_port': src_port, 'dst_port': dst_port
            }
            node = flow_list.append(key, flow)
            flow_nodes[key] = node
        else:
            flow = node.flow
            flow_list.move_to_tail(node)

        flow['end_time'] = ts

        if flow['last_packet_time'] is not None:
            gap = ts - flow['last_packet_time']
            if gap > ACTIVE_TIMEOUT:
                if flow['current_active_start'] is not None:
                    ad = flow['last_packet_time'] - flow['current_active_start']
                    if ad > 0:
                        flow['active_times'].append(ad)
                flow['idle_times'].append(gap)
                flow['current_active_start'] = ts
        else:
            flow['current_active_start'] = ts
        flow['last_packet_time'] = ts

        if flow['min_packet_len'] is None or pkt_len < flow['min_packet_len']:
            flow['min_packet_len'] = pkt_len
        if flow['max_packet_len'] is None or pkt_len > flow['max_packet_len']:
            flow['max_packet_len'] = pkt_len

        canonical_a = key[0]
        direction = "forward" if (src_ip, src_port) == canonical_a else "backward"

        if direction == "forward":
            flow['total_fwd_packets'] += 1
            flow['total_fwd_bytes'] += pkt_len
            flow['fwd_packet_lengths'].append(pkt_len)
            flow['fwd_header_lengths'].append(ip_hdr_len + tcp_hdr_len)
            flow['subflow_fwd_packets'] += 1
            flow['subflow_fwd_bytes'] += pkt_len
            if flow['last_fwd_time'] is not None:
                flow['fwd_iat'].append(ts - flow['last_fwd_time'])
            flow['last_fwd_time'] = ts
            if payload_len > 0:
                flow['act_data_pkt_fwd'] += 1
            if proto == 'TCP':
                if p.get('tcp_window') is not None and not flow['init_fwd_win_bytes']:
                    try:
                        flow['init_fwd_win_bytes'].append(int(p.get('tcp_window')))
                    except:
                        pass
                if p.get('tcp_seg_len') is not None:
                    seg = int(p.get('tcp_seg_len') or 0)
                    if flow['min_seg_size_fwd'] is None:
                        flow['min_seg_size_fwd'] = seg
                    else:
                        flow['min_seg_size_fwd'] = min(flow['min_seg_size_fwd'], seg)
                flags = p.get('tcp_flags') or ""
                if 'F' in flags: flow['fin_flags_fwd'] += 1
                if 'S' in flags: flow['syn_flags_fwd'] += 1
                if 'R' in flags: flow['rst_flags_fwd'] += 1
                if 'P' in flags: flow['psh_flags_fwd'] += 1
                if 'A' in flags: flow['ack_flags_fwd'] += 1
                if 'U' in flags: flow['urg_flags_fwd'] += 1
            if payload_len > 0:
                s = flow['fwd_bulk_state']
                s['bytes_since_bulk'] += payload_len
                s['pkts_since_bulk'] += 1
                if s['bytes_since_bulk'] > 1000 or s['pkts_since_bulk'] > 10:
                    s['bulk_bytes'].append(s['bytes_since_bulk'])
                    s['bulk_pkts'].append(s['pkts_since_bulk'])
                    s['bytes_since_bulk'] = 0
                    s['pkts_since_bulk'] = 0

        else:
            flow['total_bwd_packets'] += 1
            flow['total_bwd_bytes'] += pkt_len
            flow['bwd_packet_lengths'].append(pkt_len)
            flow['bwd_header_lengths'].append(ip_hdr_len + tcp_hdr_len)
            flow['subflow_bwd_packets'] += 1
            flow['subflow_bwd_bytes'] += pkt_len
            if flow['last_bwd_time'] is not None:
                flow['bwd_iat'].append(ts - flow['last_bwd_time'])
            flow['last_bwd_time'] = ts
            if proto == 'TCP':
                if p.get('tcp_window') is not None and not flow['init_bwd_win_bytes']:
                    try:
                        flow['init_bwd_win_bytes'].append(int(p.get('tcp_window')))
                    except:
                        pass
                flags = p.get('tcp_flags') or ""
                if 'F' in flags: flow['fin_flags_bwd'] += 1
                if 'S' in flags: flow['syn_flags_bwd'] += 1
                if 'R' in flags: flow['rst_flags_bwd'] += 1
                if 'P' in flags: flow['psh_flags_bwd'] += 1
                if 'A' in flags: flow['ack_flags_bwd'] += 1
                if 'U' in flags: flow['urg_flags_bwd'] += 1
            if payload_len > 0:
                s = flow['bwd_bulk_state']
                s['bytes_since_bulk'] += payload_len
                s['pkts_since_bulk'] += 1
                if s['bytes_since_bulk'] > 1000 or s['pkts_since_bulk'] > 10:
                    s['bulk_bytes'].append(s['bytes_since_bulk'])
                    s['bulk_pkts'].append(s['pkts_since_bulk'])
                    s['bytes_since_bulk'] = 0
                    s['pkts_since_bulk'] = 0

        flow['packet_times'].append(ts)
        if len(flow['packet_times']) > 1:
            flow['flow_iat'].append(ts - flow['packet_times'][-2])

# ----------------------
# Flow finalization -> features
# ----------------------
def finalize_bulk_stats(bulk_state, duration):
    if not bulk_state['bulk_bytes']:
        return 0.0, 0.0, 0.0
    avg_bytes = float(np.mean(bulk_state['bulk_bytes']))
    avg_pkts = float(np.mean(bulk_state['bulk_pkts']))
    bulk_rate = float(sum(bulk_state['bulk_bytes']) / duration) if duration > 0 else 0.0
    return avg_bytes, avg_pkts, bulk_rate

def extract_flow_features(key, flow):
    # finalize active interval
    if flow['current_active_start'] is not None and flow['end_time'] is not None:
        ad = flow['end_time'] - flow['current_active_start']
        if ad > 0:
            flow['active_times'].append(ad)
        flow['current_active_start'] = None

    active_mean, active_std, active_min, active_max = safe_stats(flow['active_times'])
    idle_mean, idle_std, idle_min, idle_max = safe_stats(flow['idle_times'])

    duration = float(flow['end_time'] - flow['start_time']) if (flow['start_time'] and flow['end_time']) else 0.0
    duration *= FLOW_DURATION_UNIT

    fwd_mean, fwd_std, fwd_min, fwd_max = safe_stats(flow['fwd_packet_lengths'])
    bwd_mean, bwd_std, bwd_min, bwd_max = safe_stats(flow['bwd_packet_lengths'])

    combined = flow['fwd_packet_lengths'] + flow['bwd_packet_lengths']
    pkt_mean, pkt_std, pkt_min, pkt_max = safe_stats(combined)
    pkt_var = float(np.var(combined)) if combined else 0.0

    flow_byts_sec = float((flow['total_fwd_bytes'] + flow['total_bwd_bytes']) / duration) if duration > 0 else 0.0
    flow_pkts_sec = float((flow['total_fwd_packets'] + flow['total_bwd_packets']) / duration) if duration > 0 else 0.0

    flow_iat_mean, flow_iat_std, flow_iat_min, flow_iat_max = safe_stats(flow['flow_iat'])
    fwd_iat_mean, fwd_iat_std, fwd_iat_min, fwd_iat_max = safe_stats(flow['fwd_iat'])
    bwd_iat_mean, bwd_iat_std, bwd_iat_min, bwd_iat_max = safe_stats(flow['bwd_iat'])

    down_up_ratio = float(flow['total_bwd_packets']) / flow['total_fwd_packets'] if flow['total_fwd_packets'] > 0 else 0.0

    fwd_hdr_sum = float(sum(flow['fwd_header_lengths'])) if flow['fwd_header_lengths'] else 0.0
    bwd_hdr_sum = float(sum(flow['bwd_header_lengths'])) if flow['bwd_header_lengths'] else 0.0

    fwd_avg_bytes_bulk, fwd_avg_pkts_bulk, fwd_avg_bulk_rate = finalize_bulk_stats(flow['fwd_bulk_state'], duration)
    bwd_avg_bytes_bulk, bwd_avg_pkts_bulk, bwd_avg_bulk_rate = finalize_bulk_stats(flow['bwd_bulk_state'], duration)

    proto_num = int(PROTO_MAP.get(flow['protocol'], 0)) if flow.get('protocol') else 0

    features = {
        'Source Port': int(flow['src_port']) if flow.get('src_port') is not None else -1,
        'Destination Port': int(flow['dst_port']) if flow.get('dst_port') is not None else -1,
        'Source IP': flow['src_ip'] if flow.get('src_ip') is not None else "0.0.0.0",
         'Destination IP': flow['dst_ip'] if flow.get('dst_ip') is not None else "0.0.0.0",
        'Protocol': proto_num,
        'Flow Duration': float(duration),
        'Total Fwd Packets': int(flow['total_fwd_packets']),
        'Total Backward Packets': int(flow['total_bwd_packets']),
        'Total Length of Fwd Packets': int(flow['total_fwd_bytes']),
        'Total Length of Bwd Packets': int(flow['total_bwd_bytes']),
        'Fwd Packet Length Max': float(fwd_max),
        'Fwd Packet Length Min': float(fwd_min),
        'Fwd Packet Length Mean': float(fwd_mean),
        'Fwd Packet Length Std': float(fwd_std),
        'Bwd Packet Length Max': float(bwd_max),
        'Bwd Packet Length Min': float(bwd_min),
        'Bwd Packet Length Mean': float(bwd_mean),
        'Bwd Packet Length Std': float(bwd_std),
        'Flow Bytes/s': float(flow_byts_sec),
        'Flow Packets/s': float(flow_pkts_sec),
        'Flow IAT Mean': float(flow_iat_mean),
        'Flow IAT Std': float(flow_iat_std),
        'Flow IAT Max': float(flow_iat_max),
        'Flow IAT Min': float(flow_iat_min),
        'Fwd IAT Total': float(sum(flow['fwd_iat'])) if flow['fwd_iat'] else 0.0,
        'Fwd IAT Mean': float(fwd_iat_mean),
        'Fwd IAT Std': float(fwd_iat_std),
        'Fwd IAT Max': float(fwd_iat_max),
        'Fwd IAT Min': float(fwd_iat_min),
        'Bwd IAT Total': float(sum(flow['bwd_iat'])) if flow['bwd_iat'] else 0.0,
        'Bwd IAT Mean': float(bwd_iat_mean),
        'Bwd IAT Std': float(bwd_iat_std),
        'Bwd IAT Max': float(bwd_iat_max),
        'Bwd IAT Min': float(bwd_iat_min),
        'Fwd PSH Flags': int(flow['psh_flags_fwd']),
        'Bwd PSH Flags': int(flow['psh_flags_bwd']),
        'Fwd URG Flags': int(flow['urg_flags_fwd']),
        'Bwd URG Flags': int(flow['urg_flags_bwd']),
        'Fwd Header Length': float(fwd_hdr_sum),
        'Bwd Header Length': float(bwd_hdr_sum),
        'Fwd Packets/s': float(flow['total_fwd_packets'] / duration) if duration > 0 else 0.0,
        'Bwd Packets/s': float(flow['total_bwd_packets'] / duration) if duration > 0 else 0.0,
        'Min Packet Length': int(flow['min_packet_len']) if flow['min_packet_len'] is not None else 0,
        'Max Packet Length': int(flow['max_packet_len']) if flow['max_packet_len'] is not None else 0,
        'Packet Length Mean': float(pkt_mean),
        'Packet Length Std': float(pkt_std),
        'Packet Length Variance': float(pkt_var),
        'FIN Flag Count': int(flow['fin_flags_fwd'] + flow['fin_flags_bwd']),
        'SYN Flag Count': int(flow['syn_flags_fwd'] + flow['syn_flags_bwd']),
        'RST Flag Count': int(flow['rst_flags_fwd'] + flow['rst_flags_bwd']),
        'PSH Flag Count': int(flow['psh_flags_fwd'] + flow['psh_flags_bwd']),
        'ACK Flag Count': int(flow['ack_flags_fwd'] + flow['ack_flags_bwd']),
        'URG Flag Count': int(flow['urg_flags_fwd'] + flow['urg_flags_bwd']),
        'CWE Flag Count': int(flow['cwe_flags_fwd']),
        'ECE Flag Count': int(flow['ece_flags_fwd']),
        'Down/Up Ratio': float(down_up_ratio),
        'Average Packet Size': float(pkt_mean),
        'Avg Fwd Segment Size': float(fwd_mean),
        'Avg Bwd Segment Size': float(bwd_mean),
        'Fwd Header Length.1': float(fwd_hdr_sum),
        'Fwd Avg Bytes/Bulk': float(fwd_avg_bytes_bulk),
        'Fwd Avg Packets/Bulk': float(fwd_avg_pkts_bulk),
        'Fwd Avg Bulk Rate': float(fwd_avg_bulk_rate),
        'Bwd Avg Bytes/Bulk': float(bwd_avg_bytes_bulk),
        'Bwd Avg Packets/Bulk': float(bwd_avg_pkts_bulk),
        'Bwd Avg Bulk Rate': float(bwd_avg_bulk_rate),
        'Subflow Fwd Packets': int(flow['subflow_fwd_packets']),
        'Subflow Fwd Bytes': int(flow['subflow_fwd_bytes']),
        'Subflow Bwd Packets': int(flow['subflow_bwd_packets']),
        'Subflow Bwd Bytes': int(flow['subflow_bwd_bytes']),
        'Init_Win_bytes_forward': int(flow['init_fwd_win_bytes'][0]) if flow['init_fwd_win_bytes'] else -1,
        'Init_Win_bytes_backward': int(flow['init_bwd_win_bytes'][0]) if flow['init_bwd_win_bytes'] else -1,
        'act_data_pkt_fwd': int(flow['act_data_pkt_fwd']),
        'min_seg_size_forward': int(flow['min_seg_size_fwd']) if flow['min_seg_size_fwd'] is not None else 0,
        'Active Mean': float(active_mean),
        'Active Std': float(active_std),
        'Active Max': float(active_max),
        'Active Min': float(active_min),
        'Idle Mean': float(idle_mean),
        'Idle Std': float(idle_std),
        'Idle Max': float(idle_max),
        'Idle Min': float(idle_min),
    }
    return pd.DataFrame([features])

# ----------------------
# Prediction pipeline (batch)
# ----------------------
def align_and_scale(df, scaler):
    if scaler is None:
        return df
    fn = getattr(scaler, 'feature_names_in_', None)
    if fn is None:
        try:
            arr = scaler.transform(df.values)
            return pd.DataFrame(arr, index=df.index)
        except Exception as e:
            print("[WARN] scaler transform failed:", e)
            return df
    for col in fn:
        if col not in df.columns:
            df[col] = 0.0
    df_aligned = df[list(fn)]
    scaled = scaler.transform(df_aligned)
    return pd.DataFrame(scaled, columns=list(fn))

def predict_batch(df_rows, scaler, model, batch_size_param):
    if not df_rows:
        return []
    df = pd.concat(df_rows, ignore_index=True)
    for c in df.columns:
        if df[c].dtype == 'object':
            df = df.drop(columns=[c])
    scaled = align_and_scale(df, scaler)
    results = []
    if model is None:
        for i in range(len(scaled)):
            results.append({'label': 'UNKNOWN', 'confidence': 0.0})
        return results
    preds = model.predict(scaled.values, batch_size=max(1, min(batch_size_param, len(scaled))))
    if preds.ndim == 2 and preds.shape[1] == 1:
        probs = preds.ravel()
        for p in probs:
            if p >= 0.5:
                results.append({'label': LABELS_BINARY[1], 'confidence': float(p)})
            else:
                results.append({'label': LABELS_BINARY[0], 'confidence': float(1.0 - p)})
    elif preds.ndim == 2:
        for row in preds:
            idx = int(np.argmax(row))
            conf = float(row[idx])
            label = LABELS_BINARY[idx] if idx < len(LABELS_BINARY) else f"CLASS_{idx}"
            results.append({'label': label, 'confidence': conf})
    else:
        p = float(np.ravel(preds)[0])
        if p >= 0.5:
            results.append({'label': LABELS_BINARY[1], 'confidence': p})
        else:
            results.append({'label': LABELS_BINARY[0], 'confidence': 1.0 - p})
    return results

# ----------------------
# Threads: capture, flow processor, inference dispatcher
# ----------------------
def scapy_capture_worker(iface):
    def _push(pkt):
        if stop_event.is_set():
            return False
        p = normalize_scapy_pkt(pkt)
        if p:
            try:
                packet_q.put_nowait(p)
            except queue.Full:
                if DROP_OLDEST_ON_FULL:
                    try:
                        packet_q.get_nowait()
                        packet_q.put_nowait(p)
                    except:
                        pass
    sniff(prn=_push, store=False, iface=iface)

def pcap_reader_worker(path):
    try:
        pkts = rdpcap(path)
        for pkt in pkts:
            if stop_event.is_set():
                break
            p = normalize_scapy_pkt(pkt)
            if p:
                packet_q.put(p, timeout=1)
    except Exception as e:
        print("[PCAP reader error]", e)

def flow_processor_worker(out_queue):
    last_flush = time.time()
    while not stop_event.is_set():
        try:
            p = packet_q.get(timeout=0.5)
        except queue.Empty:
            p = None
        if p is not None:
            update_flow_from_normalized(p)

        now = time.time()
        if now - last_flush >= PREDICT_INTERVAL:
            to_flush = []
            with flows_lock:
                while True:
                    item = flow_list.pop_oldest()
                    if item is None:
                        break
                    key, flow = item
                    del flow_nodes[key]
                    if now - flow['end_time'] > FLOW_IDLE_TIMEOUT:
                        df_row = extract_flow_features(key, flow)
                        if not df_row.empty:
                            to_flush.append((key, df_row))
                    else:
                        # Re-append if not timed out
                        flow_list.append(key, flow)
                        flow_nodes[key] = flow_list.tail
                        break  # Since ordered, later ones are newer
            for k, df_row in to_flush:
                out_queue.put((k, df_row))
            last_flush = now

    # Final flush
    with flows_lock:
        while True:
            item = flow_list.pop_oldest()
            if item is None:
                break
            key, flow = item
            del flow_nodes[key]
            df_row = extract_flow_features(key, flow)
            if not df_row.empty:
                out_queue.put((key, df_row))
    out_queue.put(None)

def inference_worker(out_queue, scaler, model, batch_size_param):
    batch_rows = []
    batch_keys = []
    last_predict_time = time.time()
    csv_fields = ['timestamp', 'flow_key', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                  'duration', 'prediction', 'confidence', 'blocked']
    if LOG_CSV and not os.path.exists(LOG_CSV):
        with open(LOG_CSV, 'w', newline='') as fh:
            writer = csv.DictWriter(fh, fieldnames=csv_fields)
            writer.writeheader()

    while True:
        try:
            item = out_queue.get(timeout=0.5)
        except queue.Empty:
            item = None
        if item is None:
            # flush pending batch
            if batch_rows:
                results = predict_batch(batch_rows, scaler, model, batch_size_param)
                # print & log
                for r, (k, df_row) in zip(results, batch_keys):
                    label = r['label']; conf = r['confidence']
                    dur = df_row.iloc[0].get('Flow Duration', 0.0)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Flow {k} Duration={dur:.6f} Prediction={label} Confidence={conf*100:.2f}%")
                    
                    # Load current settings dynamically for each prediction
                    settings = get_current_prevention_settings()
                    
                    if label == "ATTACK" and settings.get("autoPreventionEnabled", False):
                        threat_threshold = settings.get("threatThreshold", 0.8)
                        block_duration = settings.get("blockDuration", 600)
                        
                        if conf >= threat_threshold:
                            src = df_row.iloc[0].get('Source IP', 'N/A')
                            if block_ip_with_duration(src, block_duration):
                                log_prevention_action(src, conf, f"Auto-block: {conf*100:.2f}% confidence attack detected")
                                
                                with open("prevention_log.csv", "a", newline="") as f:
                                    writer = csv.writer(f)
                                    writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), src, f"{conf*100:.2f}%", "Auto-Blocked"])
                                
                                print(f"[AUTO-PREVENTION] IP {src} automatically blocked (confidence: {conf*100:.2f}%, threshold: {threat_threshold*100:.1f}%, duration: {block_duration}s)")
                            
                    if LOG_CSV:
                        src = df_row.iloc[0].get('Source IP', 'N/A'); dst = df_row.iloc[0].get('Destination IP', 'N/A')
                        with open(LOG_CSV, 'a', newline='') as fh:
                            writer = csv.DictWriter(fh, fieldnames=csv_fields)
                            writer.writerow({
                                'timestamp': datetime.now().isoformat(),
                                'flow_key': str(k),
                                'src_ip': src, 'dst_ip': dst,
                                'src_port': df_row.iloc[0].get('Source Port', -1),
                                'dst_port': df_row.iloc[0].get('Destination Port', -1),
                                'duration': dur, 'prediction': label, 'confidence': conf,
                                'blocked': 'Blocked' if label == "ATTACK" and settings.get("autoPreventionEnabled", False) and conf >= settings.get("threatThreshold", 0.8) else 'Not Blocked'
                            })

                batch_rows = []; batch_keys = []
            # upstream signalled EOF
            if stop_event.is_set():
                break
            continue

        # got (key, df_row)
        key, df_row = item
        batch_rows.append(df_row)
        batch_keys.append((key, df_row))

        # if batch full or time reached, predict
        if len(batch_rows) >= batch_size_param or (time.time() - last_predict_time) >= PREDICT_INTERVAL:
            try:
                results = predict_batch(batch_rows, scaler, model, batch_size_param)
            except Exception as e:
                print("[Prediction error]", e)
                traceback.print_exc()
                results = [{'label': 'ERR', 'confidence': 0.0}] * len(batch_rows)
            for r, (k, df_row) in zip(results, batch_keys):
                label = r['label']; conf = r['confidence']
                dur = df_row.iloc[0].get('Flow Duration', 0.0)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Flow {k} Duration={dur:.6f} Prediction={label} Confidence={conf*100:.2f}%")
                
                # Load current settings dynamically for each prediction
                settings = get_current_prevention_settings()
                
                if label == "ATTACK" and settings.get("autoPreventionEnabled", False):
                    threat_threshold = settings.get("threatThreshold", 0.8)
                    block_duration = settings.get("blockDuration", 600)
                    
                    if conf >= threat_threshold:
                        src = df_row.iloc[0].get('Source IP', 'N/A')
                        if block_ip_with_duration(src, block_duration):
                            log_prevention_action(src, conf, f"Auto-block: {conf*100:.2f}% confidence attack detected")
                            
                            with open("prevention_log.csv", "a", newline="") as f:
                                writer = csv.writer(f)
                                writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), src, f"{conf*100:.2f}%", "Auto-Blocked"])
                            
                            print(f"[AUTO-PREVENTION] IP {src} automatically blocked (confidence: {conf*100:.2f}%, threshold: {threat_threshold*100:.1f}%, duration: {block_duration}s)")
                
                if LOG_CSV:
                    src = df_row.iloc[0].get('Source IP', 'N/A'); dst = df_row.iloc[0].get('Destination IP', 'N/A')
                    with open(LOG_CSV, 'a', newline='') as fh:
                        writer = csv.DictWriter(fh, fieldnames=csv_fields)
                        writer.writerow({
                            'timestamp': datetime.now().isoformat(),
                            'flow_key': str(k),
                            'src_ip': src, 'dst_ip': dst,
                            'src_port': df_row.iloc[0].get('Source Port', -1),
                            'dst_port': df_row.iloc[0].get('Destination Port', -1),
                            'duration': dur, 'prediction': label, 'confidence': conf,
                            'blocked': 'Blocked' if label == "ATTACK" and settings.get("autoPreventionEnabled", False) and conf >= settings.get("threatThreshold", 0.8) else 'Not Blocked'
                        })
            batch_rows = []; batch_keys = []
            last_predict_time = time.time()

# ----------------------
# CLI & orchestration
# ----------------------
def main():
    global BATCH_SIZE, QUEUE_MAXSIZE, FLOW_DURATION_UNIT, packet_q

    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', type=str, help='Live interface name (Scapy)')
    parser.add_argument('--pcap', type=str, help='PCAP file path (offline)')
    parser.add_argument('--scaler', type=str, required=True, help='Path to scaler joblib')
    parser.add_argument('--model', type=str, required=True, help='Path to Keras model (.keras/.h5)')
    parser.add_argument('--flow-duration-micros', action='store_true', help='If set, report Flow Duration in microseconds')
    parser.add_argument('--batch-size', type=int, default=None, help='Batch size for model inference')
    parser.add_argument('--queue-max', type=int, default=None, help='Max queue size for packets')
    args = parser.parse_args()

    if args.batch_size is not None:
        BATCH_SIZE = args.batch_size
    if args.queue_max is not None:
        QUEUE_MAXSIZE = args.queue_max
        try:
            if packet_q.empty():
                packet_q = queue.Queue(maxsize=QUEUE_MAXSIZE)
        except Exception:
            pass
    if args.flow_duration_micros:
        FLOW_DURATION_UNIT = 1e6

    scaler = None
    model = None
    try:
        scaler = joblib.load(args.scaler)
        print("[INFO] Scaler loaded:", args.scaler)
    except Exception as e:
        print("[WARN] Could not load scaler:", e)
        scaler = None
    try:
        from tensorflow.keras.models import load_model
        model = load_model(args.model)
        print("[INFO] Keras model loaded:", args.model)
    except Exception as e:
        print("[WARN] Could not load Keras model:", e)
        model = None

    out_q = queue.Queue()
    fp = threading.Thread(target=flow_processor_worker, args=(out_q,), daemon=True)
    fp.start()

    inf = threading.Thread(target=inference_worker, args=(out_q, scaler, model, BATCH_SIZE), daemon=True)
    inf.start()

    cap_thread = None
    try:
        if args.pcap:
            print("[INFO] Reading pcap:", args.pcap)
            cap_thread = threading.Thread(target=pcap_reader_worker, args=(args.pcap,), daemon=True)
            cap_thread.start()
        elif args.iface:
            print("[INFO] Starting live capture on interface:", args.iface)
            cap_thread = threading.Thread(target=scapy_capture_worker, args=(args.iface,), daemon=True)
            cap_thread.start()
        else:
            print("Provide --pcap or --iface")
            return

        while cap_thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Interrupted by user.")
    finally:
        stop_event.set()
        try:
            packet_q.put(None)
        except:
            pass
        fp.join(timeout=3)
        out_q.put(None)
        inf.join(timeout=5)
        print("Shutdown complete.")

if __name__ == '__main__':
    main()