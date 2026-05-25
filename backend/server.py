from flask import Flask, jsonify, request
from flask_cors import CORS
import csv
import os
import logging
import subprocess
import psutil
import signal
import time
import platform
import threading
import json
from datetime import datetime, timedelta
try:
    import wmi
    import pythoncom
except ImportError:
    wmi = None
    pythoncom = None
app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:3001",
            "http://127.0.0.1:3001"
        ],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})


logging.basicConfig(level=logging.DEBUG)

# Global variables
capture_process = None
ATTACK_LOG_FILE = "predictions_log.csv"
BLOCK_LOG_FILE = "prevention_log.csv"
PREVENTION_ACTIONS_FILE = "prevention_actions.csv"
PREVENTION_SETTINGS_FILE = "prevention_settings.json"

# Default prevention settings
DEFAULT_PREVENTION_SETTINGS = {
    "autoPreventionEnabled": True,
    "blockDuration": 600,
    "threatThreshold": 0.8
}

# Global variables for network monitoring
last_network_stats = None
last_network_time = None

def get_network_bandwidth():
    """Calculate real network bandwidth usage."""
    global last_network_stats, last_network_time
    
    try:
        current_stats = psutil.net_io_counters()
        current_time = time.time()
        
        if last_network_stats is not None and last_network_time is not None:
            # Calculate time difference
            time_delta = current_time - last_network_time
            
            if time_delta > 0:
                # Calculate bytes per second
                bytes_sent_per_sec = (current_stats.bytes_sent - last_network_stats.bytes_sent) / time_delta
                bytes_recv_per_sec = (current_stats.bytes_recv - last_network_stats.bytes_recv) / time_delta
                
                # Total bandwidth in Mbps
                total_bandwidth = (bytes_sent_per_sec + bytes_recv_per_sec) * 8 / 1024 / 1024
                
                # Update last stats
                last_network_stats = current_stats
                last_network_time = current_time
                
                return round(total_bandwidth, 2)
        
        # Initialize for first run
        last_network_stats = current_stats
        last_network_time = current_time
        return 0.0
        
    except Exception as e:
        logging.error(f"Error calculating bandwidth: {e}")
        return 0.0

def get_cpu_temperature():
    """
    Returns the CPU temperature in Celsius.
    Uses psutil as the primary method, with WMI as a fallback for Windows.
    """
    temperature = 0.0
    
    # Try using psutil.sensors_temperatures() first (Linux, macOS)
    if hasattr(psutil, "sensors_temperatures"):
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                # Look for a relevant temperature sensor
                for name, entries in temps.items():
                    for entry in entries:
                        if "cpu" in name.lower() or "core" in name.lower():
                            temperature = entry.current
                            return temperature
            # Fallback if no specific CPU sensor is found
            for key in ['cpu-thermal', 'coretemp']:
                if key in temps:
                    temperature = temps[key][0].current
                    return temperature
        except Exception as e:
            logging.error(f"Error getting temperature with psutil: {str(e)}")

    # Fallback for Windows using WMI
    if platform.system() == 'Windows' and wmi:
        try:
            pythoncom.CoInitialize()
            w = wmi.WMI(namespace="root\\wmi")
            temp_sensors = w.MSAcpi_ThermalZoneTemperature()
            if temp_sensors:
                # The temperature is returned in tenths of a degree Kelvin.
                temp_kelvin = temp_sensors[0].CurrentTemperature / 10.0
                temperature = temp_kelvin - 273.15
                return temperature
        except Exception as e:
            logging.error(f"Error getting temperature with WMI: {str(e)}")
        finally:
            pythoncom.CoUninitialize()
    
    # Final fallback if all methods fail
    return temperature

def log_subprocess_output(pipe, level=logging.INFO):
    """Thread function to log subprocess output."""
    for line in iter(pipe.readline, ''):
        if line.strip():
            logging.log(level, f"[CAPTURE] {line.rstrip()}")

def load_prevention_settings():
    """Load prevention settings from file or return defaults."""
    try:
        if os.path.exists(PREVENTION_SETTINGS_FILE):
            with open(PREVENTION_SETTINGS_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logging.error(f"Error loading prevention settings: {e}")
    return DEFAULT_PREVENTION_SETTINGS.copy()

def save_prevention_settings(settings):
    """Save prevention settings to file."""
    try:
        with open(PREVENTION_SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=2)
        return True
    except Exception as e:
        logging.error(f"Error saving prevention settings: {e}")
        return False

def log_prevention_action(ip, action, reason, duration=0, status='active'):
    """Log prevention action to CSV file."""
    try:
        action_id = str(int(time.time() * 1000))
        timestamp = datetime.now().isoformat()
        expires_at = (datetime.now() + timedelta(seconds=duration)).isoformat() if duration > 0 else None
        
        # Ensure CSV file exists with headers
        if not os.path.exists(PREVENTION_ACTIONS_FILE):
            with open(PREVENTION_ACTIONS_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['id', 'timestamp', 'ip', 'action', 'reason', 'duration', 'status', 'expires_at'])
        
        # Append new action
        with open(PREVENTION_ACTIONS_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([action_id, timestamp, ip, action, reason, duration, status, expires_at])
        
        logging.info(f"Prevention action logged: {action} for IP {ip}")
        return action_id
    except Exception as e:
        logging.error(f"Error logging prevention action: {e}")
        return None

def update_prevention_action_status(ip, new_status):
    """Update the status of a prevention action for a specific IP."""
    try:
        if not os.path.exists(PREVENTION_ACTIONS_FILE):
            return False
        
        # Read all actions
        actions = []
        updated = False
        with open(PREVENTION_ACTIONS_FILE, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Update all active actions for this specific IP
                if row['ip'] == ip and row['status'] == 'active':
                    row['status'] = new_status
                    updated = True
                    logging.info(f"Updated prevention action status for IP {ip} to {new_status}")
                actions.append(row)
        
        # Write back updated actions if any changes were made
        if updated and actions:
            with open(PREVENTION_ACTIONS_FILE, 'w', newline='') as f:
                fieldnames = ['id', 'timestamp', 'ip', 'action', 'reason', 'duration', 'status', 'expires_at']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(actions)
        
        return updated
    except Exception as e:
        logging.error(f"Error updating prevention action status for IP {ip}: {e}")
        return False

def get_prevention_actions():
    """Get all prevention actions from CSV file."""
    actions = []
    try:
        if os.path.exists(PREVENTION_ACTIONS_FILE):
            with open(PREVENTION_ACTIONS_FILE, 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Check if action has expired
                    if row['expires_at'] and row['status'] == 'active':
                        expires_at = datetime.fromisoformat(row['expires_at'])
                        if datetime.now() > expires_at:
                            row['status'] = 'expired'
                    
                    actions.append({
                        'id': row['id'],
                        'timestamp': row['timestamp'],
                        'ip': row['ip'],
                        'action': row['action'],
                        'reason': row['reason'],
                        'duration': int(row['duration']),
                        'status': row['status'],
                        'expiresAt': row.get('expires_at')
                    })
    except Exception as e:
        logging.error(f"Error reading prevention actions: {e}")
    
    return actions

# Existing endpoints
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    csv_path = "predictions_log.csv"
    alerts = []
    try:
        if os.path.exists(csv_path) and os.path.getsize(csv_path) > 0:
            with open(csv_path, 'r', newline='') as fh:
                reader = csv.DictReader(fh)
                logging.debug(f"CSV headers: {reader.fieldnames}")
                for row in reader:
                    try:
                        alerts.append({
                            'timestamp': row['timestamp'],
                            'flow_key': row['flow_key'],
                            'src_ip': row['src_ip'],
                            'dst_ip': row['dst_ip'],
                            'src_port': int(row['src_port']),
                            'dst_port': int(row['dst_port']),
                            'duration': float(row['duration']),
                            'prediction': row['prediction'],
                            'confidence': float(row['confidence']),
                            'autoBlockEnabled': row.get('blocked', 'Not Blocked')
                        })
                    except (ValueError, KeyError) as e:
                        logging.error(f"Error parsing row {row}: {str(e)}")
                        continue
        else:
            logging.warning("No alerts available or CSV is empty")
            return jsonify([]), 200
    except Exception as e:
        logging.error(f"Server error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
    logging.debug(f"Returning {len(alerts)} alerts")
    return jsonify(alerts), 200

@app.route('/api/status', methods=['GET'])
def get_status():
    global capture_process
    engine_status = 'Online' if capture_process and capture_process.poll() is None else 'Offline'
    
    # Get system metrics
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory().percent
        temperature = get_cpu_temperature()
    except Exception as e:
        logging.error(f"Error getting system metrics: {str(e)}")
        cpu = 0.0
        memory = 0.0
        temperature = 0.0

    # Count threats from CSV
    csv_path = "predictions_log.csv"
    threats = 0
    packets = 0
    unique_connections = set()
    
    try:
        if os.path.exists(csv_path) and os.path.getsize(csv_path) > 0:
            with open(csv_path, 'r', newline='') as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    packets += 1
                    # Use a tuple of src_ip and src_port to define a unique connection
                    unique_connections.add((row.get('src_ip'), row.get('src_port')))
                    if row.get('prediction') == 'ATTACK':
                        threats += 1
    except Exception as e:
        logging.error(f"Error reading status from CSV: {str(e)}")
        
    connections = len(unique_connections)

    return jsonify({
        'engine': engine_status,
        'threats': threats,
        'packets': packets,
        'connections': connections,
        'cpu': cpu,
        'memory': memory,
        'bandwidth': get_network_bandwidth(),
        'temperature': temperature
    }), 200

@app.route('/api/start', methods=['POST', 'OPTIONS'])
def start_monitoring():
    if request.method == 'OPTIONS':
        return '', 200
        
    global capture_process
    
    if capture_process is not None and capture_process.poll() is None:
        return jsonify({'message': 'Monitoring already running'}), 400
    
    try:
        venv_python = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'venv', 'Scripts', 'python.exe')
        capture_process = subprocess.Popen(
            [venv_python, 'capture_heavy.py', '--iface', 'Intel(R) Dual Band Wireless-AC 8260', '--scaler', 'models/dl_scaler4.joblib', '--model', 'models/dl_model4.keras'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=os.path.dirname(os.path.abspath(__file__))
        )
        threading.Thread(target=log_subprocess_output, args=(capture_process.stdout, logging.INFO), daemon=True).start()
        threading.Thread(target=log_subprocess_output, args=(capture_process.stderr, logging.ERROR), daemon=True).start()
        logging.info(f"Monitoring started with process ID: {capture_process.pid}")
        return jsonify({'message': 'Monitoring started', 'pid': capture_process.pid}), 200
    except Exception as e:
        logging.error(f"Failed to start monitoring: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop', methods=['POST', 'OPTIONS'])
def stop_monitoring():
    if request.method == 'OPTIONS':
        return '', 200
        
    global capture_process
    if capture_process is None or capture_process.poll() is not None:
        return jsonify({'message': 'No monitoring process running'}), 400
    try:
        process = psutil.Process(capture_process.pid)
        for child in process.children(recursive=True):
            child.send_signal(signal.SIGTERM)
        process.send_signal(signal.SIGTERM)
        capture_process.wait(timeout=5)
        logging.info(f"Monitoring stopped for process ID: {capture_process.pid}")
        capture_process = None
        return jsonify({'message': 'Monitoring stopped'}), 200
    except Exception as e:
        logging.error(f"Failed to stop monitoring: {str(e)}")
        return jsonify({'error': str(e)}), 500

# New Prevention System Endpoints
@app.route('/api/prevention/actions', methods=['GET'])
def get_prevention_actions_endpoint():
    """Get all prevention actions."""
    try:
        actions = get_prevention_actions()
        return jsonify(actions), 200
    except Exception as e:
        logging.error(f"Error fetching prevention actions: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/prevention/block', methods=['POST', 'OPTIONS'])
def block_ip_endpoint():
    """Block an IP address."""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        ip = data.get('ip')
        duration = data.get('duration', 600)
        reason = data.get('reason', 'Manual block')

        if not ip:
            return jsonify({'error': 'No IP provided'}), 400

        # Windows firewall command to block IP - use consistent naming
        cmd = f'netsh advfirewall firewall add rule name="BlockIP_{ip}" dir=in action=block remoteip={ip}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Log the prevention action
            action_id = log_prevention_action(ip, 'IP_BLOCKED', reason, duration, 'active')
            
            if action_id:
                logging.info(f"Successfully blocked IP: {ip} for {duration} seconds")
                return jsonify({
                    'message': f'IP {ip} has been blocked successfully for {duration} seconds', 
                    'action_id': action_id
                }), 200
            else:
                return jsonify({'error': 'Failed to log prevention action'}), 500
        else:
            logging.error(f"Failed to block IP {ip}: {result.stderr}")
            return jsonify({'error': f'Failed to block IP: {result.stderr}'}), 500

    except Exception as e:
        logging.error(f"Error in block_ip_endpoint: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/prevention/unblock', methods=['POST', 'OPTIONS'])
def unblock_ip_endpoint():
    """Unblock an IP address."""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        ip = data.get('ip')

        if not ip:
            return jsonify({'error': 'No IP provided'}), 400

        # Windows firewall command to remove the specific block rule
        # Use the exact same rule name format as when blocking
        cmd = f'netsh advfirewall firewall delete rule name="BlockIP_{ip}"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Update prevention action status
            success = update_prevention_action_status(ip, 'manually_unblocked')
            
            logging.info(f"Successfully unblocked IP: {ip}")
            return jsonify({'message': f'IP {ip} has been unblocked successfully'}), 200
        else:
            # Even if the firewall command fails, try to update the status
            # (the rule might not exist but we should still update our records)
            update_prevention_action_status(ip, 'manually_unblocked')
            
            logging.warning(f"Firewall rule for IP {ip} might not exist: {result.stderr}")
            # Still return success since the IP is effectively unblocked
            return jsonify({'message': f'IP {ip} unblock attempted (rule may not have existed)'}), 200

    except Exception as e:
        logging.error(f"Error in unblock_ip_endpoint: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/prevention/settings', methods=['GET', 'POST', 'OPTIONS'])
def prevention_settings_endpoint():
    """Get or update prevention settings."""
    if request.method == 'OPTIONS':
        return '', 200
    
    if request.method == 'GET':
        try:
            settings = load_prevention_settings()
            return jsonify(settings), 200
        except Exception as e:
            logging.error(f"Error loading prevention settings: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            
            # Validate settings
            required_fields = ['autoPreventionEnabled', 'blockDuration', 'threatThreshold']
            for field in required_fields:
                if field not in data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400
            
            # Save settings
            if save_prevention_settings(data):
                logging.info("Prevention settings updated successfully")
                return jsonify({'message': 'Settings updated successfully'}), 200
            else:
                return jsonify({'error': 'Failed to save settings'}), 500
                
        except Exception as e:
            logging.error(f"Error updating prevention settings: {e}")
            return jsonify({'error': str(e)}), 500

# Legacy endpoints for backward compatibility
@app.route('/api/preventions', methods=['GET'])
def get_preventions():
    path = "prevention_log.csv"
    actions = []
    if os.path.exists(path):
        with open(path, "r") as f:
            reader = csv.reader(f)
            for row in reader:
                actions.append({"timestamp": row[0], "ip": row[1], "action": row[2]})
    return jsonify(actions), 200

@app.route("/api/get_attacks", methods=["GET"])
def get_attacks():
    try:
        attacks = []
        with open(ATTACK_LOG_FILE, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                attacks.append({
                    "time": row.get("timestamp", ""),
                    "src_ip": row.get("src_ip", ""),
                    "dst_ip": row.get("dst_ip", ""),
                    "confidence": float(row.get("confidence", 0)),
                    "label": row.get("prediction", "")
                })
        return jsonify(attacks), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/block_ip", methods=["POST"])
def block_ip():
    try:
        data = request.get_json()
        ip = data.get("ip")

        if not ip:
            return jsonify({"error": "No IP provided"}), 400

        cmd = f'netsh advfirewall firewall add rule name="BlockIP_{ip}" dir=in action=block remoteip={ip}'
        subprocess.run(cmd, shell=True, check=True)

        return jsonify({"message": f"IP {ip} has been blocked successfully"}), 200

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Failed to block IP: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Ensure data directory and files exist
    os.makedirs('data', exist_ok=True)
    
    # Initialize prevention settings file if it doesn't exist
    
    
    print("=" * 50)
    print("AI-Powered Cyber Threat Dashboard Backend")
    print("=" * 50)
    print(f"Server starting on http://localhost:5000")
    print(f"API endpoints:")
    print(f"  GET  /api/alerts                    - Get security alerts")
    print(f"  GET  /api/status                    - Get system status")
    print(f"  POST /api/start                     - Start monitoring")
    print(f"  POST /api/stop                      - Stop monitoring")
    print(f"  GET  /api/prevention/actions        - Get prevention actions")
    print(f"  POST /api/prevention/block          - Block IP address")
    print(f"  POST /api/prevention/unblock        - Unblock IP address")
    print(f"  GET  /api/prevention/settings       - Get prevention settings")
    print(f"  POST /api/prevention/settings       - Update prevention settings")
    print("=" * 50)
    
    app.run(debug=True, host='0.0.0.0', port=5000)