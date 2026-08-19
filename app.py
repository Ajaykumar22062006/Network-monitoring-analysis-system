from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
import os
import re
import ipaddress
import subprocess
from utils.ip_utils import calculate_subnet
from utils.network_utils import get_arp_table


app = Flask(__name__)
# A secret key is required for Flask session flash messages
app.secret_key = 'network_monitor_dashboard_secret_key_v1'

DATABASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database')
DATABASE_PATH = os.path.join(DATABASE_DIR, 'network_monitor.db')

# Ensure the database directory exists
os.makedirs(DATABASE_DIR, exist_ok=True)

def get_db_connection():
    """
    Establishes a connection to the SQLite database.
    Using sqlite3.Row allows us to access columns by name like dictionary keys.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initializes the database by creating the required tables if they don't exist yet.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Check if devices table exists and has location column.
        # If not, drop it to migrate to the new columns cleanly.
        try:
            cursor.execute("PRAGMA table_info(devices)")
            columns = [info[1] for info in cursor.fetchall()]
            if columns and 'location' not in columns:
                cursor.execute("DROP TABLE devices")
        except sqlite3.OperationalError:
            pass
            
        # 1. Devices Table
        # Stores device configuration and the last known status
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_name TEXT NOT NULL,
                device_type TEXT NOT NULL, -- PC, Router, Switch, Server
                ip_address TEXT NOT NULL UNIQUE,
                mac_address TEXT NOT NULL,
                location TEXT NOT NULL,
                status TEXT DEFAULT 'Unknown', -- Online, Offline, Unknown
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Check if logs table exists and has target_details column.
        # If not, drop it to migrate to the new columns cleanly.
        try:
            cursor.execute("PRAGMA table_info(logs)")
            columns = [info[1] for info in cursor.fetchall()]
            if columns and 'target_details' not in columns:
                cursor.execute("DROP TABLE logs")
        except sqlite3.OperationalError:
            pass
            
        # 2. Logs Table
        # Stores audit trails for device changes and diagnostics tests
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                action TEXT NOT NULL, -- 'Device Added', 'Device Edited', 'Device Deleted', 'Ping Test', 'Subnet Calculation'
                target_details TEXT NOT NULL,
                result_status TEXT NOT NULL
            )
        ''')
        
        conn.commit()

# Run database initialization
init_db()

# ==========================================
# HELPERS (IP, MAC Validation & Subnetting)
# ==========================================

def validate_ip(ip_str):
    """
    Validates whether the provided string is a correct IPv4 address.
    Uses Python's built-in ipaddress module which is highly secure.
    """
    try:
        ipaddress.IPv4Address(ip_str.strip())
        return True
    except ValueError:
        return False

def validate_mac(mac_str):
    """
    Validates whether the MAC address conforms to standard notation.
    Accepts colons (e.g. 00:11:22:33:44:55) or hyphens (e.g. 00-11-22-33-44-55).
    """
    pattern = re.compile(r'^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$')
    return bool(pattern.match(mac_str.strip()))

def run_ping_command(ip_str):
    """
    Performs a safe, non-blocking ping test towards a target IP address.
    On Windows, the command used is: ping -n 1 -w 1000 <ip_address>
    - '-n 1' specifies sending only 1 echo request packet.
    - '-w 1000' specifies a timeout of 1000 milliseconds (1 second) to wait for replies.
    
    This command runs safely because:
    1. We validate the IP address structure beforehand.
    2. We pass arguments as a list to subprocess.run with shell=False, preventing command execution attacks.
    """
    ip_str = ip_str.strip()
    if not validate_ip(ip_str):
        return {
            "status": "Offline",
            "response_time": "N/A",
            "packet_loss": "100%",
            "error": "Invalid IP Address format.",
            "raw_output": "Error: Invalid IP Address format. Ping aborted."
        }
        
    try:
        # Run system ping command
        # shell=False is default, meaning the parameters list is passed directly to the OS API.
        # This prevents any terminal injection.
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "1000", ip_str],
            capture_output=True,
            text=True,
            timeout=3.0 # Guard timeout for the entire subprocess run
        )
        
        output = result.stdout
        
        # Analyze Windows ping output:
        # A successful ping response contains "Reply from <IP>:" and "TTL="
        # Example success: Reply from 127.0.0.1: bytes=32 time<1ms TTL=128
        # Example failure: Request timed out. OR Destination host unreachable.
        
        is_online = False
        response_time = "N/A"
        packet_loss = "100%"
        
        if "Reply from" in output and "TTL=" in output:
            is_online = True
            packet_loss = "0%"
            
            # Use regex to find response time (e.g., time=5ms or time<1ms)
            time_match = re.search(r'time[<=](\d+)ms', output)
            if time_match:
                response_time = f"{time_match.group(1)}ms"
            elif "time<1ms" in output:
                response_time = "<1ms"
        else:
            # Check if we can parse custom loss from output
            loss_match = re.search(r'\((\d+)% loss\)', output)
            if loss_match:
                packet_loss = f"{loss_match.group(1)}%"
            else:
                packet_loss = "100%"
                
        return {
            "status": "Online" if is_online else "Offline",
            "response_time": response_time,
            "packet_loss": packet_loss,
            "raw_output": output if output else "No output received from the ping command."
        }
        
    except subprocess.TimeoutExpired:
        return {
            "status": "Offline",
            "response_time": "N/A",
            "packet_loss": "100%",
            "error": "Ping command timed out.",
            "raw_output": "Error: Ping command timed out after 3.0 seconds."
        }
    except Exception as e:
        return {
            "status": "Offline",
            "response_time": "N/A",
            "packet_loss": "100%",
            "error": str(e),
            "raw_output": f"Error executing ping process: {str(e)}"
        }

def analyze_ip_classful(ip_str):
    """
    Computes networking details for a given IP address based on Classful Routing rules:
    - Class A: First Octet 1-126 (Default Subnet Mask: 255.0.0.0)
    - Class A (Loopback): First Octet 127 (Default Subnet Mask: 255.0.0.0)
    - Class B: First Octet 128-191 (Default Subnet Mask: 255.255.0.0)
    - Class C: First Octet 192-223 (Default Subnet Mask: 255.255.255.0)
    - Class D (Multicast): First Octet 224-239 (No subnet mask)
    - Class E (Experimental): First Octet 240-255 (No subnet mask)
    
    The network address is calculated using a bitwise AND between the IP and its subnet mask.
    """
    ip_str = ip_str.strip()
    if not validate_ip(ip_str):
        return None
        
    try:
        first_octet = int(ip_str.split('.')[0])
        
        if 1 <= first_octet <= 126:
            addr_class = "Class A"
            subnet_mask = "255.0.0.0"
        elif first_octet == 127:
            addr_class = "Class A (Loopback / Localhost)"
            subnet_mask = "255.0.0.0"
        elif 128 <= first_octet <= 191:
            addr_class = "Class B"
            subnet_mask = "255.255.0.0"
        elif 192 <= first_octet <= 223:
            addr_class = "Class C"
            subnet_mask = "255.255.255.0"
        elif 224 <= first_octet <= 239:
            addr_class = "Class D (Multicast addressing)"
            subnet_mask = "N/A"
        elif 240 <= first_octet <= 255:
            addr_class = "Class E (Experimental / Reserved)"
            subnet_mask = "N/A"
        else:
            addr_class = "Unknown"
            subnet_mask = "N/A"
            
        network_address = "N/A"
        if subnet_mask != "N/A":
            # Determine network address using ipaddress library
            interface = ipaddress.IPv4Interface(f"{ip_str}/{subnet_mask}")
            network_address = str(interface.network.network_address)
            
        return {
            "ip": ip_str,
            "class": addr_class,
            "subnet_mask": subnet_mask,
            "network_address": network_address
        }
    except Exception:
        return None

def log_action(action, target_details, result_status):
    """
    Helper function to record system actions inside the database log.
    """
    try:
        with get_db_connection() as conn:
            conn.execute(
                'INSERT INTO logs (action, target_details, result_status) VALUES (?, ?, ?)',
                (action, target_details, result_status)
            )
            conn.commit()
    except Exception as e:
        print(f"Error logging action: {e}")

# ==========================================
# FLASK WEB ROUTES
# ==========================================

@app.route('/')
@app.route('/dashboard')
def dashboard():
    """
    Loads the Dashboard page.
    Fetches the total, online, and offline counts from local device cache state,
    and forwards devices list to dashboard.html template.
    """
    with get_db_connection() as conn:
        devices = conn.execute('SELECT * FROM devices').fetchall()
        
        # Calculate totals
        total_devices = len(devices)
        online_devices = sum(1 for d in devices if d['status'] == 'Online')
        offline_devices = sum(1 for d in devices if d['status'] == 'Offline')
        
    return render_template(
        'dashboard.html',
        devices=devices,
        total_devices=total_devices,
        online_devices=online_devices,
        offline_devices=offline_devices,
        active_page='dashboard'
    )

@app.route('/devices')
def devices_list():
    """
    View all devices. Displays the devices list in a structured table.
    """
    with get_db_connection() as conn:
        devices = conn.execute('SELECT * FROM devices').fetchall()
    return render_template('devices.html', devices=devices, active_page='devices')

@app.route('/devices/add', methods=['POST'])
def add_device():
    """
    Endpoint for adding a new device configuration to the database.
    Validates form data prior to insertion.
    """
    name = request.form.get('name', '').strip()
    device_type = request.form.get('type', '').strip()
    ip_address = request.form.get('ip_address', '').strip()
    mac_address = request.form.get('mac_address', '').strip()
    location = request.form.get('location', '').strip()
    
    # Validation checks
    if not name or not device_type or not ip_address or not mac_address or not location:
        flash("All fields are required.", "danger")
        return redirect(url_for('devices_list'))
        
    if device_type not in ['PC', 'Router', 'Switch', 'Server']:
        flash("Invalid Device Type selected.", "danger")
        return redirect(url_for('devices_list'))
        
    if not validate_ip(ip_address):
        flash(f"'{ip_address}' is not a valid IPv4 address.", "danger")
        return redirect(url_for('devices_list'))
        
    if not validate_mac(mac_address):
        flash(f"'{mac_address}' is not a valid MAC address structure. Use (XX:XX:XX:XX:XX:XX) format.", "danger")
        return redirect(url_for('devices_list'))
        
    try:
        with get_db_connection() as conn:
            conn.execute(
                'INSERT INTO devices (device_name, device_type, ip_address, mac_address, location, status) VALUES (?, ?, ?, ?, ?, ?)',
                (name, device_type, ip_address, mac_address, location, 'Unknown')
            )
            conn.commit()
            
        flash(f"Device '{name}' ({ip_address}) added successfully!", "success")
        log_action('Device Added', f"Name: {name} | IP: {ip_address} | Type: {device_type} | Location: {location}", 'SUCCESS')
        
    except sqlite3.IntegrityError:
        flash(f"An error occurred. The IP Address '{ip_address}' is already registered.", "danger")
        
    return redirect(url_for('devices_list'))

@app.route('/devices/edit/<int:device_id>', methods=['GET', 'POST'])
def edit_device(device_id):
    """
    Allows editing details of an existing device configuration.
    """
    with get_db_connection() as conn:
        device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
        
    if not device:
        flash("Device not found.", "danger")
        return redirect(url_for('devices_list'))
        
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        device_type = request.form.get('type', '').strip()
        ip_address = request.form.get('ip_address', '').strip()
        mac_address = request.form.get('mac_address', '').strip()
        location = request.form.get('location', '').strip()
        
        if not name or not device_type or not ip_address or not mac_address or not location:
            flash("All fields are required.", "danger")
            return render_template('edit_device.html', device=device, active_page='devices')
            
        if device_type not in ['PC', 'Router', 'Switch', 'Server']:
            flash("Invalid Device Type selected.", "danger")
            return render_template('edit_device.html', device=device, active_page='devices')
            
        if not validate_ip(ip_address):
            flash(f"'{ip_address}' is not a valid IPv4 address.", "danger")
            return render_template('edit_device.html', device=device, active_page='devices')
            
        if not validate_mac(mac_address):
            flash(f"'{mac_address}' is not a valid MAC address structure. Use (XX:XX:XX:XX:XX:XX) format.", "danger")
            return render_template('edit_device.html', device=device, active_page='devices')
            
        try:
            with get_db_connection() as conn:
                conn.execute(
                    'UPDATE devices SET device_name = ?, device_type = ?, ip_address = ?, mac_address = ?, location = ? WHERE id = ?',
                    (name, device_type, ip_address, mac_address, location, device_id)
                )
                conn.commit()
                
            flash(f"Device '{name}' updated successfully!", "success")
            log_action('Device Edited', f"ID: {device_id} | Name: {name} | IP: {ip_address} | Type: {device_type} | Location: {location}", 'SUCCESS')
            return redirect(url_for('devices_list'))
            
        except sqlite3.IntegrityError:
            flash(f"Update failed. The IP address '{ip_address}' is already assigned to another device.", "danger")
            
    return render_template('edit_device.html', device=device, active_page='devices')

@app.route('/devices/delete/<int:device_id>', methods=['POST'])
def delete_device(device_id):
    """
    Deletes a device configuration from the database.
    """
    with get_db_connection() as conn:
        device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
        
    if not device:
        flash("Device not found.", "danger")
        return redirect(url_for('devices_list'))
        
    with get_db_connection() as conn:
        conn.execute('DELETE FROM devices WHERE id = ?', (device_id,))
        conn.commit()
        
    flash(f"Device '{device['device_name']}' ({device['ip_address']}) deleted.", "success")
    log_action('Device Deleted', f"Name: {device['device_name']} | IP: {device['ip_address']}", 'SUCCESS')
    return redirect(url_for('devices_list'))

# ==========================================
# DIAGNOSTICS & NETWORK CALCULATOR ROUTES
# ==========================================

@app.route('/ping', methods=['GET', 'POST'])
def ping_tool():
    """
    Standard Ping utility tool route.
    Allows manual IP entry to perform single diagnostics pings.
    """
    result = None
    ip_to_test = ""
    
    if request.method == 'POST':
        ip_to_test = request.form.get('ip_address', '').strip()
        
        if not ip_to_test:
            flash("Please enter an IP Address.", "warning")
        elif not validate_ip(ip_to_test):
            flash("Please enter a valid IPv4 address.", "danger")
        else:
            # Perform ping check
            ping_data = run_ping_command(ip_to_test)
            result = ping_data
            
            # Log results in database
            status = "SUCCESS" if ping_data['status'] == "Online" else "FAILED"
            res_time = ping_data.get('response_time', 'N/A')
            packet_loss = ping_data.get('packet_loss', '100%')
            result_parts = [status]
            if res_time and res_time != "N/A":
                result_parts.append(f"Latency: {res_time}")
            if packet_loss:
                result_parts.append(f"Loss: {packet_loss}")
            result_str = " | ".join(result_parts)
            log_action('Ping Test', ip_to_test, result_str)
            
    return render_template('ping.html', result=result, ip_address=ip_to_test, active_page='ping')

@app.route('/network-info', methods=['GET', 'POST'])
def network_info():
    """
    Subnet and Address class calculator.
    Processes user input address to output Class, mask, network, broadcast, hosts, binary.
    """
    result = None
    ip_to_test = ""
    mask_or_cidr = ""
    
    if request.method == 'POST':
        ip_to_test = request.form.get('ip_address', '').strip()
        mask_or_cidr = request.form.get('mask_or_cidr', '').strip()
        
        if not ip_to_test or not mask_or_cidr:
            flash("Please enter both the IP Address and the Subnet Mask or CIDR Prefix.", "warning")
        else:
            try:
                result = calculate_subnet(ip_to_test, mask_or_cidr)
                log_action(
                    'Subnet Calculation',
                    f"IP: {ip_to_test} | Mask/CIDR: {mask_or_cidr}",
                    f"Network: {result['network_address']} | Broadcast: {result['broadcast_address']}"
                )
            except ValueError as e:
                flash(str(e), "danger")
                
    return render_template(
        'network_info.html', 
        result=result, 
        ip_address=ip_to_test, 
        mask_or_cidr=mask_or_cidr, 
        active_page='network-info'
    )

@app.route('/arp-analysis', methods=['GET', 'POST'])
def arp_analysis():
    """
    ARP Table Analysis route.
    Runs system 'arp -a' and displays entries.
    Records scan events in SQLite logs.
    """
    entries = []
    try:
        entries = get_arp_table()
        log_action('ARP_SCAN', 'System ARP Table Scan', f'{len(entries)} entries found')
        if request.method == 'POST':
            flash(f"ARP table scanned successfully! Found {len(entries)} entries.", "success")
    except Exception as e:
        flash(f"Failed to scan ARP table: {str(e)}", "danger")
        log_action('ARP_SCAN', 'System ARP Table Scan Failed', str(e))
        
    return render_template(
        'arp_analysis.html',
        entries=entries,
        active_page='arp-analysis'
    )

@app.route('/logs')
def logs_view():
    """
    View list of system and network actions stored in SQLite audit trail.
    """
    with get_db_connection() as conn:
        logs = conn.execute('SELECT * FROM logs ORDER BY id DESC').fetchall()
    return render_template('logs.html', logs=logs, active_page='logs')

@app.route('/logs/clear', methods=['POST'])
def clear_logs():
    """
    Deletes all logs from the SQLite database.
    """
    try:
        with get_db_connection() as conn:
            conn.execute('DELETE FROM logs')
            conn.commit()
        flash("All logs have been cleared successfully.", "success")
    except Exception as e:
        flash(f"Error clearing logs: {str(e)}", "danger")
    return redirect(url_for('logs_view'))

# ==========================================
# ASYNC STATUS API FOR DASHBOARD (AJAX)
# ==========================================

@app.route('/api/ping_device/<int:device_id>')
def api_ping_device(device_id):
    """
    API endpoint invoked asynchronously by dashboard JavaScript.
    Runs ping command on the device, updates its database status, and logs it.
    Returns status, latency, and packet loss in a JSON payload.
    """
    with get_db_connection() as conn:
        device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
        
    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404
        
    # Execute ping
    ping_data = run_ping_command(device['ip_address'])
    
    # Save the updated status back to database
    with get_db_connection() as conn:
        conn.execute(
            'UPDATE devices SET status = ? WHERE id = ?',
            (ping_data['status'], device_id)
        )
        conn.commit()
        
    # Log the automated check in the logs table
    status = "SUCCESS" if ping_data['status'] == "Online" else "FAILED"
    res_time = ping_data.get('response_time', 'N/A')
    packet_loss = ping_data.get('packet_loss', '100%')
    result_parts = [status]
    if res_time and res_time != "N/A":
        result_parts.append(f"Latency: {res_time}")
    if packet_loss:
        result_parts.append(f"Loss: {packet_loss}")
    result_str = " | ".join(result_parts)
    log_action('Automated Ping', f"Device: {device['device_name']} (IP: {device['ip_address']})", result_str)
    
    return jsonify({
        "success": True,
        "device_id": device_id,
        "status": ping_data['status'],
        "response_time": ping_data['response_time'],
        "packet_loss": ping_data['packet_loss']
    })

if __name__ == '__main__':
    # Start local web development server on port 5000
    # Enable debugging during construction to easily trace stack traces.
    print(f"Network Monitor V1 Initialized.")
    print(f"Database located at: {DATABASE_PATH}")
    app.run(host='127.0.0.1', port=5000, debug=True)
