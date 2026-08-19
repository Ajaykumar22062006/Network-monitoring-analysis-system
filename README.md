# Network Monitoring Dashboard (Version 1)

Welcome to your **Network Monitoring Dashboard**! This application was designed specifically for networking students (like those in the Cisco Networking Academy) to connect theoretical concepts—like IPv4 addressing, MAC addresses, ICMP ping testing, and classful subnetting—with a real, working Python Flask application.

---

## Table of Contents
1. [Project Directory Structure](#project-directory-structure)
2. [How to Run the Application on Windows](#how-to-run-the-application-on-windows)
3. [File Explanations (How the Code Works)](#file-explanations-how-the-code-works)
4. [Networking Concepts Explained in Detail](#networking-concepts-explained-in-detail)
   - [1. IP Address (Logical Addressing)](#1-ip-address-logical-addressing)
   - [2. MAC Address (Physical Addressing)](#2-mac-address-physical-addressing)
   - [3. Ping & ICMP (Connectivity Diagnosis)](#3-ping--icmp-connectivity-diagnosis)
   - [4. Classful Routing & Subnet Masks](#4-classful-routing--subnet-masks)
   - [5. Network Address Computation](#5-network-address-computation)

---

## Project Directory Structure

```text
network-monitor/
├── app.py                   # Main Flask application file (database logic, routing, ping engine)
├── requirements.txt         # List of Python dependencies (Flask)
├── database/
│   └── network_monitor.db   # SQLite Database file (created automatically on startup)
├── static/
│   ├── css/
│   │   └── style.css        # Custom CSS for the user interface (slate colors, console styling)
│   └── js/
│       └── main.js          # JavaScript helper (handles async background checks on load)
├── templates/
│   ├── base.html            # Shared HTML layout structure (sidebar, alert panels, headers)
│   ├── dashboard.html       # Statistics cards and device registry list
│   ├── devices.html         # Inventory manager (adding, viewing, and deleting nodes)
│   ├── edit_device.html     # Modify settings for an existing device
│   ├── logs.html            # Audit trail viewer (shows database inserts, changes, ping logs)
│   ├── network_info.html    # Address class calculator and reference panel
│   └── ping.html            # Diagnostics CLI terminal console
└── README.md                # This learning documentation
```

---

## How to Run the Application on Windows

Follow these simple steps in your PowerShell or Command Prompt:

### 1. Navigate to the project directory
Make sure you are in the folder where `app.py` is saved:
```powershell
cd "c:\Users\ajay8\OneDrive\Desktop\networking project\network-monitor"
```

### 2. Install dependencies
Install Flask using pip:
```powershell
pip install -r requirements.txt
```

### 3. Run the application
Run the Python script:
```powershell
python app.py
```

### 4. Open in your web browser
You will see output indicating that Flask is running. Open your browser and navigate to:
```text
http://127.0.0.1:5000
```
*(Press `Ctrl + C` in the terminal to stop the application).*

---

## File Explanations (How the Code Works)

### 1. `app.py` (The Brain)
Written in Python using the **Flask** framework, this file acts as the backend server.
- **SQLite Database Integration (`sqlite3`)**: When the app starts, it checks if a database file exists. If not, it creates `network_monitor.db` and builds two tables: `devices` (holds names, IPs, MACs, and online/offline status) and `logs` (holds records of what you've done).
- **IP and MAC Validation**: Uses Python's library `ipaddress` to verify that any entered IP is a mathematically valid IPv4 address (e.g. four numbers between 0 and 255 separated by dots). It uses Regular Expressions (`re`) to make sure MAC addresses look like `00:11:22:33:44:55`.
- **Command execution (`subprocess`)**: To ping a device, Python launches a safe system ping process (`ping -n 1 -w 1000 <ip_address>`). Passing arguments in a Python list (e.g. `["ping", "-n", "1", ...]`) instead of a single string ensures no user can run dangerous hidden shell commands.
- **Routing**: Defines URL routes like `/dashboard`, `/devices`, and `/ping` to process request forms and return web templates.

### 2. `templates/` (The Face)
HTML files containing placeholders that Flask fills dynamically using the **Jinja2** template engine.
- `base.html` defines the overall layout (like the sidebar menu). Other pages (like `dashboard.html` or `ping.html`) "extend" the base file.
- Loops like `{% for device in devices %}` are used in Jinja to generate a table row for each device in your database automatically.

### 3. `static/css/style.css` (The Clothes)
Provides a premium dark theme styling.
- Uses a color palette inspired by professional network consoles (Slate Slate Blue, Emerald green for success, Ruby red for offline status).
- Styled console elements use standard fonts like Courier to look like a real terminal emulator screen.

### 4. `static/js/main.js` (The Nervous System)
Provides client-side actions.
- When you load the Dashboard, Javascript reads all the devices in the table. Instead of making the user wait for the page to load while Python pings 10 devices (which would take 10 seconds if they are offline!), Javascript fetches status for each device asynchronously via a background API.
- As the status replies arrive, Javascript updates the Online/Offline badges and increments the counter cards instantly!

---

## Networking Concepts Explained in Detail

### 1. IP Address (Logical Addressing)
An **IP (Internet Protocol) Address** is a logical identifier assigned to each device on a network.
- **IPv4 Format**: Consists of 32 bits divided into 4 octets (8 bits each), separated by dots (e.g., `192.168.1.50`). Each octet can have a decimal value from `0` to `255`.
- **Logical vs. Physical**: IP addresses are logical. A network administrator can change them, and they are used to route packets across different networks (at Layer 3 of the OSI model).

### 2. MAC Address (Physical Addressing)
A **MAC (Media Access Control) Address** is the permanent physical identifier burned into a device's Network Interface Card (NIC) during manufacturing.
- **Format**: A 48-bit address written in hexadecimal format (e.g., `00:11:22:33:44:55` or `00-11-22-33-44-55`).
- **Layer 2**: MAC addresses are used for communication on the local local network link (Layer 2 of the OSI model). While IP addresses direct packets *between* networks, MAC addresses deliver packets to the *specific physical device* on the local subnet.

### 3. Ping & ICMP (Connectivity Diagnosis)
**Ping** is a diagnostic tool used to test whether a host is reachable.
- **ICMP**: Ping uses the **Internet Control Message Protocol (ICMP)**.
- **Echo Request**: Your computer sends an ICMP Echo Request packet to the target IP.
- **Echo Reply**: If the target is online and its firewall doesn't block it, it responds with an ICMP Echo Reply.
- **Latency (Response Time)**: The time it takes for the packet to go to the target and come back (measured in milliseconds, `ms`).
- **Packet Loss**: If the request fails to return a reply, it is a lost packet. 100% packet loss means the device is completely offline or blocking ping messages.

### 4. Classful Routing & Subnet Masks
Before modern classless addressing (CIDR), the IPv4 address space was divided into **Classes** based on the first few bits of the IP address:

*   **Class A (First octet 1–126)**:
    *   Default Subnet Mask: `255.0.0.0` (/8).
    *   First 8 bits represent the Network, last 24 bits represent Hosts.
    *   Designed for massive networks.
*   **Class B (First octet 128–191)**:
    *   Default Subnet Mask: `255.255.0.0` (/16).
    *   First 16 bits represent the Network, last 16 bits represent Hosts.
*   **Class C (First octet 192–223)**:
    *   Default Subnet Mask: `255.255.255.0` (/24).
    *   First 24 bits represent the Network, last 8 bits represent Hosts.
    *   Ideal for home networks (e.g., `192.168.1.X`).
*   **Class D (First octet 224–239)**:
    *   No subnet mask. Reserved for **Multicasting** (sending data to multiple receivers simultaneously).
*   **Class E (First octet 240–255)**:
    *   No subnet mask. Reserved for experimental and research purposes.

*Note: The range starting with `127` (e.g., `127.0.0.1`) is a special loopback range reserved for testing local TCP/IP stack configuration.*

### 5. Network Address Computation
The **Network Address** represents the subnet itself and cannot be assigned to a host.
- **How it is calculated**: It is calculated by performing a logical bitwise AND operation between the binary representation of the IP Address and the Subnet Mask.
- **Example**:
  - IP Address: `192.168.1.50`
  - Subnet Mask: `255.255.255.0`
  - Network Address: `192.168.1.0` (Since the mask covers the first three octets completely, those numbers stay the same, while the host octet becomes `0`).
- Devices can only communicate directly with other devices on the same Network Address. If they want to send packets to a different Network Address, they must send them to a **Default Gateway** (a Router).
