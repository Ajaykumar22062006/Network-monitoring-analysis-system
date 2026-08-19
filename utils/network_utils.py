import subprocess
import re
import os

def get_arp_table():
    """
    Executes 'arp -a' on Windows and parses the output.
    Returns a list of dicts: [
        {
            "interface": "10.235.239.40",
            "ip_address": "10.235.239.8",
            "mac_address": "56-93-46-66-06-97",
            "type": "Dynamic"
        },
        ...
    ]
    """
    try:
        # Run system arp -a command safely (shell=False by default)
        # Using encoding="oem" to handle Windows system encoding correctly
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            encoding="oem",
            timeout=5.0
        )
        
        if result.returncode != 0:
            raise Exception(f"Command returned non-zero code {result.returncode}. Error: {result.stderr}")
            
        output = result.stdout
        if not output:
            return []
            
        entries = []
        current_interface = None
        
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
                
            # Parse interface header, e.g. "Interface: 10.235.239.40 --- 0xb"
            if line.startswith("Interface:"):
                match = re.match(r'Interface:\s*([0-9.]+)\s*---', line)
                if match:
                    current_interface = match.group(1)
                else:
                    current_interface = "Unknown"
                continue
                
            # Skip header lines
            if "Internet Address" in line or "Physical Address" in line:
                continue
                
            # Match entry rows, e.g. "10.235.239.8          56-93-46-66-06-97     dynamic"
            parts = line.split()
            if len(parts) == 3:
                ip, mac, entry_type = parts
                # Keep matching entries
                entries.append({
                    "interface": current_interface or "Unknown",
                    "ip_address": ip,
                    "mac_address": mac,
                    "type": entry_type.capitalize()
                })
                
        return entries
        
    except subprocess.TimeoutExpired:
        raise Exception("The arp command timed out.")
    except FileNotFoundError:
        raise Exception("The 'arp' executable was not found on this system.")
    except Exception as e:
        raise Exception(f"Failed to scan ARP table: {str(e)}")
