import ipaddress

def ip_to_binary(ip_str):
    """
    Converts a dotted-decimal IP address into its binary representation.
    Example: 192.168.1.1 -> 11000000.10101000.00000001.00000001
    """
    try:
        octets = ip_str.split('.')
        binary_octets = [format(int(octet), '08b') for octet in octets]
        return ".".join(binary_octets)
    except Exception:
        return "N/A"

def calculate_subnet(ip_str, mask_or_cidr):
    """
    Validates and calculates IPv4 subnet parameters.
    Supports mask_or_cidr as a CIDR prefix (e.g. "24", "/24") or a Subnet Mask (e.g. "255.255.255.0").
    
    Returns a dictionary of calculated parameters on success, or raises ValueError on validation error.
    """
    ip_str = ip_str.strip()
    mask_or_cidr = mask_or_cidr.strip()
    
    # 1. Validate IP address format
    try:
        ip = ipaddress.IPv4Address(ip_str)
    except ValueError:
        raise ValueError(f"'{ip_str}' is not a valid IPv4 address. Each octet must be between 0 and 255.")

    # 2. Parse and Validate CIDR Prefix / Subnet Mask
    cidr_val = None
    
    # Check if input is CIDR notation (e.g., /24 or 24)
    cidr_clean = mask_or_cidr[1:] if mask_or_cidr.startswith('/') else mask_or_cidr
    
    if cidr_clean.isdigit():
        cidr_val = int(cidr_clean)
        if not (0 <= cidr_val <= 32):
            raise ValueError(f"CIDR prefix '/{cidr_val}' is invalid. It must be between 0 and 32.")
        subnet_mask_str = str(ipaddress.IPv4Network(f"0.0.0.0/{cidr_val}").netmask)
    else:
        # Check if input is a valid Subnet Mask (e.g., 255.255.255.0)
        try:
            # We construct a network with wild IP and this mask to see if the mask is valid
            test_net = ipaddress.IPv4Network(f"0.0.0.0/{cidr_clean}", strict=False)
            cidr_val = test_net.prefixlen
            subnet_mask_str = cidr_clean
        except ValueError:
            raise ValueError(f"'{mask_or_cidr}' is not a valid Subnet Mask or CIDR prefix.")

    # 3. Perform Subnet Calculations using ipaddress library
    # strict=False allows passing host IPs instead of requiring strict network addresses
    network_input = f"{ip_str}/{cidr_val}"
    net = ipaddress.IPv4Network(network_input, strict=False)
    
    network_address = str(net.network_address)
    broadcast_address = str(net.broadcast_address)
    total_addresses = net.num_addresses
    
    # Usable host range and counts
    hosts = list(net.hosts())
    
    if cidr_val == 32:
        # Single Host Subnet
        first_usable = ip_str
        last_usable = ip_str
        usable_hosts_count = 1
    elif cidr_val == 31:
        # Point-to-Point Subnet (RFC 3021)
        first_usable = network_address
        last_usable = broadcast_address
        usable_hosts_count = 2
    else:
        if hosts:
            first_usable = str(hosts[0])
            last_usable = str(hosts[-1])
            usable_hosts_count = len(hosts)
        else:
            first_usable = "N/A"
            last_usable = "N/A"
            usable_hosts_count = 0

    # 4. Determine Classful Addressing Category
    first_octet = int(ip_str.split('.')[0])
    if 1 <= first_octet <= 126:
        addr_class = "A"
    elif first_octet == 127:
        addr_class = "A (Loopback / Localhost)"
    elif 128 <= first_octet <= 191:
        addr_class = "B"
    elif 192 <= first_octet <= 223:
        addr_class = "C"
    elif 224 <= first_octet <= 239:
        addr_class = "D (Multicast)"
    elif 240 <= first_octet <= 255:
        addr_class = "E (Experimental / Reserved)"
    else:
        addr_class = "Unknown"

    # 5. Build Dotted Binary Output
    ip_binary = ip_to_binary(ip_str)
    mask_binary = ip_to_binary(subnet_mask_str)
    network_binary = ip_to_binary(network_address)
    broadcast_binary = ip_to_binary(broadcast_address)

    return {
        "ip": ip_str,
        "cidr": f"/{cidr_val}",
        "subnet_mask": subnet_mask_str,
        "network_address": network_address,
        "broadcast_address": broadcast_address,
        "first_usable": first_usable,
        "last_usable": last_usable,
        "total_addresses": total_addresses,
        "usable_hosts": usable_hosts_count,
        "address_class": addr_class,
        "ip_binary": ip_binary,
        "mask_binary": mask_binary,
        "network_binary": network_binary,
        "broadcast_binary": broadcast_binary
    }
