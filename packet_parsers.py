# Parse Ethernet header
def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    # Route payload based on EtherType
    if ether_type == "0806":  # ARP
        parse_arp_header(payload)
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload


def hex_to_mac(hex_data):
    length = len(hex_data)
    mac_address = ""
    for i in range (0, length, 2):
        current = hex_data[i:(i + 2)]
        if(i == length - 2):
            mac_address += current
        else:
            mac_address += current + ":"

    return mac_address

def hex_to_ip(hex_data):
    length = len(hex_data)
    ip_address = ""
    for i in range(0, length, 2):
        current = str(int(hex_data[i:(i + 2)], 16))
        print("Hex to ip: " + current)
        if(i == length - 2):
            ip_address = ip_address + current
        else:
            ip_address = ip_address + current + "."

    return ip_address

# Parse ARP header
def parse_arp_header(hex_data):
    hardware_type   = int(hex_data[:4], 16)
    protocol_type   = int(hex_data[4:8], 16)
    hardware_size   = int(hex_data[8:10], 16)
    protocol_size   = int(hex_data[10:12], 16)
    operation_code  = int(hex_data[12:16], 16)
    sender_mac      = hex_to_mac(hex_data[16:28])
    sender_ip       = hex_to_ip(hex_data[28:36])
    target_mac      = hex_to_mac(hex_data[36:46])
    target_ip       = hex_to_ip(hex_data[46:54])

    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")

    print(f"  {'Protocol Type:':<25} {hex_data[4:8]:<20} | {protocol_type}")
    print(f"  {'Hardware Size:':<25} {hex_data[8:10]:<20} | {hardware_size}")
    print(f"  {'Protocol Size:':<25} {hex_data[10:12]:<20} | {protocol_size}")
    print(f"  {'Operation Code:':<25} {hex_data[12:16]:<20} | {operation_code}")
    print(f"  {'Sender MAC Address:':<25} {hex_data[16:28]:<20} | {sender_mac}")
    print(f"  {'Sender IP Address:':<25} {hex_data[28:36]:<20} | {sender_ip}")
    print(f"  {'Target MAC Address:':<25} {hex_data[36:46]:<20} | {target_mac}")
    print(f"  {'Target IP Address:':<25} {hex_data[46:54]:<20} | {target_ip}")
