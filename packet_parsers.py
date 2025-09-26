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
    elif ether_type == "0800": # UDP
        parse_udp_header(payload)
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

def parse_flags(flag_hex_data):
    binary_data = str(bin(int(flag_hex_data, 16)))
    binary_data = binary_data[:1] + binary_data[2:]
    reserved = binary_data[0]
    DF = binary_data[1]
    MF = binary_data[2]
    offset_binary = binary_data[3:]
    offset = int(offset_binary, 2)
    offset_hex = hex(offset)

    return reserved, DF, MF, offset_hex, offset

def parse_ipv4_header(hex_data):
    ipv4_version    = int(hex_data[:1], 16)
    header_length   = str(int(hex_data[1:2], 16) * 4) + " bytes"
    total_length    = int(hex_data[4:8], 16)

    reserved, df, mf, offset_hex, offset = parse_flags(hex_data[12:16])

    flags           = str(bin(int(hex_data[12:16], 16)))

    protocol = int(hex_data[18:20], 16)
    source_address = hex_to_ip(hex_data[24:32])
    destination_address = hex_to_ip(hex_data[32:40])

    print(f"IPv4 Header: ")

    print(f"  {'IPv4 Version:':<25} {hex_data[:1]:<20} | {ipv4_version}")
    print(f"  {'Header Length:':<25} {hex_data[1:2]:<20} | {header_length}")
    print(f"  {'Total Length:':<25} {hex_data[4:8]:<20} | {total_length}")
    print(f"  {'Flags & Frag Offset:':<25} {hex_data[12:16]:<20} | {flags}")

    print(f"    {'Reserved:':<25} {reserved}")
    print(f"    {'DF:':<25} {df}")
    print(f"    {'MF:':<25} {mf}")
    print(f"    {'Offset:':<25} {offset_hex:<18} | {offset}")

    print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {protocol}")
    print(f"  {'Source IP:':<25} {hex_data[24:32]:<20} | {source_address}")
    print(f"  {'Destination IP:':<25} {hex_data[32:40]:<20} | {destination_address}")

# Parse UDP Header
def parse_udp_header(hex_data):
    parse_ipv4_header(hex_data)

    source_port         = int(hex_data[40:44], 16)
    destination_port    = int(hex_data[44:48], 16)
    length              = int(hex_data[48:52], 16)
    checksum            = int(hex_data[52:56], 16)
    payload_length      = (length - 8) * 2
    payload             = hex_data[56:(56 + payload_length)]

    print(f"UDP Header: ")

    print(f"  {'Source Port:':<25} {hex_data[40:44]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[44:48]:<20} | {destination_port}")
    print(f"  {'Length:':<25} {hex_data[48:52]:<20} | {length}")
    print(f"  {'Checksum:':<25} {hex_data[52:56]:<20} | {checksum}")
    print(f"  {'Payload (hex):':<25} {payload}")




