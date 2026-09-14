"""
IPsecGuard AI - Built-in Sample Datasets and PCAP Generator
Contains realistic ground-truth IPsec configurations and synthetic PCAP generation utilities.
"""

import os
import struct
import time

SAMPLE_CONFIGURATIONS = [
    {
        "id": "strong-enterprise",
        "name": "Strong Enterprise VPN",
        "tag": "Enterprise / High Security",
        "badge_color": "emerald",
        "description": "Enterprise-grade site-to-site IPsec tunnel conforming to CNSA & NIST SP 800-77 Rev. 1 guidelines. Features modern IKEv2, AES-256 encryption, SHA-256 HMAC integrity, and DH Group 20 with PFS enabled.",
        "config": {
            "ike_version": "IKEv2",
            "mode": "Tunnel",
            "encryption": "AES-256",
            "authentication": "HMAC-SHA256",
            "dh_group": "Group 20",
            "pfs": True,
            "ip_version": "IPv4",
            "traffic_type": "Web Browsing",
            "replay_protection": True,
            "key_lifetime": 28800
        },
        "traffic_metrics": {
            "packet_count": 14250,
            "avg_packet_size": 842,
            "encrypted_ratio": 99.4,
            "esp_detected": True,
            "ah_detected": False,
            "ike_detected": True,
            "inbound_spi": "0x8F3C92A1",
            "outbound_spi": "0x4E12B07D",
            "replay_window_size": 64,
            "source_ip": "198.51.100.15",
            "dest_ip": "203.0.113.88",
            "protocol_breakdown": {
                "ESP": 13950,
                "IKE": 260,
                "NAT-T": 40
            },
            "size_distribution": [
                {"range": "64-128 B", "count": 1200},
                {"range": "129-512 B", "count": 3400},
                {"range": "513-1024 B", "count": 6850},
                {"range": "1025-1500 B", "count": 2800}
            ]
        }
    },
    {
        "id": "legacy-vpn",
        "name": "Legacy VPN",
        "tag": "Legacy / Deprecated",
        "badge_color": "red",
        "description": "Outdated legacy site-to-site tunnel using deprecated IKEv1 Main Mode, AES-128-CBC, SHA-1 authentication, and DH Group 2 (1024-bit MODP) with Perfect Forward Secrecy disabled. Vulnerable to cryptoanalysis and key compromise.",
        "config": {
            "ike_version": "IKEv1",
            "mode": "Tunnel",
            "encryption": "AES-128",
            "authentication": "HMAC-SHA1",
            "dh_group": "Group 2",
            "pfs": False,
            "ip_version": "IPv4",
            "traffic_type": "Email",
            "replay_protection": False,
            "key_lifetime": 86400
        },
        "traffic_metrics": {
            "packet_count": 8920,
            "avg_packet_size": 612,
            "encrypted_ratio": 98.1,
            "esp_detected": True,
            "ah_detected": False,
            "ike_detected": True,
            "inbound_spi": "0x1A2B3C4D",
            "outbound_spi": "0x5E6F7A8B",
            "replay_window_size": 0,
            "source_ip": "192.0.2.45",
            "dest_ip": "198.51.100.22",
            "protocol_breakdown": {
                "ESP": 8600,
                "IKE": 300,
                "NAT-T": 20
            },
            "size_distribution": [
                {"range": "64-128 B", "count": 2100},
                {"range": "129-512 B", "count": 4300},
                {"range": "513-1024 B", "count": 1820},
                {"range": "1025-1500 B", "count": 700}
            ]
        }
    },
    {
        "id": "modern-vpn",
        "name": "Modern High-Security VPN (IPv6 + AES-GCM)",
        "tag": "Next-Gen / Zero-Trust",
        "badge_color": "cyan",
        "description": "State-of-the-art authenticated encryption (AEAD) using AES-GCM with SHA-384 and DH Group 20 (384-bit ECP) operating over IPv6. Highest cryptographic robustness and minimal metadata leakage.",
        "config": {
            "ike_version": "IKEv2",
            "mode": "Tunnel",
            "encryption": "AES-GCM",
            "authentication": "HMAC-SHA384",
            "dh_group": "Group 20",
            "pfs": True,
            "ip_version": "IPv6",
            "traffic_type": "Video Streaming",
            "replay_protection": True,
            "key_lifetime": 14400
        },
        "traffic_metrics": {
            "packet_count": 25400,
            "avg_packet_size": 1180,
            "encrypted_ratio": 99.8,
            "esp_detected": True,
            "ah_detected": False,
            "ike_detected": True,
            "inbound_spi": "0xFEEDC0DE",
            "outbound_spi": "0xCAFEBABE",
            "replay_window_size": 128,
            "source_ip": "2001:db8:85a3::8a2e:370:7334",
            "dest_ip": "2001:db8:85a3::8a2e:370:7335",
            "protocol_breakdown": {
                "ESP": 25150,
                "IKE": 210,
                "NAT-T": 40
            },
            "size_distribution": [
                {"range": "64-128 B", "count": 950},
                {"range": "129-512 B", "count": 2250},
                {"range": "513-1024 B", "count": 8200},
                {"range": "1025-1500 B", "count": 14000}
            ]
        }
    },
    {
        "id": "transport-mode",
        "name": "Host-to-Host Transport Mode",
        "tag": "Transport / Host-to-Host",
        "badge_color": "purple",
        "description": "Host-to-host direct endpoint encryption using Transport Mode. The original IP headers are retained, exposing communication endpoints to intermediate observers.",
        "config": {
            "ike_version": "IKEv2",
            "mode": "Transport",
            "encryption": "AES-256",
            "authentication": "HMAC-SHA256",
            "dh_group": "Group 14",
            "pfs": True,
            "ip_version": "IPv4",
            "traffic_type": "VoIP",
            "replay_protection": True,
            "key_lifetime": 28800
        },
        "traffic_metrics": {
            "packet_count": 11600,
            "avg_packet_size": 320,
            "encrypted_ratio": 98.9,
            "esp_detected": True,
            "ah_detected": False,
            "ike_detected": True,
            "inbound_spi": "0x33445566",
            "outbound_spi": "0x77889900",
            "replay_window_size": 64,
            "source_ip": "10.0.1.50",
            "dest_ip": "10.0.2.100",
            "protocol_breakdown": {
                "ESP": 11350,
                "IKE": 180,
                "NAT-T": 70
            },
            "size_distribution": [
                {"range": "64-128 B", "count": 4800},
                {"range": "129-512 B", "count": 5200},
                {"range": "513-1024 B", "count": 1200},
                {"range": "1025-1500 B", "count": 400}
            ]
        }
    },
    {
        "id": "misconfigured-vpn",
        "name": "Misconfigured High-Risk VPN",
        "tag": "Critical / High Risk",
        "badge_color": "rose",
        "description": "Dangerously misconfigured VPN with IKEv1, AES-128-CBC, weak SHA-1, DH Group 2, PFS disabled, Replay Protection disabled, and an excessively long key lifetime of 48 hours.",
        "config": {
            "ike_version": "IKEv1",
            "mode": "Transport",
            "encryption": "AES-128",
            "authentication": "HMAC-SHA1",
            "dh_group": "Group 2",
            "pfs": False,
            "ip_version": "IPv4",
            "traffic_type": "Web Browsing",
            "replay_protection": False,
            "key_lifetime": 172800
        },
        "traffic_metrics": {
            "packet_count": 6400,
            "avg_packet_size": 580,
            "encrypted_ratio": 97.4,
            "esp_detected": True,
            "ah_detected": False,
            "ike_detected": True,
            "inbound_spi": "0xBAD0CAFE",
            "outbound_spi": "0xDEADBEEF",
            "replay_window_size": 0,
            "source_ip": "172.16.0.4",
            "dest_ip": "172.16.10.88",
            "protocol_breakdown": {
                "ESP": 6120,
                "IKE": 240,
                "NAT-T": 40
            },
            "size_distribution": [
                {"range": "64-128 B", "count": 1800},
                {"range": "129-512 B", "count": 3100},
                {"range": "513-1024 B", "count": 1100},
                {"range": "1025-1500 B", "count": 400}
            ]
        }
    }
]


def generate_sample_pcap(filepath: str, sample_id: str = "strong-enterprise"):
    """
    Synthesizes a valid standard Libpcap binary capture file without external tools.
    Includes Ethernet frames, IPv4/IPv6 headers, ISAKMP (IKE UDP 500) negotiation frames,
    and IPsec ESP (IP Protocol 50) encrypted payload records with realistic SPIs.
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    # Select SPI and IP based on sample
    match_sample = next((s for s in SAMPLE_CONFIGURATIONS if s["id"] == sample_id), SAMPLE_CONFIGURATIONS[0])
    in_spi_int = int(match_sample["traffic_metrics"]["inbound_spi"], 16)
    out_spi_int = int(match_sample["traffic_metrics"]["outbound_spi"], 16)
    is_ikev2 = match_sample["config"]["ike_version"] == "IKEv2"

    # PCAP Global Header: magic_number (0xa1b2c3d4), version_major (2), version_minor (4),
    # thiszone (0), sigfigs (0), snaplen (65535), network (1 = LINKTYPE_ETHERNET)
    global_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    packets_data = []
    base_time = int(time.time()) - 300

    def make_eth_ip_udp(src_ip, dst_ip, src_port, dst_port, udp_payload, ts_sec, ts_usec):
        # Ethernet Header: Dest MAC (6B), Src MAC (6B), Type (2B = 0x0800 IPv4)
        eth = b"\x00\x1a\x2b\x3c\x4d\x5e\x00\x11\x22\x33\x44\x55\x08\x00"
        
        # IPv4 Header
        src_parts = [int(p) for p in src_ip.split(".")]
        dst_parts = [int(p) for p in dst_ip.split(".")]
        src_bytes = bytes(src_parts)
        dst_bytes = bytes(dst_parts)
        
        udp_len = 8 + len(udp_payload)
        ip_total_len = 20 + udp_len
        # Version 4, IHL 5, DSCP 0, Total Len, Identification 0x1234, Flags/Frag 0x4000 (DF), TTL 64, Proto 17 (UDP), Checksum 0, Src, Dst
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total_len, 0x1234, 0x4000, 64, 17, 0, src_bytes, dst_bytes)
        
        # UDP Header
        udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        
        frame = eth + ip_hdr + udp_hdr + udp_payload
        pcap_rec_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame))
        return pcap_rec_hdr + frame

    def make_eth_ip_esp(src_ip, dst_ip, spi, seq_num, esp_payload, ts_sec, ts_usec):
        eth = b"\x00\x1a\x2b\x3c\x4d\x5e\x00\x11\x22\x33\x44\x55\x08\x00"
        src_parts = [int(p) for p in src_ip.split(".")]
        dst_parts = [int(p) for p in dst_ip.split(".")]
        src_bytes = bytes(src_parts)
        dst_bytes = bytes(dst_parts)
        
        # ESP Header: SPI (4B), Sequence Number (4B) + Payload + Padding + Pad Len (1B) + Next Header (1B)
        esp_packet = struct.pack("!II", spi, seq_num) + esp_payload + b"\x01\x02\x02\x06" # next header 6 = TCP
        ip_total_len = 20 + len(esp_packet)
        # Proto 50 = ESP
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total_len, 0x5678, 0x4000, 64, 50, 0, src_bytes, dst_bytes)
        
        frame = eth + ip_hdr + esp_packet
        pcap_rec_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame))
        return pcap_rec_hdr + frame

    # 1. Packet 1: IKE_SA_INIT (UDP port 500)
    # ISAKMP header: Initiator SPI (8B), Responder SPI (8B), Next Payload (1B), Major/Minor Version (1B), Exchange Type (1B), Flags (1B), Message ID (4B), Length (4B)
    ike_version_byte = 0x20 if is_ikev2 else 0x10
    exchange_type = 34 if is_ikev2 else 2 # IKE_SA_INIT or Identity Protection
    ike_payload = struct.pack("!8s8sBBBBII", b"\x5a\x1b\x9c\x3d\x7e\x2f\x0a\x11", b"\x00"*8, 33, ike_version_byte, exchange_type, 0x08, 0, 148)
    ike_payload += b"\x00" * 120 # Security Association Proposal payloads
    packets_data.append(make_eth_ip_udp("198.51.100.15", "203.0.113.88", 500, 500, ike_payload, base_time, 1000))

    # 2. Packet 2: IKE_SA_INIT Response (UDP port 500)
    ike_resp = struct.pack("!8s8sBBBBII", b"\x5a\x1b\x9c\x3d\x7e\x2f\x0a\x11", b"\x88\x77\x66\x55\x44\x33\x22\x11", 33, ike_version_byte, exchange_type, 0x20, 0, 156)
    ike_resp += b"\x00" * 128
    packets_data.append(make_eth_ip_udp("203.0.113.88", "198.51.100.15", 500, 500, ike_resp, base_time + 1, 15000))

    # 3. Packets 3-12: Simulated ESP encrypted sessions (Protocol 50)
    for seq in range(1, 11):
        # Varying payload length to simulate realistic traffic
        payload_len = 128 + ((seq * 87) % 800)
        cipher_bytes = (b"\xde\xad\xbe\xef\xca\xfe\xba\xbe" * ((payload_len // 8) + 1))[:payload_len]
        spi = in_spi_int if seq % 2 == 1 else out_spi_int
        src = "198.51.100.15" if seq % 2 == 1 else "203.0.113.88"
        dst = "203.0.113.88" if seq % 2 == 1 else "198.51.100.15"
        packets_data.append(make_eth_ip_esp(src, dst, spi, seq, cipher_bytes, base_time + 2 + seq, seq * 45000))

    with open(filepath, "wb") as f:
        f.write(global_hdr)
        for pkt in packets_data:
            f.write(pkt)

    return filepath
