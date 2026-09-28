from client import IPv4Packet

def main():
    raw_packet = IPv4Packet.build_ipv4_header("192.168.1.1", "10.0.0.1", protocol=6, payload_len=64)
    info = IPv4Packet.parse_header(raw_packet)
    print("Parsed IPv4 Header:", info)
    assert info["valid_checksum"] is True

if __name__ == "__main__":
    main()
