"""TCP/IP IPv4 Packet Checksum & Parser Engine.
100% Python Standard Library.
"""

import struct
import socket

class IPv4Packet:
    """IPv4 packet builder, validator, and header parser."""

    @staticmethod
    def calculate_checksum(data: bytes) -> int:
        if len(data) % 2 != 0:
            data += b"\x00"
        s = sum(struct.unpack(f"!{len(data)//2}H", data))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return (~s) & 0xFFFF

    @classmethod
    def build_ipv4_header(cls, src_ip: str, dst_ip: str, protocol: int = 6, payload_len: int = 0, ttl: int = 64) -> bytes:
        src_bytes = socket.inet_aton(src_ip)
        dst_bytes = socket.inet_aton(dst_ip)
        version_ihl = (4 << 4) | 5
        tos = 0
        total_len = 20 + payload_len
        ident = 54321
        flags_offset = 0x4000  # Don't fragment
        dummy_checksum = 0
        header_no_cs = struct.pack("!BBHHHBBH4s4s", version_ihl, tos, total_len, ident, flags_offset, ttl, protocol, dummy_checksum, src_bytes, dst_bytes)
        cs = cls.calculate_checksum(header_no_cs)
        return struct.pack("!BBHHHBBH4s4s", version_ihl, tos, total_len, ident, flags_offset, ttl, protocol, cs, src_bytes, dst_bytes)

    @classmethod
    def parse_header(cls, packet_bytes: bytes) -> dict:
        if len(packet_bytes) < 20:
            raise ValueError("Packet truncated: header < 20 bytes")
        v_ihl, tos, total_len, ident, flags_off, ttl, proto, cs, src, dst = struct.unpack("!BBHHHBBH4s4s", packet_bytes[:20])
        version = v_ihl >> 4
        ihl = (v_ihl & 0x0F) * 4
        verified_cs = cls.calculate_checksum(packet_bytes[:ihl])
        return {
            "version": version,
            "ihl": ihl,
            "total_len": total_len,
            "ttl": ttl,
            "protocol": proto,
            "checksum": hex(cs),
            "valid_checksum": (verified_cs == 0),
            "src_ip": socket.inet_ntoa(src),
            "dst_ip": socket.inet_ntoa(dst)
        }
