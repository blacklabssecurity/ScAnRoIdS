"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/test_firewalk_capture.py
Purpose: Execute Firewalk BPF against router-generated ICMP/ICMPv6 quoted probes.
"""

import ctypes
import ipaddress
import os
import struct
import pytest
from core.capture import firewalk_filter

pytestmark = pytest.mark.skipif(
    not os.environ.get("SCANROIDS_LIBPCAP"), reason="Optional local libpcap"
)


@pytest.mark.parametrize("linktype", [1, 113, 276])
@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("error_kind", ["expired", "unreachable"])
def test_router_error_quoting_target_is_captured_but_unrelated_error_is_not(
    linktype, family, error_kind
):
    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_uint), ("instructions", ctypes.c_void_p)]

    class Timeval(ctypes.Structure):
        _fields_ = [("seconds", ctypes.c_long), ("microseconds", ctypes.c_long)]

    class Header(ctypes.Structure):
        _fields_ = [("time", Timeval), ("captured", ctypes.c_uint32), ("length", ctypes.c_uint32)]

    library = ctypes.CDLL(os.environ["SCANROIDS_LIBPCAP"])
    library.pcap_compile_nopcap.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(Program),
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint32,
    ]
    library.pcap_offline_filter.argtypes = [
        ctypes.POINTER(Program),
        ctypes.POINTER(Header),
        ctypes.c_void_p,
    ]
    library.pcap_offline_filter.restype = ctypes.c_uint
    target = "203.0.113.10" if family == 4 else "2001:db8:3::10"
    scanner = "192.0.2.2" if family == 4 else "2001:db8:1::2"
    router = "192.0.2.1" if family == 4 else "2001:db8:2::1"
    unrelated = "203.0.113.99" if family == 4 else "2001:db8:3::99"
    program = Program()
    expression = firewalk_filter(target)
    assert (
        library.pcap_compile_nopcap(
            65535, linktype, ctypes.byref(program), expression.encode(), 1, 0xFFFFFFFF
        )
        == 0
    ), expression

    def ipv4(src, dst, protocol, payload):
        return (
            struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                20 + len(payload),
                1,
                0,
                64,
                protocol,
                0,
                ipaddress.ip_address(src).packed,
                ipaddress.ip_address(dst).packed,
            )
            + payload
        )

    def ipv6(src, dst, protocol, payload):
        return (
            struct.pack(
                "!IHBB16s16s",
                6 << 28,
                len(payload),
                protocol,
                64,
                ipaddress.ip_address(src).packed,
                ipaddress.ip_address(dst).packed,
            )
            + payload
        )

    def frame(quoted_destination):
        if family == 4:
            quoted = ipv4(scanner, quoted_destination, 6, b"\x00" * 8)
            payload = struct.pack("!BBHI", 11 if error_kind == "expired" else 3, 0, 0, 0) + quoted
            packet = ipv4(router, scanner, 1, payload)
            ether = 0x0800
        else:
            quoted = ipv6(scanner, quoted_destination, 6, b"\x00" * 8)
            payload = struct.pack("!BBHI", 3 if error_kind == "expired" else 1, 0, 0, 0) + quoted
            packet = ipv6(router, scanner, 58, payload)
            ether = 0x86DD
        if linktype == 1:
            return b"\x00" * 12 + struct.pack("!H", ether) + packet
        if linktype == 113:
            return struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, ether) + packet
        return struct.pack("!HHIHBB8s", ether, 0, 1, 1, 0, 6, b"\x00" * 8) + packet

    def accepted(packet):
        header = Header(Timeval(0, 0), len(packet), len(packet))
        buffer = ctypes.create_string_buffer(packet)
        return bool(
            library.pcap_offline_filter(ctypes.byref(program), ctypes.byref(header), buffer)
        )

    try:
        assert accepted(frame(target))
        assert not accepted(frame(unrelated))
    finally:
        library.pcap_freecode(ctypes.byref(program))


"""
INPUT: Constructed router ICMP errors and actual compiled BPF for Ethernet/SLL/SLL2.
OUTPUT: Offline proof that relevant router feedback survives target scoping.
"""
