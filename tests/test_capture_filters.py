"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/test_capture_filters.py
Purpose: Optional offline libpcap compilation of generated packet capture expressions.
"""

import ctypes
import os
import pytest
from config import SCAN_LIBRARY
from core.scanner import capture_filter

pytestmark = pytest.mark.skipif(
    not os.environ.get("SCANROIDS_LIBPCAP"), reason="Optional local libpcap offline compiler"
)


@pytest.mark.parametrize(
    "choice,targets,flags",
    [
        ("01", ["192.0.2.0/28"], ["-sn"]),
        ("03", ["192.0.2.0/28"], ["-PR"]),
        ("04", ["192.0.2.10"], ["-sL"]),
        ("20", ["ff02::1"], ["-6"]),
        ("30", ["192.0.2.10"], ["-sY"]),
        ("33", ["224.0.0.10"], []),
        ("34", ["224.0.0.5"], []),
        ("44", ["192.0.2.10"], ["-sS", "-sU", "-p", "T:22,80,U:161,500"]),
        ("50", ["2001:db8::10"], ["-6", "-sT", "-p", "22,80-90"]),
        ("05", ["192.0.2.10"], ["-sI", "192.0.2.15:80"]),
    ],
)
def test_generated_filter_compiles_without_live_capture(choice, targets, flags):
    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_uint), ("instructions", ctypes.c_void_p)]

    library = ctypes.CDLL(os.environ["SCANROIDS_LIBPCAP"])
    library.pcap_compile_nopcap.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(Program),
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint32,
    ]
    library.pcap_compile_nopcap.restype = ctypes.c_int
    program = Program()
    expression = capture_filter(SCAN_LIBRARY[choice], targets, flags)
    assert (
        library.pcap_compile_nopcap(
            65535, 1, ctypes.byref(program), expression.encode(), 1, 0xFFFFFFFF
        )
        == 0
    ), expression
    library.pcap_freecode(ctypes.byref(program))


"""
INPUT: Generated BPF and an explicitly configured local libpcap library.
OUTPUT: Offline syntax validation; no interfaces are opened and no traffic is captured.
"""


@pytest.mark.parametrize("linktype", [1, 113, 276])
@pytest.mark.parametrize("choice", ["42", "50"])
def test_filters_accept_realistic_ssh_linux_and_reply_frames(linktype, choice):
    """Run compiled BPF against packet bytes, including Linux 'any' link types."""
    import socket
    import struct
    import shlex

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
    flags = (
        shlex.split(SCAN_LIBRARY[choice]["flags"]) if choice == "42" else ["-Pn", "-sS", "-p", "22"]
    )
    expression = capture_filter(SCAN_LIBRARY[choice], ["192.0.2.10"], flags)
    program = Program()
    assert (
        library.pcap_compile_nopcap(
            65535, linktype, ctypes.byref(program), expression.encode(), 1, 0xFFFFFFFF
        )
        == 0
    )

    def wrap(payload, protocol=0x0800):
        if linktype == 1:
            return b"\x00" * 12 + struct.pack("!H", protocol) + payload
        if linktype == 113:
            return struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, protocol) + payload
        return struct.pack("!HHIHBB8s", protocol, 0, 1, 1, 0, 6, b"\x00" * 8) + payload

    def tcp(port, reply=False, target="192.0.2.10"):
        src, dst = (target, "192.0.2.1") if reply else ("192.0.2.1", target)
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            40,
            0,
            0,
            64,
            6,
            0,
            socket.inet_aton(src),
            socket.inet_aton(dst),
        )
        sport, dport = (port, 55000) if reply else (55000, port)
        segment = struct.pack(
            "!HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x12 if reply else 0x02, 65535, 0, 0
        )
        return wrap(ip + segment)

    def accepted(frame):
        buffer = ctypes.create_string_buffer(frame)
        header = Header(Timeval(0, 0), len(frame), len(frame))
        return bool(
            library.pcap_offline_filter(ctypes.byref(program), ctypes.byref(header), buffer)
        )

    try:
        ports = [22, 111, 2049, 3306, 5432, 443] if choice == "42" else [22]
        for port in ports:
            assert accepted(tcp(port)), (linktype, port, expression)
            assert accepted(tcp(port, reply=True)), (linktype, port, expression)
        assert not accepted(tcp(22, target="192.0.2.99"))
        if choice == "42":
            arp = struct.pack(
                "!HHBBH6s4s6s4s",
                1,
                0x0800,
                6,
                4,
                1,
                b"\x01" * 6,
                socket.inet_aton("192.0.2.1"),
                b"\x00" * 6,
                socket.inet_aton("192.0.2.10"),
            )
            assert accepted(wrap(arp, 0x0806))
        else:
            assert not accepted(tcp(80))
    finally:
        library.pcap_freecode(ctypes.byref(program))
