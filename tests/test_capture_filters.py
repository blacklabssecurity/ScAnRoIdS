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
