#!/usr/bin/python
from bcc import BPF
import socket
import ipaddress
import struct
import ctypes
from time import sleep

def start_monitoring():
    b = BPF(src_file="tcp_c.c")
    try:
        while True:
            sleep(2)
            s = ""
            for k, v in b["tcp_probe_h"].items():
                src_ip = decode_in6(v.family, v.saddr)
                dst_ip = decode_in6(v.family, v.daddr)
                print("ts: {6}, src: {0}, dst: {1}, sport: {2}, dport: {3}, snd_cwnd: {4}, rcv_wnd: {8}, srtt: {5}, ssthresh: {7}".format(src_ip, dst_ip, v.sport, v.dport, v.snd_cwnd, v.srtt, v.ts, v.ssthresh, v.rcv_wnd))
                del b["tcp_probe_h"][k]

    except KeyboardInterrupt: #7
        print("Exiting")

def decode_in6(af ,addr6):
                af, tport, flow, a1, a2, a3, a4, scope = struct.unpack('<HHILLLLI', bytearray(addr6))
                ip = "0.0.0.0"
                if (af == 10):
                    ip = str(ipaddress.IPv6Address(struct.pack('<LLLL', a1, a2, a3, a4)))
                elif (af == 2):
                    ip = str(ipaddress.IPv4Address(struct.pack('<I', flow)))
                return ip

if __name__ == "__main__":
    start_monitoring()
    
