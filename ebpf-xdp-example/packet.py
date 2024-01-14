#!/usr/bin/python
from bcc import BPF
import socket
import struct
from time import sleep

def get_interfaces():
    print("Select your interface:")
    # Return a list of network interface information
    interfaces = socket.if_nameindex()
    for iface in interfaces:
        print(iface[1])
    val = input("Interface name: ")
    for iface in interfaces:
        if val == iface[1]:
            return val
    else:
        print("invalid interface name")
        exit()


def start_monitoring(interface):
    b = BPF(src_file="packet.c")
    b.attach_xdp(dev=interface, fn=b.load_func("packet_counter", BPF.XDP))
    try:
        while True:
            sleep(2)
            s = ""
            for k, v in b["packets"].items():
                s += "Protocol {}: counter {},".format(k.value, v.value)
            print(s)
            source = ""
            for k, v in b["sources"].items():
                source += "Sources {}: counter {},".format(socket.inet_ntoa(struct.pack('<L', k.value)), v.value)
            print(source)
    except KeyboardInterrupt: #7
        print("Detaching")
        b.remove_xdp(iface, 0)
        print("Exiting")

if __name__ == "__main__":
    iface = get_interfaces()
    start_monitoring(iface)
    
