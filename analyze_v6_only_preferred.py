#!/usr/bin/env python3
"""
Analyze a PCAP file containing DHCP Discover messages.
Print stats including number of unique MAC addresses,
number of MAC addresses requesting DHCP option 108
(IPv6-only Preferred) and MAC adresses flapping between
requesting and not requesting it.

To collect PCAP file, tcpdump can be used like this:

    # tcpdump -i eth0 -s0 -w dhcp_messages.pcap udp port bootpc

To analyse collected file, run:

    $ python3 -m venv venv
    $ source ./venv/bin/activate
    (venv) $ pip install click dpkt scapy
    (venv) $ python analyze_v6_only_preferred.py dhcp_messages.pcap
"""

import io
import os

import click
from scapy.all import Ether, DHCP
import dpkt

def dhcp_option(options, name):
    """Return DHCP option of name provided."""
    for option in options:
        if option[0] == name:
            return option[1]


@click.command()
@click.argument("pcapfile", type=click.File("rb"))
def main(pcapfile):
    """Parse PCAP files to look for option 108 in DHCP requests."""
    devicestatus = dict()
    flapping = set()
    pcapfile.seek(0, io.SEEK_END)
    size = pcapfile.tell()
    pcapfile.seek(0, io.SEEK_SET)
    pos = 0
    with click.progressbar(length=size) as bar:
        for ts, buf in dpkt.pcap.Reader(pcapfile):
            newpos = pcapfile.raw.tell()
            bar.update(newpos - pos)
            pos = newpos
            p = Ether(buf)
            srcmac = p[Ether].src
            if not p.haslayer(DHCP):
                continue
            dhcp_msg_type = dhcp_option(p[DHCP].options, 'message-type')
            if dhcp_msg_type != 1 and dhcp_msg_type != 3:
                continue
            v6onlysupported = 108 in dhcp_option(p[DHCP].options, 'param_req_list')
            if srcmac not in devicestatus:
                 devicestatus[srcmac] = v6onlysupported
            elif devicestatus[srcmac] != v6onlysupported:
                flapping.add(srcmac)
    total = len(devicestatus)
    enabled = len([d for d in devicestatus.values() if d])
    print("Unique MACs:", total)
    print("Option 108 enabled:", enabled, f"{100*enabled//total}%")
    print("Flapping:", len(flapping))
    print(", ".join(flapping))


if __name__ == '__main__':
    main()