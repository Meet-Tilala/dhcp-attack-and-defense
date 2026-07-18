#!/usr/bin/env python3
# Phase 1 - reconnaissance.
# Send one DHCP DISCOVER and print out whatever servers reply, along with the
# offer they send (IP, MAC, subnet, gateway, DNS, lease time). If more than one
# server answers, something rogue might already be on the network.
# Authorized, isolated networks only - see ../../DISCLAIMER.md.

import argparse
import random

from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp, conf

conf.checkIPaddr = False


def random_mac():
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] & 0xFE) | 0x02   # locally administered, unicast
    return ':'.join('%02x' % o for o in octets)


def get_option(options, key):
    for entry in options:
        if isinstance(entry, tuple) and entry[0] == key:
            return entry[1]
    return None


def discover_servers(iface, timeout):
    mac = random_mac()
    mac_bytes = bytes(int(x, 16) for x in mac.split(':'))

    discover = (Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') /
                IP(src='0.0.0.0', dst='255.255.255.255') /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac_bytes, xid=random.randint(1, 0xFFFFFFFF)) /
                DHCP(options=[('message-type', 'discover'),
                              ('param_req_list', [1, 3, 6, 51]),
                              'end']))

    print(f'[*] Sending DHCP DISCOVER on {iface} (probe MAC {mac})\n')
    answered, _ = srp(discover, iface=iface, timeout=timeout, verbose=0, multi=True)

    servers = {}
    for _sent, recv in answered:
        if DHCP not in recv:
            continue
        opts = recv[DHCP].options
        server_ip = get_option(opts, 'server_id') or recv[IP].src
        if server_ip in servers:
            continue
        servers[server_ip] = {
            'mac': recv[Ether].src,
            'offered_ip': recv[BOOTP].yiaddr,
            'mask': get_option(opts, 'subnet_mask'),
            'gateway': get_option(opts, 'router'),
            'dns': get_option(opts, 'name_server'),
            'lease': get_option(opts, 'lease_time'),
        }
    return servers


def main():
    p = argparse.ArgumentParser(description='DHCP server recon (authorized use only)')
    p.add_argument('-i', '--iface', default='eth0')
    p.add_argument('--timeout', type=int, default=5)
    args = p.parse_args()

    servers = discover_servers(args.iface, args.timeout)
    if not servers:
        print('[-] No DHCP servers replied. Check the interface / that a server is up.')
        return

    print(f'[+] Found {len(servers)} DHCP server(s):\n')
    for ip, info in servers.items():
        print(f'  server IP   : {ip}')
        print(f'  server MAC  : {info["mac"]}')
        print(f'  offered IP  : {info["offered_ip"]}')
        print(f'  subnet mask : {info["mask"]}')
        print(f'  gateway     : {info["gateway"]}')
        print(f'  dns         : {info["dns"]}')
        print(f'  lease time  : {info["lease"]} s\n')

    if len(servers) > 1:
        print('[!] More than one server answered - possible rogue already present.')


if __name__ == '__main__':
    main()
