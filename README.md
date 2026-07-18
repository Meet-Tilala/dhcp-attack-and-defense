# DHCP Starvation and Rogue DHCP Server Attack

A hands-on project showing how a DHCP-based network can be attacked and then
defended. It walks through the whole chain end to end: exhaust the real DHCP
server's address pool (starvation), bring up a rogue DHCP server that hands
clients a fake gateway and DNS, use that position to sit in the middle of their
traffic, and finally turn on DHCP Snooping and Port Security to show the attack
stops working.

The goal is to understand Layer-2 network weaknesses and see, concretely, why
the standard switch defenses matter.

Everything here should only be run against a **network you own or are explicitly
authorized to test**. Please read DISCLAIMER.md before running anything.

## Topology

All devices are in a single VLAN / broadcast domain:

```
      Victim client  ---\
                          \
      Attacker (Kali)  ----  L2 switch ---- Legitimate DHCP server (Ubuntu + isc-dhcp)
                          /                        |
      (traffic goes  ---/                     WiFi router --- Internet
       through attacker
       after the attack)
```

Baseline is deliberately vulnerable: router DHCP off, no DHCP snooping, no port
security, no DAI. The full write-up and diagram are in `docs/`.

## Layout

```
docs/                       execution plan (pdf) and slides
scripts/
  phase1_recon/             find the real DHCP server
  phase2_starvation/        drain the address pool
  phase3_rogue_dhcp/        our rogue dnsmasq server
  phase4_mitm/              forwarding + NAT so we can capture traffic
  phase5_mitigation/        switch configs that stop the attack
```

## Setup

On the Kali attacker box:

```bash
sudo apt update
sudo apt install -y dnsmasq wireshark tcpdump iptables python3 python3-pip
python3 -m pip install -r requirements.txt
```

The Python scripts use Scapy and need root (raw sockets). Find your interface
with `ip link` — the scripts default to `eth0`, pass `-i` to change it.

## How to run it

**Phase 1 - recon.** See which DHCP server(s) are answering and what they hand
out:

```bash
sudo python3 scripts/phase1_recon/dhcp_recon.py -i eth0
```

**Phase 2 - starvation.** Grab leases with random spoofed MACs until the pool is
empty:

```bash
sudo python3 scripts/phase2_starvation/dhcp_starve.py -i eth0 -c 254
```

Check the server's lease file (`/var/lib/dhcp/dhcpd.leases`) to confirm it's full.

**Phase 3 - rogue server.** Once the real pool is drained, start our dnsmasq so
new requests get our lease. Edit `dnsmasq.conf` first so the gateway/DNS options
and the range match your lab, then:

```bash
sudo scripts/phase3_rogue_dhcp/setup_rogue_dhcp.sh eth0 192.168.1.66/24
```

**Phase 4 - MITM.** Turn on forwarding + NAT so the victim still reaches the
internet through us, then capture:

```bash
sudo scripts/phase4_mitm/enable_mitm.sh eth0 wlan0
# on the victim: ipconfig /renew  (Windows)  or  dhclient -r && dhclient  (Linux)
# then capture in Wireshark on eth0
```

Run the same script with `--disable` to undo the forwarding/NAT changes.

**Phase 5 - defense.** Apply the switch configs in `scripts/phase5_mitigation/`,
then re-run phases 2 and 3. Port security err-disables the flooding port and
DHCP snooping drops the rogue offers, so the attack fails. Verification commands
are in the comments of each `.ios` file.

## Why the defenses work

- Port security caps the number of MACs per access port, so the flood of spoofed
  MACs trips a violation.
- DHCP snooping only trusts DHCP replies from the port going to the real server,
  so the rogue server's offers get dropped.
- (Optional) Dynamic ARP Inspection uses the snooping table to block ARP
  spoofing too.

## Owner

- Meet Tilala

- Rudra Gupta

## License

MIT — see LICENSE. Educational use only.
