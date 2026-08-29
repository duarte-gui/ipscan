#!/usr/bin/env bash
# Synthetic lab for validating ipscan without depending on real hardware.
#
# Builds an isolated bridge with two hosts in network namespaces:
#   - "legit"    172.31.99.50/24  -> inside the expected subnet
#   - "intruder" 10.37.129.88/24  -> static IP outside the range, the test target
#
# Usage: sudo tests/lab.sh up | down | status | announce

set -u

BR=br-ipscan-test
NET=172.31.99
BR_IP=$NET.1/24

up() {
  down >/dev/null 2>&1

  ip link add "$BR" type bridge
  ip addr add "$BR_IP" dev "$BR"
  ip link set "$BR" up

  add_host legit    "$NET.50/24"
  add_host intruder "10.37.129.88/24"

  # The bridge only forwards once it has learned; a moment is enough.
  sleep 1
  echo "lab ready: bridge $BR ($BR_IP)"
  ip netns exec legit    ip -br addr show veth-in | sed 's/^/  legit:    /'
  ip netns exec intruder ip -br addr show veth-in | sed 's/^/  intruder: /'
}

add_host() {
  local ns=$1 addr=$2
  ip netns add "$ns"
  ip link add "veth-$ns" type veth peer name veth-in
  ip link set "veth-$ns" master "$BR" up
  ip link set veth-in netns "$ns"
  ip netns exec "$ns" ip addr add "$addr" dev veth-in
  ip netns exec "$ns" ip link set veth-in up
  ip netns exec "$ns" ip link set lo up
}

down() {
  for ns in legit intruder; do
    ip netns del "$ns" 2>/dev/null
  done
  ip link del "$BR" 2>/dev/null
  echo "lab removed"
}

status() {
  ip -br addr show "$BR" 2>/dev/null || echo "bridge $BR does not exist"
  ip netns list
}

# Makes the intruder announce itself with a gratuitous ARP, simulating a boot.
announce() {
  ip netns exec intruder arping -A -c 3 -I veth-in 10.37.129.88 >/dev/null 2>&1
  echo "gratuitous ARP sent by 10.37.129.88"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  announce) announce ;;
  *) echo "usage: $0 {up|down|status|announce}"; exit 1 ;;
esac
