#!/bin/bash

# Script to cleanup the network namespace created by setup-netns.sh
# This script must be run with root/sudo privileges

set -euxo pipefail

NETNS_NAME="${NETNS_NAME:-launcher-test}"
VETH_HOST="veth-host"
SUBNET="172.16.0.0/24"

echo "Cleaning up network namespace: $NETNS_NAME"

# Delete veth interface on host side (this also removes the peer)
if ip link show "$VETH_HOST" &>/dev/null; then
    ip link delete "$VETH_HOST"
    echo "✓ Deleted veth interface: $VETH_HOST"
fi

# Delete network namespace
if ip netns list | grep -q "^${NETNS_NAME}"; then
    ip netns delete "$NETNS_NAME"
    echo "✓ Deleted network namespace: $NETNS_NAME"
else
    echo "⚠ Network namespace $NETNS_NAME not found"
fi

echo ""
echo "Cleanup complete!"
