#!/bin/bash

# Script to create a network namespace for testing launcher
# This script must be run with root/sudo privileges

set -euxo pipefail

NETNS_NAME="${NETNS_NAME:-launcher-test}"
VETH_HOST="veth-host"
VETH_IF="veth0"
HOST_IP="172.16.0.2"
NS_IP="172.16.0.1"
SUBNET="172.16.0.0/24"

echo "Creating network namespace: $NETNS_NAME"

# Check if namespace already exists
if ip netns list | grep -q "^${NETNS_NAME}"; then
    echo "Network namespace $NETNS_NAME already exists. Deleting it first..."
    ip netns delete "$NETNS_NAME"
fi

# 1. Create a new linux network namespace
ip netns add "$NETNS_NAME"
echo "✓ Created network namespace: $NETNS_NAME"

# Create veth pair to connect host and namespace
ip link add "$VETH_HOST" type veth peer name "$VETH_IF"
echo "✓ Created veth pair: $VETH_HOST <-> $VETH_IF"

# Move one end of veth pair into the namespace
ip link set "$VETH_IF" netns "$NETNS_NAME"

# 2. Set up the network interface in the namespace and name it eth0
ip netns exec "$NETNS_NAME" ip link set "$VETH_IF" up
ip netns exec "$NETNS_NAME" ip link set lo up
echo "✓ Set up $VETH_IF interface in namespace"

# 3. Set the IP of eth0 to 172.16.0.1
ip netns exec "$NETNS_NAME" ip addr add "${NS_IP}/24" dev "$VETH_IF"
# ip netns exec "$NETNS_NAME" ip route add 172.16.0.0/24 via "$NS_IP" dev "$VETH_IF"
echo "✓ Assigned IP $NS_IP to $VETH_IF"

# 4. Configure host side of veth pair
ip addr add "${HOST_IP}/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up
echo "✓ Configured host side: $VETH_HOST with IP $HOST_IP"

# 5. Add 172.16.0.0/24 route to route traffic via veth0 on host
# ip route add 172.16.0.0/24 via "$HOST_IP" dev "$VETH_HOST"
# echo "✓ Added 172.16.0.0/24 route via $HOST_IP"

echo ""
echo "Network namespace setup complete!"
echo ""
echo "To run launcher in this namespace:"
echo "  sudo ip netns exec $NETNS_NAME /path/to/launcher"
echo ""
echo "To enter the namespace for debugging:"
echo "  sudo ip netns exec $NETNS_NAME bash"
echo ""
echo "To verify network setup:"
echo "  sudo ip netns exec $NETNS_NAME ip addr show"
echo "  sudo ip netns exec $NETNS_NAME ip route show"
echo "  sudo ip netns exec $NETNS_NAME ping -c 3 $HOST_IP"
echo ""
echo "To cleanup:"
echo "  sudo ./scripts/cleanup-netns.sh"
