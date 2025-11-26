# Launcher Testing Scripts

This directory contains helper scripts for testing the launcher in isolated network environments.

## Network Namespace Testing

The `setup-netns.sh` and `cleanup-netns.sh` scripts help you test the launcher in a separate network namespace with its own network configuration.

### Setup

Create a network namespace with a configured network interface:

```bash
sudo ./scripts/setup-netns.sh
```

This will:

1. Create a new Linux network namespace named `launcher-test`
2. Create a veth pair connecting the host and namespace
3. Set up an `eth0` interface in the namespace with IP `172.16.0.1/24`
4. Configure the host side with IP `172.16.0.2/24`

### Usage

Run the launcher in the network namespace:

```bash
# Build the launcher first
cargo build --release

# Run in the namespace
sudo ip netns exec launcher-test /home/allosaurus/Workspace/sandbox/launcher/target/release/launcher
```

Or enter the namespace interactively for debugging:

```bash
sudo ip netns exec launcher-test bash

# Inside the namespace, verify network setup
ip addr show
ip route show
ping -c 3 172.16.0.2
```

### Customization

You can customize the namespace name by setting the `NETNS_NAME` environment variable:

```bash
sudo NETNS_NAME=my-test-ns ./scripts/setup-netns.sh
sudo NETNS_NAME=my-test-ns ip netns exec my-test-ns /path/to/launcher
sudo NETNS_NAME=my-test-ns ./scripts/cleanup-netns.sh
```

### Cleanup

Remove the network namespace and associated resources:

```bash
sudo ./scripts/cleanup-netns.sh
```

## Testing the Launcher

Once in the network namespace, you can:

1. Start the launcher service
2. Use the client CLI from the host to connect to it
3. Verify that containers can be created and have network connectivity
4. Test IP delegation features in the isolated network environment

Example workflow:

```bash
# Terminal 1: Start launcher in namespace
sudo ip netns exec launcher-test cargo run --release

# Terminal 2: Run client from host
cargo run --bin client -- --addr http://127.0.0.1:50051 create test-container --image ubuntu:22.04 --ip 172.16.0.1
```
