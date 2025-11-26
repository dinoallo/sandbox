Launcher Docker image & Kubernetes deployment

This folder contains a Dockerfile and example Kubernetes manifests to deploy the
launcher service on Kubernetes. The launcher requires access to the host LXD
unix socket and the network capabilities it needs to configure networking (CAP_NET_ADMIN and CAP_SYS_ADMIN).
to perform host networking operations (macvlan creation, namespace moves, etc.).

## gRPC Server Configuration

The launcher gRPC server listens on a Unix socket instead of a TCP port. By default, it uses `/tmp/launcher.sock`.
You can customize the socket path using the `LAUNCHER_SOCKET_PATH` environment variable.

### Network Namespace Support

The launcher can be configured to run in a specific network namespace using the `LAUNCHER_NETNS` environment variable.
This is useful for isolating the launcher's network environment.

Example:

```bash
# Start server with default socket path
cargo run --release

# Start server with custom socket path
LAUNCHER_SOCKET_PATH=/var/run/launcher.sock cargo run --release

# Start server in a specific network namespace
# (The namespace must already exist, created with: sudo ip netns add launcher-test)
sudo LAUNCHER_NETNS=launcher-test cargo run --release

# Or use the provided setup script
sudo ./scripts/setup-netns.sh
sudo LAUNCHER_NETNS=launcher-test cargo run --release
```

The client CLI will automatically connect to the same socket:

```bash
# Connect to default socket
cargo run --bin client -- ping test

# Connect to custom socket
LAUNCHER_SOCKET_PATH=/var/run/launcher.sock cargo run --bin client -- create mycontainer --image ubuntu:22.04
```

Build image locally
-------------------

From the `launcher/` folder build the image and tag it for your registry:

```bash
# build image
docker build -t launcher:latest .

# tag and push to your registry (example)
docker tag launcher:latest ghcr.io/myorg/launcher:latest
docker push ghcr.io/myorg/launcher:latest
```

Deploy on Kubernetes
--------------------

The included `k8s/launcher-deployment.yaml` shows a ServiceAccount and a single `Pod` manifest.
The container is configured to mount the host LXD unix socket at `/var/snap/lxd/common/lxd/unix.socket`
and grants the capabilities `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` which are sufficient for the network
namespace operations performed by launcher.

Apply the manifest:

```bash
kubectl apply -f k8s/launcher-deployment.yaml
```

Notes
-----

- The example grants specific network and sys_admin capabilities. For production you should
  carefully evaluate the exact capabilities required and prefer even tighter capability sets,
  or restrict its scope with Pod Security Admission and RBAC.
- Ensure that the mounted socket path exists on your nodes (Path in Deployment uses `/var/snap/lxd/common/lxd/unix.socket` which is standard for snap-installed LXD; adjust if your LXD places the socket elsewhere).
