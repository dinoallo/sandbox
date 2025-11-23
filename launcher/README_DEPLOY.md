Launcher Docker image & Kubernetes deployment

This folder contains a Dockerfile and example Kubernetes manifests to deploy the
launcher service on Kubernetes. The launcher requires access to the host LXD
unix socket and the network capabilities it needs to configure networking (CAP_NET_ADMIN and CAP_SYS_ADMIN).
to perform host networking operations (macvlan creation, namespace moves, etc.).

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
