# Kubernetes Deployment

## Sidecar injection

The simplest way to use Loom in Kubernetes is as a sidecar. Copy the `loom` container spec from `sidecar.yaml` into your existing Deployment and redeploy.

```bash
kubectl apply -f sidecar.yaml

# Port-forward the inspector to your laptop
kubectl port-forward deployment/my-service 9998:9998

# Open the inspector
open http://localhost:9998
```

## Redirecting traffic through Loom

To actually capture traffic, clients need to talk to Loom's port (`:9999`) rather than your app's port (`:50051`). Options:

**During a debugging session** — temporarily reconfigure your client's target address.

**Permanently** — set the Service's `targetPort` to `9999` (Loom) rather than `50051` (your app). Loom forwards all traffic transparently so nothing breaks.

**With Istio/Linkerd** — use a VirtualService to mirror traffic to Loom without touching client config.

## Accessing session history

Loom saves call history to `~/.loom/sessions/` inside the container. To persist it across pod restarts:

```yaml
volumes:
  - name: loom-sessions
    emptyDir: {}   # or a PVC for real persistence

volumeMounts:
  - name: loom-sessions
    mountPath: /home/nonroot/.loom
```

## Removing Loom

Delete the `loom` container spec and the `loom.dev/inspector: "true"` label, then redeploy. No other changes needed.
