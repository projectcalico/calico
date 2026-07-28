# Calico tiered RBAC authorization webhook

Enforces Calico tier-based RBAC on GET/LIST/WATCH of tiered policy resources (`NetworkPolicy`, `GlobalNetworkPolicy`, and their staged variants) for clusters that run Calico's v3 API as CRDs rather than through the aggregated API server. Mutations (CREATE/UPDATE/DELETE) are covered separately by the `calico-webhooks` admission webhook, which unlike this one can read the object body.

## Applicability

Self-hosted clusters only. `--authorization-config` cannot be set on EKS, AKS, or GKE, and the config file has to be placed on the control-plane nodes. If you don't manage the API server's flags directly, this webhook does not apply to you.

## Install

1. Apply the chart with `useV3CRDs` enabled so `calico-webhooks` is deployed:

   ```
   helm upgrade calico charts/calico --set useV3CRDs=true
   ```

2. Read the allocated ClusterIP and write it, along with the webhook's CA bundle, into `calico-authz-webhook-kubeconfig.yaml`:

   ```
   kubectl get svc -n kube-system calico-webhooks -o jsonpath='{.spec.clusterIP}'
   ```

   Replace `CLUSTER_IP` in `calico-authz-webhook-kubeconfig.yaml`'s `server` field with that IP on port 443, and point `certificate-authority` at a file containing the CA cert that signed `calico-webhooks`' TLS certificate. Use a path here, not inline `certificate-authority-data`: you are already placing files on the control-plane nodes in the next step, so drop the CA cert alongside them. A `.svc` DNS name will not work in place of the IP: kube-apiserver resolves `server` from its own network namespace, which has no cluster DNS and no pod-network route.

3. Place `authorization-configuration.yaml`, `calico-authz-webhook-kubeconfig.yaml`, and the CA cert file under `/etc/kubernetes/authz/` on every control-plane node, then point the API server at the config file and remove `--authorization-mode`:

   ```
   kube-apiserver --authorization-config=/etc/kubernetes/authz/authorization-configuration.yaml
   ```

   `--authorization-config` and `--authorization-mode` are mutually exclusive. An API server started with both set will not start. Adding `--authorization-config` without removing `--authorization-mode=Node,RBAC` is the most likely install mistake here.

`calico-webhooks` also serves `/metrics` on the same TLS listener as the webhook endpoints (`--port`, default 6443). If `--client-ca-file` is set, that listener requires a verified client certificate for every connection, including scrapes: a Prometheus job configured with only CA trust and no client cert gets a TLS handshake failure and never scrapes, silently.

## Break-glass

`failurePolicy: Deny` means an unreachable webhook denies every read of a tiered policy resource cluster-wide, not just the ones it would otherwise have denied. Causes include the webhook pod being down, a cert that expired, or a dataplane failure that keeps `calico-webhooks` from starting.

To restore reads, edit `authorization-configuration.yaml` on each control-plane node and either:

- delete the `calico-tiered-rbac` entry from `authorizers`, or
- set its `failurePolicy` to `NoOpinion`.

`kube-apiserver` reloads `--authorization-config` from disk automatically; no flag changes are needed. Whether the running API server picks up the edit without a restart is unverified as of this writing; treat a restart as the fallback if reads are still denied after editing the file.

## What this does not cover

Reads are covered by this webhook, mutations by the `calico-webhooks` admission webhook. Neither is an audit trail: a denied request appears in the API server's own audit log if audit logging is enabled, not in Calico's logs.

## Behavior change from the aggregated API server

A tier-restricted user must name a tier in the request:

```
kubectl get networkpolicies -l projectcalico.org/tier=production
```

Without a tier selector, the request is denied unless the user is unrestricted by tier, meaning their RBAC grant for the resource carries no `resourceNames` restriction at all. With the aggregated API server, the same command without a selector returned a filtered list instead of a denial. This is a consequence of the webhook seeing only the request attributes, not the tier field on stored objects: it can approve or deny a request, not filter a response.

## Certificate rotation

Not yet implemented. `calico-webhooks-tls` is a manually created secret (see the comment at the top of `charts/calico/templates/calico-webhooks.yaml`), and the `caBundle` fields in the admission webhook configuration and in `calico-authz-webhook-kubeconfig.yaml` are populated by hand from the same CA cert. Rotating the cert today means regenerating the secret and re-patching both `caBundle` fields; there is no automation for it yet.
