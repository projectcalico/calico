# Calico tiered RBAC authorization webhook

Enforces Calico tier-based RBAC on GET/LIST/WATCH of tiered policy resources (`NetworkPolicy`, `GlobalNetworkPolicy`, and their staged variants) for clusters that run Calico's v3 API as CRDs rather than through the aggregated API server. Mutations (CREATE/UPDATE/DELETE) are covered separately by the `calico-webhooks` admission webhook, which unlike this one can read the object body.

## Applicability

Self-hosted clusters only. `--authorization-config` cannot be set on EKS, AKS, or GKE, and the config file has to be placed on the control-plane nodes. If you don't manage the API server's flags directly, this webhook does not apply to you.

Requires Kubernetes 1.32 or later. `apiserver.config.k8s.io/v1 AuthorizationConfiguration`, the `apiVersion` this file uses, only exists from 1.32 onward: the `StructuredAuthorizationConfiguration` feature went GA (locked on) in 1.32, after alpha in 1.29 and beta in 1.30. An apiserver older than 1.32 does not recognize this `apiVersion` and refuses to start with `--authorization-config` pointed at this file.

## Install

1. Apply the chart with `useV3CRDs` enabled so `calico-webhooks` is deployed:

   ```
   helm upgrade calico charts/calico --install -n kube-system --set useV3CRDs=true
   ```

   `useV3CRDs` is the CRD-mode gate, not a webhook-specific value; there is no separate flag to enable `calico-webhooks` today.

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

## Operator-managed installs

Not supported yet. The install above is the Helm chart path, and it is the only one that works today. On an operator-managed cluster the operator renders `calico-webhooks` itself (`pkg/render/webhooks` in tigera/operator), and three things block this webhook there:

- The webhook's ClusterRole grants `create` on `subjectaccessreviews` and `get` on `tiers`, but no `get`/`list`/`watch` on the tiered policy resources the authorizer's policy cache needs. The cache never syncs, the pod never goes ready, and under `failurePolicy: Deny` that denies the whole `projectcalico.org` group.
- The rendered Service has no `clusterIP`, so there is no way to pin the address the kubeconfig has to name. The chart pins it via `authzWebhookClusterIP`.
- The operator installs into `calico-system`, while the exempt identities in `authorization-configuration.yaml` are `kube-system` service accounts, and the operator's own service account is not exempt at all. Bootstrap deadlocks.

There is also no operator API surface for `--authorization-config` itself, which is a control-plane flag and outside what the operator manages.

## Break-glass

`failurePolicy: Deny` means an unreachable webhook denies every request the `matchConditions` route to it, not just the reads the webhook itself would otherwise have denied. The first `matchCondition` matches the entire `projectcalico.org` group with no verb or resource guard, so an outage denies every verb (including writes) on every resource in that group (not just tiered policy), for every identity not on the exempt list. Concretely: a webhook outage can block `kubectl apply` of an `IPPool` or `FelixConfiguration`, and `calico-cni-plugin`, which reads IP pools through this group in `useV3CRDs` mode, is not on the exempt list, so pod setup can fail too. Causes include the webhook pod being down, a cert that expired, or a dataplane failure that keeps `calico-webhooks` from starting.

To restore access, edit `authorization-configuration.yaml` on each control-plane node and either:

- delete the `calico-tiered-rbac` entry from `authorizers`, or
- set its `failurePolicy` to `NoOpinion`.

Kubernetes documents `kube-apiserver` as reloading `--authorization-config` from disk automatically, without a flag or restart; this repo has not independently verified that reload path. If reads are still denied after editing the file, restart `kube-apiserver` as the fallback. Two things worth knowing while debugging a break-glass edit: an invalid config file is rejected and the last-known-good configuration keeps running, which during an outage looks identical to "the edit did not take"; and the apiserver's `apiserver_authorization_config_controller_automatic_reload_last_timestamp_seconds` metric shows whether and when the reload actually happened.

## What this does not cover

Reads are covered by this webhook, mutations by the `calico-webhooks` admission webhook. Neither is an audit trail: a denied request appears in the API server's own audit log if audit logging is enabled, not in Calico's logs.

## Behavior change from the aggregated API server

A tier-restricted user must name a tier in the request:

```
kubectl get networkpolicies -l projectcalico.org/tier=production
```

Without a tier selector, the request is denied unless the user is unrestricted by tier, meaning their RBAC grant on `tiers` (not on the policy resource itself) carries no `resourceNames` restriction. With the aggregated API server, the same command without a selector returned a filtered list instead of a denial. This is a consequence of the webhook seeing only the request attributes, not the tier field on stored objects: it can approve or deny a request, not filter a response.

## Certificate rotation

Not yet implemented. `calico-webhooks-tls` is a manually created secret (see the comment at the top of `charts/calico/templates/calico-webhooks.yaml`), and both the `ValidatingWebhookConfiguration`'s `caBundle` field and `calico-authz-webhook-kubeconfig.yaml`'s `certificate-authority` file are populated by hand from the same CA cert; the kubeconfig references the CA by file path, not by an inline field. Rotating the cert today means regenerating the secret, re-patching the `caBundle` field, and replacing the CA cert file referenced by `certificate-authority` on every control-plane node; there is no automation for it yet.
