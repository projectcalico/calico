---
title: Selector-based policies
description: Apply ordered policies to endpoints that match specific label selectors.
canonical_url: '/reference/host-endpoints/selector'
---

We recommend using selector-based security policy with
host endpoints. This allows ordered policy to be applied to
endpoints that match particular label selectors.

For example, you could add a second policy for webserver access:

```bash
cat <<EOF | dist/calicoctl create -f -
- apiVersion: projectcalico.org/v3
  kind: GlobalNetworkPolicy
  metadata:
    name: webserver
  spec:
    selector: "role==\"webserver\""
    order: 100
    ingress:
    - action: Allow
      protocol: TCP
      destination:
        ports: [80]
    egress:
    - action: Allow
EOF
```
