---
name: setup-whisker-test-traffic
description: Deploy workloads and Calico policies to generate diverse, continuous flow logs for testing Whisker filters. Use when you need flow logs covering multiple namespaces, policy kinds, tiers, actions (Allow/Deny), reporters (Src/Dst), ports, and protocols.
---

## Overview

Sets up a complete test environment on an existing cluster with Calico and Whisker deployed. Deploys workloads across multiple namespaces with continuous traffic generators, plus Calico policies across multiple tiers and kinds, to produce diverse flow logs for exercising all Whisker filters.

## Prerequisites

- A running Kubernetes cluster with Calico installed (kind cluster or other)
- Whisker and Goldmane pods running in `calico-system`
- `kubectl` access configured

## Step 1: Create Namespaces and Workloads

Create 4 namespaces with services that traffic generators will target:

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: frontend
---
apiVersion: v1
kind: Namespace
metadata:
  name: backend
---
apiVersion: v1
kind: Namespace
metadata:
  name: database
---
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
---
# Frontend: nginx on port 80
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: frontend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
        role: frontend
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: frontend
spec:
  selector:
    app: web
  ports:
  - port: 80
    targetPort: 80
---
# Backend: nginx on port 8080
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: backend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
        role: backend
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: backend
spec:
  selector:
    app: api
  ports:
  - port: 8080
    targetPort: 80
---
# Database: TCP listener on 5432
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: database
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
        role: database
    spec:
      containers:
      - name: listener
        image: busybox:1.36
        command: ["sh", "-c", "while true; do nc -l -p 5432 -e echo ok; sleep 0.1; done"]
        ports:
        - containerPort: 5432
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: database
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
---
# Monitoring: nginx on port 9090
apiVersion: apps/v1
kind: Deployment
metadata:
  name: metrics
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: metrics
  template:
    metadata:
      labels:
        app: metrics
        role: monitoring
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: metrics
  namespace: monitoring
spec:
  selector:
    app: metrics
  ports:
  - port: 9090
    targetPort: 80
EOF
```

## Step 2: Deploy Traffic Generators

One traffic-gen pod per namespace, each hitting multiple services every ~3 seconds. This produces flows with diverse source/dest namespace and name combinations, multiple ports (80, 8080, 5432, 9090, 53), and both TCP and UDP protocols.

```bash
cat <<'EOF' | kubectl apply -f -
# Frontend traffic-gen: hits backend, monitoring, database, does DNS lookups
apiVersion: apps/v1
kind: Deployment
metadata:
  name: traffic-gen
  namespace: frontend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: traffic-gen
  template:
    metadata:
      labels:
        app: traffic-gen
        role: client
    spec:
      containers:
      - name: curl
        image: curlimages/curl:latest
        command:
        - sh
        - -c
        - |
          while true; do
            curl -s -o /dev/null -m 2 http://api.backend.svc.cluster.local:8080/ &
            curl -s -o /dev/null -m 2 http://web.frontend.svc.cluster.local/ &
            curl -s -o /dev/null -m 2 http://metrics.monitoring.svc.cluster.local:9090/ &
            nslookup api.backend.svc.cluster.local > /dev/null 2>&1 &
            nslookup postgres.database.svc.cluster.local > /dev/null 2>&1 &
            nc -z -w 2 postgres.database.svc.cluster.local 5432 &
            wait
            sleep 3
          done
---
# Backend traffic-gen: hits frontend, monitoring, database
apiVersion: apps/v1
kind: Deployment
metadata:
  name: traffic-gen
  namespace: backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: traffic-gen
  template:
    metadata:
      labels:
        app: traffic-gen
        role: client
    spec:
      containers:
      - name: curl
        image: curlimages/curl:latest
        command:
        - sh
        - -c
        - |
          while true; do
            curl -s -o /dev/null -m 2 http://web.frontend.svc.cluster.local/ &
            curl -s -o /dev/null -m 2 http://metrics.monitoring.svc.cluster.local:9090/ &
            nc -z -w 2 postgres.database.svc.cluster.local 5432 &
            nslookup web.frontend.svc.cluster.local > /dev/null 2>&1 &
            wait
            sleep 3
          done
---
# Monitoring traffic-gen: hits frontend, backend, database
apiVersion: apps/v1
kind: Deployment
metadata:
  name: traffic-gen
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: traffic-gen
  template:
    metadata:
      labels:
        app: traffic-gen
        role: client
    spec:
      containers:
      - name: curl
        image: curlimages/curl:latest
        command:
        - sh
        - -c
        - |
          while true; do
            curl -s -o /dev/null -m 2 http://web.frontend.svc.cluster.local/ &
            curl -s -o /dev/null -m 2 http://api.backend.svc.cluster.local:8080/ &
            nc -z -w 2 postgres.database.svc.cluster.local 5432 &
            nslookup metrics.monitoring.svc.cluster.local > /dev/null 2>&1 &
            wait
            sleep 3
          done
---
# Database traffic-gen: tries to reach frontend and backend (will be denied by policies)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: traffic-gen
  namespace: database
spec:
  replicas: 1
  selector:
    matchLabels:
      app: traffic-gen
  template:
    metadata:
      labels:
        app: traffic-gen
        role: client
    spec:
      containers:
      - name: curl
        image: curlimages/curl:latest
        command:
        - sh
        - -c
        - |
          while true; do
            curl -s -o /dev/null -m 2 http://web.frontend.svc.cluster.local/ &
            curl -s -o /dev/null -m 2 http://api.backend.svc.cluster.local:8080/ &
            nslookup web.frontend.svc.cluster.local > /dev/null 2>&1 &
            wait
            sleep 3
          done
EOF
```

## Step 3: Create Calico Tiers

Create 4 custom tiers at different orders to test tier filtering:

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: compliance
spec:
  order: 50
---
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: security
spec:
  order: 100
---
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: platform
spec:
  order: 200
---
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: application
spec:
  order: 300
EOF
```

## Step 4: Create Enforced Policies (CalicoNetworkPolicy + GlobalNetworkPolicy)

These generate Allow, Deny, and Pass action flows across multiple tiers and namespaces:

```bash
cat <<'EOF' | kubectl apply -f -
# --- compliance tier (GlobalNetworkPolicies) ---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: restrict-external-access
spec:
  tier: compliance
  order: 100
  selector: all()
  types:
  - Egress
  egress:
  - action: Deny
    destination:
      nets: ["0.0.0.0/0"]
      notNets: ["10.0.0.0/8"]
  - action: Pass
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: audit-all-ingress
spec:
  tier: compliance
  order: 200
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Pass
---
# --- security tier (Deny policies for database + frontend) ---
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: deny-db-to-frontend
  namespace: database
spec:
  tier: security
  order: 100
  selector: role == 'client'
  types:
  - Egress
  egress:
  - action: Deny
    destination:
      namespaceSelector: kubernetes.io/metadata.name == 'frontend'
  - action: Pass
---
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: deny-db-to-backend
  namespace: database
spec:
  tier: security
  order: 110
  selector: role == 'client'
  types:
  - Egress
  egress:
  - action: Deny
    destination:
      namespaceSelector: kubernetes.io/metadata.name == 'backend'
  - action: Pass
---
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: isolate-db-ingress
  namespace: database
spec:
  tier: security
  order: 50
  selector: app == 'postgres'
  types:
  - Ingress
  ingress:
  - action: Allow
    source:
      namespaceSelector: kubernetes.io/metadata.name == 'backend'
  - action: Deny
---
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: frontend-ingress-control
  namespace: frontend
spec:
  tier: security
  order: 100
  selector: app == 'web'
  types:
  - Ingress
  ingress:
  - action: Allow
    source:
      namespaceSelector: kubernetes.io/metadata.name == 'monitoring'
  - action: Allow
    source:
      namespaceSelector: kubernetes.io/metadata.name == 'frontend'
  - action: Deny
    source:
      namespaceSelector: kubernetes.io/metadata.name == 'database'
  - action: Pass
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-monitoring-to-db
spec:
  tier: security
  order: 120
  namespaceSelector: kubernetes.io/metadata.name == 'monitoring'
  selector: app == 'traffic-gen'
  types:
  - Egress
  egress:
  - action: Deny
    destination:
      namespaceSelector: kubernetes.io/metadata.name == 'database'
  - action: Pass
---
# --- platform tier (Allow policies) ---
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: frontend
spec:
  tier: platform
  order: 100
  selector: app == 'traffic-gen'
  types:
  - Egress
  egress:
  - action: Allow
    destination:
      namespaceSelector: kubernetes.io/metadata.name == 'backend'
  - action: Pass
---
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-backend-to-db
  namespace: backend
spec:
  tier: platform
  order: 100
  selector: app == 'traffic-gen'
  types:
  - Egress
  egress:
  - action: Allow
    destination:
      namespaceSelector: kubernetes.io/metadata.name == 'database'
  - action: Pass
---
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: backend-to-monitoring
  namespace: backend
spec:
  tier: platform
  order: 200
  selector: app == 'traffic-gen'
  types:
  - Egress
  egress:
  - action: Allow
    destination:
      namespaceSelector: kubernetes.io/metadata.name == 'monitoring'
  - action: Pass
---
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: monitoring-egress-allow
  namespace: monitoring
spec:
  tier: platform
  order: 100
  selector: app == 'traffic-gen'
  types:
  - Egress
  egress:
  - action: Allow
    protocol: TCP
    destination:
      ports: [80, 8080]
  - action: Pass
---
# --- application tier (fine-grained app policies) ---
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: frontend-rate-limit
  namespace: frontend
spec:
  tier: application
  order: 100
  selector: app == 'traffic-gen'
  types:
  - Egress
  egress:
  - action: Allow
    protocol: TCP
    destination:
      ports: [80, 8080, 5432, 9090]
  - action: Allow
    protocol: UDP
    destination:
      ports: [53]
  - action: Deny
---
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: api-server-policy
  namespace: backend
spec:
  tier: application
  order: 100
  selector: app == 'api'
  types:
  - Ingress
  ingress:
  - action: Allow
    protocol: TCP
    destination:
      ports: [80]
  - action: Deny
---
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: postgres-access-control
  namespace: database
spec:
  tier: application
  order: 100
  selector: app == 'postgres'
  types:
  - Ingress
  ingress:
  - action: Allow
    protocol: TCP
    destination:
      ports: [5432]
    source:
      namespaceSelector: kubernetes.io/metadata.name == 'backend'
  - action: Pass
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: restrict-udp-non-dns
spec:
  tier: application
  order: 200
  selector: role == 'client'
  types:
  - Egress
  egress:
  - action: Allow
    protocol: UDP
    destination:
      ports: [53]
  - action: Deny
    protocol: UDP
  - action: Pass
EOF
```

## Step 5: Create Kubernetes NetworkPolicies

These produce flows with `kind: NetworkPolicy` (K8s native) to test the Kind filter:

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k8s-allow-web-ingress
  namespace: frontend
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 80
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k8s-restrict-db
  namespace: database
spec:
  podSelector:
    matchLabels:
      app: postgres
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: backend
    ports:
    - protocol: TCP
      port: 5432
EOF
```

## Step 6: Create Staged Policies

These produce pending/staged action flows to test the Staged Action filter and policy trace pending section:

```bash
cat <<'EOF' | kubectl apply -f -
# Staged GlobalNetworkPolicy in default tier (staged Allow)
apiVersion: projectcalico.org/v3
kind: StagedGlobalNetworkPolicy
metadata:
  name: staged-allow-all
spec:
  tier: default
  order: 9999
  selector: all()
  types:
  - Ingress
  - Egress
  ingress:
  - action: Allow
  egress:
  - action: Allow
---
# Staged GlobalNetworkPolicy in compliance tier (staged Deny)
apiVersion: projectcalico.org/v3
kind: StagedGlobalNetworkPolicy
metadata:
  name: staged-compliance-deny-all
spec:
  tier: compliance
  order: 9000
  selector: all()
  types:
  - Ingress
  - Egress
  ingress:
  - action: Deny
  egress:
  - action: Deny
---
# Staged NetworkPolicy in default tier (staged Deny for frontend)
apiVersion: projectcalico.org/v3
kind: StagedNetworkPolicy
metadata:
  name: staged-deny-frontend-egress
  namespace: frontend
spec:
  tier: default
  order: 50
  selector: app == 'web'
  types:
  - Egress
  egress:
  - action: Deny
---
# Staged NetworkPolicy in security tier (staged isolation for backend)
apiVersion: projectcalico.org/v3
kind: StagedNetworkPolicy
metadata:
  name: staged-isolate-backend
  namespace: backend
spec:
  tier: security
  order: 50
  selector: all()
  types:
  - Ingress
  - Egress
  ingress:
  - action: Allow
    source:
      namespaceSelector: kubernetes.io/metadata.name == 'frontend'
  - action: Deny
  egress:
  - action: Allow
    destination:
      namespaceSelector: kubernetes.io/metadata.name == 'database'
  - action: Deny
---
# Staged NetworkPolicy in platform tier (staged monitoring lockdown)
apiVersion: projectcalico.org/v3
kind: StagedNetworkPolicy
metadata:
  name: staged-monitoring-lockdown
  namespace: monitoring
spec:
  tier: platform
  order: 50
  selector: all()
  types:
  - Ingress
  ingress:
  - action: Allow
    protocol: TCP
    destination:
      ports: [9090]
  - action: Deny
---
# Staged Kubernetes NetworkPolicy
apiVersion: projectcalico.org/v3
kind: StagedKubernetesNetworkPolicy
metadata:
  name: staged-k8s-deny-all-monitoring
  namespace: monitoring
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF
```

## Step 7: Verify

Wait ~30 seconds for flow logs to populate, then verify diversity:

```bash
# Check all pods are running
for ns in frontend backend database monitoring; do
  kubectl get pods -n "$ns"
done

# Check flow logs are streaming with diverse data
curl -s "http://localhost:8081/whisker-backend/flows?watch=true&startTimeGte=-60" --max-time 8 2>&1 | grep -o '"action":"[^"]*"' | sort | uniq -c | sort -rn
```

Expected output should show Allow, Deny, and Pass actions.

## What This Covers

| Whisker Filter | Coverage |
|---|---|
| Source Namespace | frontend, backend, database, monitoring, calico-system, kube-system |
| Dest Namespace | frontend, backend, database, monitoring, kube-system, calico-system |
| Source/Dest Name | traffic-gen-*, web-*, api-*, postgres-*, metrics-*, coredns-*, goldmane-* |
| Port | 53, 80, 5432, 7443, 8080, 9090 |
| Protocol | TCP, UDP |
| Reporter | Src, Dst |
| Action | Allow, Deny, Pass |
| Policy Kind | CalicoNetworkPolicy, GlobalNetworkPolicy, NetworkPolicy, Profile, StagedGlobalNetworkPolicy, StagedNetworkPolicy, StagedKubernetesNetworkPolicy |
| Policy Tier | compliance, security, platform, application, default, calico-system |
| Policy Namespace | frontend, backend, database, monitoring, calico-system, "" (global) |
| Staged Action | Allow (staged-allow-all), Deny (staged-compliance-deny-all, staged-deny-frontend-egress, staged-isolate-backend, staged-monitoring-lockdown) |

## Cleanup

```bash
kubectl delete namespace frontend backend database monitoring
kubectl delete tier compliance security platform application
kubectl delete globalnetworkpolicy restrict-external-access audit-all-ingress deny-monitoring-to-db restrict-udp-non-dns
kubectl delete stagedglobalnetworkpolicy staged-allow-all staged-compliance-deny-all
```
