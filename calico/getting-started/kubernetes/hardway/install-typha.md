---
title: Install Typha
description: Learn about Typha for scaling deployment.
canonical_url: '/getting-started/kubernetes/hardway/install-typha'
---

**Typha** sits between the Kubernetes API server and per-node daemons like **Felix** and **confd** (running in `calico/node`).
It watches the Kubernetes resources and {{site.prodname}} custom resources used by these daemons, and whenever a resource changes
it fans out the update to the daemons. This reduces the number of watches the Kubernetes API server needs to serve
and improves scalability of the cluster.

## Provision Certificates

We will use mutually authenticated TLS to ensure that `calico/node` and Typha communicate securely. In this section, we generate a
certificate authority (CA) and use it to sign a certificate for Typha.

Create the CA certificate and key
```bash
openssl req -x509 -newkey rsa:4096 \
                  -keyout typhaca.key \
                  -nodes \
                  -out typhaca.crt \
                  -subj "/CN=Calico Typha CA" \
                  -days 365
```

Store the CA certificate in a ConfigMap that Typha & `calico/node` will access.
```bash
kubectl create configmap -n kube-system calico-typha-ca --from-file=typhaca.crt
```

Create the Typha key and certificate signing request (CSR)
```bash
openssl req -newkey rsa:4096 \
           -keyout typha.key \
           -nodes \
           -out typha.csr \
           -subj "/CN=calico-typha"
```

The certificate presents the Common Name (CN) as `calico-typha`. `calico/node` will be configured to verify this name.

Sign the Typha certificate with the CA
```bash
openssl x509 -req -in typha.csr \
                  -CA typhaca.crt \
                  -CAkey typhaca.key \
                  -CAcreateserial \
                  -out typha.crt \
                  -days 365
```

Store the Typha key and certificate in a secret that Typha will access

```bash
kubectl create secret generic -n kube-system calico-typha-certs --from-file=typha.key --from-file=typha.crt
```

## Provision RBAC

Create a ServiceAccount that will be used to run Typha.

```bash
kubectl create serviceaccount -n kube-system calico-typha
```

Define a cluster role for Typha with permission to watch {{site.prodname}} datastore objects.

```bash
kubectl apply -f - <<EOF
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: calico-typha
rules:
  - apiGroups: [""]
    resources:
      - pods
      - namespaces
      - serviceaccounts
      - endpoints
      - services
      - nodes
    verbs:
      # Used to discover service IPs for advertisement.
      - watch
      - list
  - apiGroups: ["networking.k8s.io"]
    resources:
      - networkpolicies
    verbs:
      - watch
      - list
  - apiGroups: ["crd.projectcalico.org"]
    resources:
      - globalfelixconfigs
      - felixconfigurations
      - bgppeers
      - globalbgpconfigs
      - bgpconfigurations
      - ippools
      - ipamblocks
      - globalnetworkpolicies
      - globalnetworksets
      - networkpolicies
      - clusterinformations
      - hostendpoints
      - blockaffinities
      - networksets
    verbs:
      - get
      - list
      - watch
  - apiGroups: ["crd.projectcalico.org"]
    resources:
      #- ippools
      #- felixconfigurations
      - clusterinformations
    verbs:
      - get
      - create
      - update
EOF
```

Bind the cluster role to the `calico-typha` ServiceAccount.

```bash
kubectl create clusterrolebinding calico-typha --clusterrole=calico-typha --serviceaccount=kube-system:calico-typha
```

## Install Deployment

Since Typha is required by `calico/node`, and `calico/node` establishes the pod network, we run Typha as a host networked pod to avoid
a chicken-and-egg problem.  We run 3 replicas of Typha so that even during a rolling update, a single failure does not
make Typha unavailable.

```bash
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: calico-typha
  namespace: kube-system
  labels:
    k8s-app: calico-typha
spec:
  replicas: 3
  revisionHistoryLimit: 2
  selector:
    matchLabels:
      k8s-app: calico-typha
  template:
    metadata:
      labels:
        k8s-app: calico-typha
      annotations:
        cluster-autoscaler.kubernetes.io/safe-to-evict: 'true'
    spec:
      hostNetwork: true
      tolerations:
        # Mark the pod as a critical add-on for rescheduling.
        - key: CriticalAddonsOnly
          operator: Exists
      serviceAccountName: calico-typha
      priorityClassName: system-cluster-critical
      containers:
      - image: calico/typha:v3.8.0
        name: calico-typha
        ports:
        - containerPort: 5473
          name: calico-typha
          protocol: TCP
        env:
          # Disable logging to file and syslog since those don't make sense in Kubernetes.
          - name: TYPHA_LOGFILEPATH
            value: "none"
          - name: TYPHA_LOGSEVERITYSYS
            value: "none"
          # Monitor the Kubernetes API to find the number of running instances and rebalance
          # connections.
          - name: TYPHA_CONNECTIONREBALANCINGMODE
            value: "kubernetes"
          - name: TYPHA_DATASTORETYPE
            value: "kubernetes"
          - name: TYPHA_HEALTHENABLED
            value: "true"
          # Location of the CA bundle Typha uses to authenticate calico/node; volume mount
          - name: TYPHA_CAFILE
            value: /calico-typha-ca/typhaca.crt
          # Common name on the calico/node certificate
          - name: TYPHA_CLIENTCN
            value: calico-node
          # Location of the server certificate for Typha; volume mount
          - name: TYPHA_SERVERCERTFILE
            value: /calico-typha-certs/typha.crt
          # Location of the server certificate key for Typha; volume mount
          - name: TYPHA_SERVERKEYFILE
            value: /calico-typha-certs/typha.key
        livenessProbe:
          httpGet:
            path: /liveness
            port: 9098
            host: localhost
          periodSeconds: 30
          initialDelaySeconds: 30
        readinessProbe:
          httpGet:
            path: /readiness
            port: 9098
            host: localhost
          periodSeconds: 10
        volumeMounts:
        - name: calico-typha-ca
          mountPath: "/calico-typha-ca"
          readOnly: true
        - name: calico-typha-certs
          mountPath: "/calico-typha-certs"
          readOnly: true
      volumes:
      - name: calico-typha-ca
        configMap:
          name: calico-typha-ca
      - name: calico-typha-certs
        secret:
          secretName: calico-typha-certs
EOF
```

We set `TYPHA_CLIENTCN` to `calico-node` which is the common name we will use on the certificate `calico/node` will use in the
next lab.

Verify Typha is up an running with three instances

```bash
kubectl get pods -l k8s-app=calico-typha -n kube-system
```

Result:

```
NAME                            READY   STATUS    RESTARTS   AGE
calico-typha-66498ddfbd-2pzsr   1/1     Running   0          69s
calico-typha-66498ddfbd-lrtzw   1/1     Running   0          50s
calico-typha-66498ddfbd-scckd   1/1     Running   0          62s
```
{: .no-select-button}

## Install Service

`calico/node` uses a Kubernetes Service to get load-balanced access to Typha.

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: calico-typha
  namespace: kube-system
  labels:
    k8s-app: calico-typha
spec:
  ports:
    - port: 5473
      protocol: TCP
      targetPort: calico-typha
      name: calico-typha
  selector:
    k8s-app: calico-typha
EOF
```

Validate that Typha is using TLS.

```bash
TYPHA_CLUSTERIP=$(kubectl get svc -n kube-system calico-typha -o jsonpath='{.spec.clusterIP}')
curl https://$TYPHA_CLUSTERIP:5473 -v --cacert typhaca.crt
```

Result
```
* Rebuilt URL to: https://10.103.120.116:5473/
*   Trying 10.103.120.116...
* TCP_NODELAY set
* Connected to 10.103.120.116 (10.103.120.116) port 5473 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: typhaca.crt
  CApath: /etc/ssl/certs
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Request CERT (13):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Certificate (11):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Client hello (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS alert, Server hello (2):
* error:14094412:SSL routines:ssl3_read_bytes:sslv3 alert bad certificate
* stopped the pause stream!
* Closing connection 0
curl: (35) error:14094412:SSL routines:ssl3_read_bytes:sslv3 alert bad certificate
```
{: .no-select-button}

This demonstrates that Typha is presenting its TLS certificate and rejecting our connection because we do not present a certificate.
In the next lab we will deploy `calico/node` with a certificate Typha will accept.

## Next

[Install calico/node](./install-node)
