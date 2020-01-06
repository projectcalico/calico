---
title: End user RBAC
canonical_url: '/getting-started/kubernetes/hardway/end-user-rbac'
---

In this lab we will set up role-based access control (RBAC) suitable for running the cluster in production. We will
cover roles for using {{site.prodname}}.  General RBAC for a production Kubernetes cluster is beyond the scope of this lab.

## Network admin

A network admin is a person responsible for configuring and operating the {{site.prodname}} network as a whole. As such, they
will need access to all {{site.prodname}} custom resources, as well as some associated Kubernetes resources.

Create the role

```
kubectl apply -f - <<EOF
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: network-admin
rules:
  - apiGroups: [""]
    resources:
      - pods
      - nodes
    verbs:
      - get
      - watch
      - list
      - update
  - apiGroups: [""]
    resources:
      - namespaces
      - serviceaccounts
    verbs:
      - get
      - watch
      - list
  - apiGroups: ["networking.k8s.io"]
    resources:
      - networkpolicies
    verbs: ["*"]
  - apiGroups: ["crd.projectcalico.org"]
    resources:
      - felixconfigurations
      - ipamblocks
      - blockaffinities
      - ipamhandles
      - ipamconfigs
      - bgppeers
      - bgpconfigurations
      - ippools
      - hostendpoints
      - clusterinformations
      - globalnetworkpolicies
      - globalnetworksets
      - networkpolicies
      - networksets
    verbs: ["*"]
EOF
```

To test out the network admin role, we'll create a user named Nik grant them the role.

On the Kubernetes master node, create the key and certificate signing request. Note that we include `/O=network-admins` in the subject. This places Nik in the `network-admins` group.

```
openssl req -newkey rsa:4096 \
           -keyout nik.key \
           -nodes \
           -out nik.csr \
           -subj "/O=network-admins/CN=nik"
```

We will sign this certificate using the main Kubernetes CA.

```
sudo openssl x509 -req -in nik.csr \
                  -CA /etc/kubernetes/pki/ca.crt \
                  -CAkey /etc/kubernetes/pki/ca.key \
                  -CAcreateserial \
                  -out nik.crt \
                  -days 365
sudo chown ubuntu:ubuntu nik.crt
```

Next, we create a kubeconfig file for Nik.

```
APISERVER=$(kubectl config view -o jsonpath='{.clusters[0].cluster.server}')
kubectl config set-cluster kubernetes \
    --certificate-authority=/etc/kubernetes/pki/ca.crt \
    --embed-certs=true \
    --server=$APISERVER \
    --kubeconfig=nik.kubeconfig

kubectl config set-credentials nik \
    --client-certificate=nik.crt \
    --client-key=nik.key \
    --embed-certs=true \
    --kubeconfig=nik.kubeconfig

kubectl config set-context default \
    --cluster=kubernetes \
    --user=nik \
    --kubeconfig=nik.kubeconfig

kubectl config use-context default --kubeconfig=nik.kubeconfig
```

Bind the role to the group `network-admins`.

```
kubectl create clusterrolebinding network-admins --clusterrole=network-admin --group=network-admins
```

Test Nik's access by creating a global network set

```
KUBECONFIG=./nik.kubeconfig calicoctl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  name: niks-set
spec:
  nets:
  - 110.120.130.0/24
  - 210.220.230.0/24
EOF
```

Verify the global network set exists

```
KUBECONFIG=./nik.kubeconfig calicoctl get globalnetworkset -o wide
```

Result

```
NAME       NETS
niks-set   110.120.130.0/24,210.220.230.0/24
```
{: .no-select-button}

Delete the global network set

```
KUBECONFIG=./nik.kubeconfig calicoctl delete globalnetworkset niks-set
```

## Service owner

A service owner is a person responsible for operating one or more services in Kubernetes. They should be able to define
network policy for their service, but don't need to view or modify any global configuration related to {{site.prodname}}.

Define the role

```
kubectl apply -f - <<EOF
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: network-service-owner
rules:
  - apiGroups: ["networking.k8s.io"]
    resources:
      - networkpolicies
    verbs: ["*"]
  - apiGroups: ["crd.projectcalico.org"]
    resources:
      - networkpolicies
      - networksets
    verbs: ["*"]
EOF
```

To test out the service owner role, we'll create a user named Sam and grant them the role.

On the Kubernetes master node, create the key and certificate signing request.

```
openssl req -newkey rsa:4096 \
           -keyout sam.key \
           -nodes \
           -out sam.csr \
           -subj "/CN=sam"
```

We will sign this certificate using the main Kubernetes CA.

```
sudo openssl x509 -req -in sam.csr \
                  -CA /etc/kubernetes/pki/ca.crt \
                  -CAkey /etc/kubernetes/pki/ca.key \
                  -CAcreateserial \
                  -out sam.crt \
                  -days 365
sudo chown ubuntu:ubuntu sam.crt
```

Next, we create a kubeconfig file for Sam.

```
APISERVER=$(kubectl config view -o jsonpath='{.clusters[0].cluster.server}')
kubectl config set-cluster kubernetes \
    --certificate-authority=/etc/kubernetes/pki/ca.crt \
    --embed-certs=true \
    --server=$APISERVER \
    --kubeconfig=sam.kubeconfig

kubectl config set-credentials sam \
    --client-certificate=sam.crt \
    --client-key=sam.key \
    --embed-certs=true \
    --kubeconfig=sam.kubeconfig

kubectl config set-context default \
    --cluster=kubernetes \
    --user=sam \
    --kubeconfig=sam.kubeconfig

kubectl config use-context default --kubeconfig=sam.kubeconfig
```

We will limit Sam's access to a single namespace.  Create the namespace

```
kubectl create namespace sam
```

Bind the role to Sam in the namespace

```
kubectl create rolebinding -n sam network-service-owner-sam --clusterrole=network-service-owner --user=sam
```

Sam cannot create global network set resources (like Nik can as network admin)

```
KUBECONFIG=./sam.kubeconfig calicoctl get globalnetworkset -o wide
```

Result

```
connection is unauthorized: globalnetworksets.crd.projectcalico.org is forbidden: User "sam" cannot list resource "globalnetworksets" in API group "crd.projectcalico.org" at the cluster scope
```
{: .no-select-button}

However, Sam can create resources in their own namespace

```
KUBECONFIG=./sam.kubeconfig calicoctl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: NetworkSet
metadata:
  name: sams-set
  namespace: sam
spec:
  nets:
  - 110.120.130.0/24
  - 210.220.230.0/24
EOF
```

Verify the resource exists

```
KUBECONFIG=./sam.kubeconfig calicoctl get networksets -n sam
```

Result

```
NAMESPACE   NAME
sam         sams-set
```
{: .no-select-button}

Delete the NetworkSet

```
KUBECONFIG=./sam.kubeconfig calicoctl delete networkset sams-set -n sam
```

## Next

[Istio integration](./istio-integration)
