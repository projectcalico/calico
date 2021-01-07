---
title: Manage TLS certificates used by Calico
description: Control the issuer of certificates used by Calico
---

### Big picture

Bring your own certificate request signer and approver and have control over the TLS certificates for {{site.prodname}} components.

### Value

- With this feature enabled private keys will never be stored outside of the pod that uses it.
- Have control over the trusted certificates in your cluster.

### How to

#### Enable certificate management
This section covers how to enable certificate management in a single step, followed by three ways to monitor and verify that the feature works as expected. 

1. Modify your [the installation reference]({{site.baseurl}}/reference/installation/api#operator.tigera.io/v1.Installation)
resource and add the `certificateManagement` section. Apply the following change to your cluster.
```
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
...
  certificateManagement:
    rootCA: <Your CA Cert in Pem format>
    signerName: <your-domain>/<signer-name>
    signatureAlgorithm: SHA512WithRSA # Optional
    keyAlgorithm: RSAWithSize4096 # Optional
...
```

Done! If you have an automatic signer and approver, there is nothing left to do. The following steps explain in more detail what just happened.

1. (Optional) Monitor your pods as they come up:
```
$ kubectl get pod -n calico-system -w
NAMESPACE                  NAME                                       READY   STATUS             RESTARTS   AGE
calico-system              calico-node-5ckvq                          0/1     Pending            0          0s
calico-system              calico-typha-688c9957f5-h9c5w              0/1     Pending            0          0s
calico-system              calico-node-5ckvq                          0/1     Init:0/3           0          1s
calico-system              calico-typha-688c9957f5-h9c5w              0/1     Init:0/1           0          1s
calico-system              calico-node-5ckvq                          0/1     PodInitializing    0          2s
calico-system              calico-typha-688c9957f5-h9c5w              0/1     PodInitializing    0          2s
calico-system              calico-node-5ckvq                          1/1     Running            0          3s
calico-system              calico-typha-688c9957f5-h9c5w              1/1     Running            0          3s
```
During the `Init` phase a certificate signing request (CSR) is created by an init container of the pod. It will be stuck in the 
`Init` phase. Once the CSR has been approved and signed by the certificate authority, the pod continues with `PodInitializing`
and eventually `Running`.

1. (Optional) Monitor certificate signing requests:
```
$ kubectl get csr -w
NAME                                                 AGE   REQUESTOR                                          CONDITION
calico-system:calico-node-5ckvq:9a3a10               0s    system:serviceaccount:calico-system:calico-node    Pending
calico-system:calico-node-5ckvq:9a3a10               0s    system:serviceaccount:calico-system:calico-node    Pending,Issued
calico-system:calico-node-5ckvq:9a3a10               0s    system:serviceaccount:calico-system:calico-node    Approved,Issued
calico-system:typha-688c9957f5-h9c5w:2b0d82          0s    system:serviceaccount:calico-system:calico-typha   Pending
calico-system:typha-688c9957f5-h9c5w:2b0d82          0s    system:serviceaccount:calico-system:calico-typha   Pending,Issued
calico-system:typha-688c9957f5-h9c5w:2b0d82          0s    system:serviceaccount:calico-system:calico-typha   Approved,Issued
```
A CSR will be `Pending` until it has been `Issued` and `Approved`. The name of a CSR is based on the namespace, the pod
name and the first 6 characters of the pod's UID. The pod will be `Pending` until the CSR has been `Approved`

1. (Optional) Monitor the status of this feature using the `TigeraStatus`:
```
$ kubectl get tigerastatus
NAME     AVAILABLE   PROGRESSING   DEGRADED   SINCE
calico   True        False         False      2m40s
```
 
#### Implement your own signing and approval process

**Necessary steps**

This feature uses api version `certificates.k8s.io/v1beta1` for [certificate signing requests](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/). 
To automate signing and approval process,
you want to run a server that performs the following actions:
1. Watch `CertificateSigningRequests` resources with status `Pending` and `spec.signerName=<your-signer-name>`
1. For each `Pending` CSR perform (security) checks (see next heading)
1. Issue a certificate and update `.spec.status.certificate`
1. Approve the CSR and update `.spec.status.conditions`

> **Note**: The signerName field was introduced in [Kubernetes v1.18](https://github.com/kubernetes/kubernetes/pull/86476). If you use an older version, you should skip the signerName check in step 1.
{: .alert .alert-info}

**Security checks**

Based on your requirements you may want to implement custom checks to make sure that no certificates are issued for a malicious user.
When a CSR is created, the kube-apiserver adds immutable fields to the spec to help you perform checks:
- `.spec.username` contains the username of the requester.
- `.spec.groups` contains the groups that the requester belongs to.
- `.spec.request` contains the certificate request in pem format. Verify that the user and/or group match with the requested certificate subject (alt) names.

**Implement your signer and approver using golang**
- Use [client-go](https://github.com/kubernetes/client-go) to create a clientset
- To watch CSRs, use `clientset.CertificatesV1beta1().CertificateSigningRequests().Watch(..)`
- To issue the certificate use `clientset.CertificatesV1beta1().CertificateSigningRequests().UpdateStatus(...)`
- To approve the CSR use `clientset.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(...)`

#### Further reading
- Read [kubernetes certificate signing requests](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/) for more information on CSRs.
- Use [client-go](https://github.com/kubernetes/client-go) to implement a controller to sign and approve a CSR.
