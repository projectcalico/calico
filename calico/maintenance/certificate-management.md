---
title: Manage TLS certificates used by Calico
description: Control the issuer of certificates used by Calico
---

### Big picture

Enable custom workflows for issuing and signing certificates used to secure communication between {{site.prodname}} components.

### Value

Some deployments have security requirements that strictly minimize or eliminate the access to private keys and/or 
requirements to control the trusted certificates throughout clusters. Using the Kubernetes Certificates API that automates 
certificate issuance, {{site.prodname}} provides a simple configuration option that you add to your installation.

### Before you begin

**Supported algorithms**
- Private Key Pair: RSA (size: 2048, 4096, 8192), ECDSA (curve: 256, 384, 521)
- Certificate Signature: RSA (sha: 256, 384, 512), ECDSA (sha: 256, 384, 512)

### How to
- [Enable certificate management](#enable-certificate-management)
- [Verify and monitor](#verify-and-monitor)
- [Implement your own signing/approval process](#implement-your-own-signing-and-approval-process)

#### Enable certificate management
1. Modify your [the installation resource]({{site.baseurl}}/reference/installation/api#operator.tigera.io/v1.Installation)
resource and add the `certificateManagement` section. Apply the following change to your cluster.
```
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
  certificateManagement:
       caCert: <Your CA Cert in Pem format>
       signerName: <your-domain>/<signer-name>
       signatureAlgorithm: SHA512WithRSA
       keyAlgorithm: RSAWithSize4096
```

Done! If you have an automatic signer and approver, there is nothing left to do. The next section explains in more detail
how to verify and monitor the status.

#### Verify and monitor
1. Monitor your pods as they come up:
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

1. Monitor certificate signing requests:
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
name and the first 6 characters of the pod's UID. The pod will be `Pending` until the CSR has been `Approved`.

1. Monitor the status of this feature using the `TigeraStatus`:
```
$ kubectl get tigerastatus
NAME     AVAILABLE   PROGRESSING   DEGRADED   SINCE
calico   True        False         False      2m40s
```
 
#### Implement your own signing and approval process

**Required steps**

This feature uses api version `certificates.k8s.io/v1beta1` for [certificate signing requests](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/). 
To automate the signing and approval process, run a server that performs the following actions:
1. Watch `CertificateSigningRequests` resources with status `Pending` and `spec.signerName=<your-signer-name>`.

   > **Note**: You can skip this step if you are using a version before Kubernetes v1.18; (the signerName field was not available).
   {: .alert .alert-info}

1. For each `Pending` CSR perform (security) checks (see next heading)
1. Issue a certificate and update `.spec.status.certificate`
1. Approve the CSR and update `.spec.status.conditions`

**Security requirements**

Based on your requirements you may want to implement custom checks to make sure that no certificates are issued for a malicious user.
When a CSR is created, the kube-apiserver adds immutable fields to the spec to help you perform checks:
- `.spec.username`: username of the requester
- `.spec.groups`: user groups of the requester
- `.spec.request`: certificate request in pem format

Verify that the user and/or group match with the requested certificate subject (alt) names.

**Implement your signer and approver using golang**
- Use [client-go](https://github.com/kubernetes/client-go) to create a clientset
- To watch CSRs, use `clientset.CertificatesV1().CertificateSigningRequests().Watch(..)`
- To issue the certificate use `clientset.CertificatesV1().CertificateSigningRequests().UpdateStatus(...)`
- To approve the CSR use `clientset.CertificatesV1().CertificateSigningRequests().UpdateApproval(...)`

#### Above and beyond
- Read [kubernetes certificate signing requests](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/) for more information on CSRs
- Use [client-go](https://github.com/kubernetes/client-go) to implement a controller to sign and approve a CSR
