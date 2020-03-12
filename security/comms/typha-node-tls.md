---
title: Provide TLS certificates for Typha and Node
description: Add TLS certificates to secure communications between if you are using Typha to scale your deployment.
---

### Big picture

Provide TLS certificates that allow mutual TLS authentication between Node and Typha.

### Value

By default, {{site.prodname}} Typha and Node components are configured with self-signed Certificate Authority (CA) and certificates for mutual TLS authentication. This article describes how to provide a CA and TLS certificates.

### Concepts

**Mutual TLS authentication** means each side of a connection authenticates the other side. As such, the CA and certificates that are used must all be in sync. If one side of the connection is updated with a certificate that is not compatible with the other side, communication stops. So if certificate updates are mismatched on Typha, Node, or CA certificate, new pod networking and policy application will be interrupted until you restore compatibility. To make it easy to keep updates in sync, this article describes how to use one command to apply updates for all resources.

### Before you begin...

**Get the Certificate Authority certificate and signed certificate and key pairs for {{site.prodname}} Typha and Node**
  - Generate the certificates using any X.509-compatible tool or from your organization's CA.
  - Ensure the generated certificates meet the requirements for [TLS connections between Node and Typha]({{site.baseurl}}/security/comms/crypto-auth#connections-from-node-to-typha-kubernetes).

### How to

#### Create resource file

1. Create the CA ConfigMap with the following commands:
   ```bash
   kubectl create configmap typha-ca -n tigera-operator --from-file=caBundle=</path/to/CA/cert> --dry-run -o yaml --save-config > typha-node-tls.yaml
   echo '---' >> typha-node-tls.yaml
   ```

1. Create the Typha Secret with the following command:
   ```bash
   kubectl create secret generic typha-certs -n tigera-operator \
     --from-file=cert.crt=</path/to/typha/cert> --from-file=key.key=</path/to/typha/key> \
     --from-literal=common-name=<typha certificate common name> --dry-run  -o yaml --save-config >> typha-node-tls.yaml
   echo '---' >> typha-node-tls.yaml
   ```

   > **Note**: If using SPIFFE identifiers replace `--from-literal=common-name=<typha certificate common name>` with `--from-literal=uri-san=<typha SPIFFE ID>`.
   {: .alert .alert-success}

1. Create the Node Secret with the following command:
   ```bash
   kubectl create configmap node-certs -n tigera-operator \
     --from-file=cert.crt=</path/to/node/cert> --from-file=key.key=</path/to/node/key> \
     --from-literal=common-name=<node certificate common name> >> typha-node-tls.yaml
   kubectl create secret generic node-certs -n tigera-operator \
     --from-file=cert.crt=</path/to/node/cert> --from-file=key.key=</path/to/node/key> \
     --from-literal=common-name=<node certificate common name> --dry-run  -o yaml --save-config >> typha-node-tls.yaml

   ```

   > **Note**: If using SPIFFE identifiers replace `--from-literal=common-name=<node certificate common name>` with `--from-literal=uri-san=<node SPIFFE ID>`.
   {: .alert .alert-success}

#### Apply or update resources

1. Apply the `typha-node-tls.yaml` file.
   - To create these resource for use during deployment, you must apply this file before applying `custom-resource.yaml` or before creating the Installation resource. To apply this file, use the following command:
     ```bash
     kubectl apply -f typha-node-tls.yaml
     ```
   - To update existing resources, use the following command:
     ```bash
     kubectl replace -f typha-node-tls.yaml
     ```

If {{site.prodname}} Node and Typha are already running, the update causes a rolling restart of both. If the new CA and certificates are not compatible with the previous set, there may be a period where the Node pods produce errors until the old set CA and certificates are replaced with the new ones.
