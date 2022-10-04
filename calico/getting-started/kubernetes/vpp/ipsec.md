---
title: IPsec configuration with VPP
description: Enable IPsec for faster encryption between nodes when using the VPP dataplane.
canonical_url: '/getting-started/kubernetes/vpp/ipsec'
---

### Big picture

Enable IPsec encryption for the traffic flowing between the nodes.

### Value

IPsec is the fastest option to encrypt the traffic between nodes. It enables blanket application traffic encryption with very little performance impact.

### Before you begin...

In order to enable IPsec encryption, you will need a Kubernetes cluster with:
- the [VPP dataplane]({{ site.baseurl }}/getting-started/kubernetes/vpp/getting-started) configured
- [IP-in-IP encapsulation]({{ site.baseurl }}/networking/vxlan-ipip) configured between the nodes

### How to

- [Create the IKEv2 PSK](#create-the-ikev2-psk)
- [Configure the VPP dataplane](#configure-the-vpp-dataplane)

#### Create the IKEv2 PSK

Create a Kubernetes secret that contains the PSK used for the IKEv2 exchange between the nodes. You can use the following command to create a random PSK. It will generate a unique random key. You may also replace the part after `psk=` with a key of your choice.
```bash
kubectl -n calico-vpp-dataplane create secret generic calicovpp-ipsec-secret \
   --from-literal=psk="$(dd if=/dev/urandom bs=1 count=36 2>/dev/null | base64)"
```

#### Configure the VPP dataplane

To enable IPsec, you need to configure two environment variables on the `calico-vpp-node` pod. You can do so with the following kubectl command:
````bash
kubectl -n calico-vpp-dataplane patch daemonset calico-vpp-node --patch "$(curl https://raw.githubusercontent.com/projectcalico/vpp-dataplane/{{page.vppbranch}}/yaml/components/ipsec/ipsec.yaml)"
````

Once IPsec is enabled, all the traffic that uses IP-in-IP encapsulation in the cluster will be automatically encrypted.

### Next steps

#### Verify encryption

In order to verify that the traffic is encrypted, open a VPP debug CLI session to check the configuration with [calivppctl]({{ site.baseurl }}/maintenance/troubleshoot/vpp)
```bash
calivppctl vppctl myk8node1
```
Then at the `vpp#` prompt, you can run the following commands:
- `show ikev2 profile` will list the configured IKEv2 profiles, there should be one per other node in your cluster
- `show ipsec sa` will list the establish IPsec SA, two per IKEv2 profile
- `show interface` will list all the interfaces configured in VPP. The ipip interfaces (which correspond to the IPsec tunnels) should be up

You can also [capture the traffic]({{ site.baseurl }}/maintenance/troubleshoot/vpp#tracing-packets) flowing between the nodes to verify that it is encrypted.
