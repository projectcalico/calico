---
title: Converting your calicoctl manifests
canonical_url: https://docs.projectcalico.org/v3.5/getting-started/kubernetes/upgrade/convert
---

 Use `calicoctl convert` to convert your Calico resource manifests from v1 API to v3 API.
 
   > **Note**: Make sure to use the latest version of `calicoctl`
   
 `calicoctl convert` command allows you to convert multiple resources from v1 API to v3 at the same time.
 You can convert your v1 yaml or json manifests v3 yaml or json manifests.
 
 **Example**
 ```
 calicoctl convert -f path/to/v1-multi-resource.yaml -o yaml
 - apiVersion: projectcalico.org/v3
   kind: BGPPeer
   metadata:
     creationTimestamp: null
     name: node1.00aa-00bb-0000-0000-0000-0000-0000-00ff
   spec:
     asNumber: 64514
     node: node1
     peerIP: aa:bb::ff
 - apiVersion: projectcalico.org/v3
   kind: BGPPeer
   metadata:
     creationTimestamp: null
     name: node2.5-5-5-5
   spec:
     asNumber: 6555
     node: node5
     peerIP: 5.5.5.5
 ```
 
 Original v1 resource file:
 ```
 cat v1-multi-resource.yaml
 - apiVersion: v1
   kind: bgpPeer
   metadata:
     node: Node1
     peerIP: aa:bb::ff
     scope: node
   spec:
     asNumber: 64514
 - apiVersion: v1
   kind: bgpPeer
   metadata:
     node: Node5
     peerIP: 5.5.5.5
     scope: node
   spec:
     asNumber: 6555
 ```
 
 See [calicoctl convert]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/convert) for detailed usage of the `convert` command.