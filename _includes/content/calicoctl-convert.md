
 Use `calicoctl convert` to convert your Calico resource manifests from v1 API to v3 API.
 
 > **Important**: Make sure to use the latest version of `calicoctl`.
 {: .alert .alert-danger}
   
 `calicoctl convert` command allows you to convert multiple resources from v1 API to v3 at the same time.
 You can convert your v1 YAML or JSON manifests to v3 YAML or JSON manifests.
 
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
 
 See [calicoctl convert]({{ site.baseurl }}/reference/calicoctl/commands/convert) for detailed usage of the `convert` command.
