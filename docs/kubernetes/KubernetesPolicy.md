# Programming Calico Policy in Kubernetes
The [Calico-Kubernetes plugin](https://github.com/projectcalico/calico-docker/blob/master/docs/kubernetes/KubernetesIntegration.md) will allow you to program Networking policy directly from your Kubernetes pod config. 


### The Basics
The Calico Networking plugin will look for a `policy` key in the annotations section of your pod's metadata. This `policy` key should map to a single string that outlines networking behavior semantically.

Programming policy is as simple as saying what you want your pod to do!

For instance:
```
...
  metadata:
    annotations:
      policy: "allow tcp from label name=backend"
...
```

To specify multiple rules, separate them by semicolons.
```
...
      policy: "allow from label name=backend; allow tcp to ports 4001,443"
...
```
In it's current state, Calico supports whitelist oriented, inbound rules. This means that anything unspecified by the policy spec will be rejected at the destination. 

Calico can specify any combination of label (multiple labels per rule are unsupported), protocol, source/dest ports, and source/dest net. The full syntax for creating compound rules is shown below [below](#Syntax).

### Defaults
With no specified policy, Calico will only allow traffic from within a pod's own namespace. This default rule will be overidden if any policy is programmed. If you wish to include rules that police the namespace, you can do so with the keyword `tag namespace_<NAMESPACE>`, as in `allow tcp from tag namespace_default`

The only exception to this are services within the `kube-system` namespace. These services are universally accessed by all namespaces and will allow all traffic.

### Tags, Labels, and Namespaces
For each policy profile, Calico will generate a tag for its namespace, pod name, and for each label pair.

For example, the metadata
```
metadata:
  name: pod1
  namespace: app1
  labels:
    name: backend
    stage: production
```
will generate the following tags
```
namespace_app1
app1_pod1
app1_name_backend
app1_stage_production
```

### Syntax
```
    allow [(
      (tcp|udp) [(from [(ports <SRCPORTS>)] [(label <SRCKEY>=<SRCVAL>)] [(cidr <SRCCIDR>)])]
      | icmp [(type <ICMPTYPE> [(code <ICMPCODE>)])]
             [(from [(label <SRCKEY>=<SRCVAL>)] [(cidr <SRCCIDR>)])]
      | [(from [(label <SRCKEY>=<SRCVAL>)] [(cidr <SRCCIDR>)])]
    )]
```
