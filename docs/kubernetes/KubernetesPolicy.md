# Programming Calico Policy in Kubernetes
The [Calico Kubernetes plugin](https://github.com/projectcalico/calico-docker/blob/master/docs/kubernetes/KubernetesIntegration.md) allows you to specify networking policy in the Kubernetes API using pod annotations. 

## Prerequisites
* A Kubernetes Deployment
    - To implement service policy, you will need a build of Kubernetes after [`kubernetes/kubernetes@b8dc963`](https://github.com/kubernetes/kubernetes/commit/b8dc963512326bcf7186026830b0dcbceecbcc80).
    - Make sure you have configured your kube-proxy using the `--legacy-userspace-proxy=false` option.
* [v0.1.0+](https://github.com/projectcalico/calico-kubernetes/releases) of the Calico Kubernetes Plugin
    - For more information on how to integrate Calico into your Kubernetes Deployment, view our [integration doc](KubernetesIntegration.md).

### Declaring Policy
To enforce a policy rule to your pod, add a `projectcalico.org/policy` key to the annotations section of your pod's metadata. This `projectcalico.org/policy` key should map to a single string which defines network behavior. Programming policy follows a simple syntax that can specify any combination of label*, protocol, source/dest ports, and source/dest net. The syntax for this can be seen below.

>*Note: Multiple labels per rule are unsupported in the current release of the plugin.

##### Policy Syntax
```
    allow [(
      (tcp|udp) [(from [(ports <SRCPORTS>)] [(label <SRCKEY>=<SRCVAL>)] [(cidr <SRCCIDR>)])]
      | icmp [(type <ICMPTYPE> [(code <ICMPCODE>)])]
             [(from [(label <SRCKEY>=<SRCVAL>)] [(cidr <SRCCIDR>)])]
      | [(from [(label <SRCKEY>=<SRCVAL>)] [(cidr <SRCCIDR>)])]
    )]
```

Here is an example of how this looks in a pod spec.
```
...
  metadata:
    annotations:
      projectcalico.org/policy: "allow tcp from label role=backend"
...
```

You can specify multiple rules by separating them with semicolons.
```
...
      projectcalico.org/policy: "allow from label role=backend; allow tcp to ports 4001,443"
...
```
In its current state, the Calico Kubernetes Plugin supports whitelist oriented, inbound rules. This means that any traffic not specified in a pod's policy is unauthorized, and unauthorized traffic will be dropped at the receiving Kubernetes node.

### Defaults
With no specified policy, Calico will only allow traffic from within a pod's own namespace. This default rule will be overidden if any policy is programmed. The only exception to this are resources within the `kube-system` namespace. These are universally accessed by all namespaces and will accept all traffic.

### Tags, Labels, and Namespaces
For each policy profile, Calico will generate a tag for its namespace, pod name, and for each label pair.

For example, the metadata
```
metadata:
  name: pod1
  namespace: production
  labels:
    role: backend
    version: v1.2.3
```
will generate the following tags
```
namespace_production
production_pod1
production_role_backend
production_version_v1.2.3
```
