<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->


# Deprecated
Annotation based policy has been deprecated in favor of the new Kubernetes `NetworkPolicy` v1alpha1 API.  It is recommended 
that you switch to using the new API.

Please see our documentation on [Calico and Kubernetes NetworkPolicy](NetworkPolicy.md).

# Calico Policy for Kubernetes
The Calico CNI plugin for Kubernetes allows you to specify network policy in the Kubernetes API using annotations.  
> *Note*: annotation-based policy is currently experimental and is subject to change in future releases. 

## Prerequisites
* A Kubernetes v1.1 Deployment using the Calico CNI plugin v1.0+.
* You must be using the iptables kube-proxy in your deployment. All of the Calico getting started guides configure the kube-proxy in this way.

## Behavior
Without annotation-based policy enabled, Calico follows the [Kubernetes networking model][k8s-network-model], allowing full connectivity between pods.

When Calico's annotation-based policy is enabled: 
- Pods will be, by default, isolated by namespace boundaries. Only pods in the same Kubernetes namespace can communicate.
- Annotations on pods can be used to expose access to pods outside of their namespace. 
- Annotations on pods can be used to further isolate pods within their namespace.
- Pods in the `kube-system` namespace (such as SkyDNS), are accessible to the rest of the cluster.  

Since pods are, by default, isolated by namespace boundaries, they will:
- not be accessible by pods outside of their namespace unless explicitly allowed via annotations.  
- not be accessible via Kubernetes service IPs, NodePort services, or LoadBalancer services unless specifically allowed using an annotation.
- not be accessible by the compute hosts in your cluster unless specifically allowed using an annotation. 

## Enabling annotation-based policy
To enable annotation-based policy, add the `policy` section to your CNI network config file as shown - you will need to make this change on each Kubernetes worker node in your cluster (any node that allows scheduling of pods).  The CNI network configuration file can usually be found in the `/etc/cni/net.d/` directory.
```
$ cat /etc/cni/net.d/10-calico.conf
{
    "name": "calico-k8s-network",
    "type": "calico",
    "etcd_authority": "<ETCD_IP:ETCD_PORT>",
    "log_level": "info",
    "ipam": {
        "type": "calico-ipam"
    },
    "policy": {
        "type": "k8s-annotations",
        "k8s_api_root": "<KUBERNETES_API_ROOT>",
        "k8s_auth_token": "<AUTH_TOKEN>"
    }
}
```

The following configuration optons are supported in the `policy` section:

* ##### `type`
   The type of policy to use.  Currently, only `k8s-annotations` is supported.

* ##### `k8s_api_root` (Optional) 
   Location of the Kubernetes API.  Consists of a protocol (`http` or `https`), IP address or DNS name at which the Kubernetes API is available (usually either the master IP address or Kubernetes service VIP), and the Kubernetes v1 API root (`/api/v1/`). 
   
   Default: `https://10.100.0.1:443/api/v1/`

* ##### `k8s_auth_token` (Optional) 
   ServiceAccount token for accessing a secure API.  This value is not needed on clusters which do not use TLS to secure the Kubernetes API. 
   
   Default: `None`
   
Once you have modified the network configuration file as show above, you will need to restart the kubelet to pick up the changes.

>Example for `systemd`:
```
sudo systemctl restart kubelet
```

## Declaring Policy using Annotations
With `k8s-annotations` policy enabled, you can now declare network policy on pods at creation time using annotations.  Annotations allow you to contol network access to pods using the Calico distributed firewall. 

The following describes the supported syntaxes for declaring a single annotation-based rule.  Multiple rules can be defined using a semicolon.
```
(allow|deny) [(
   (tcp|udp) [(from [(ports <SRCPORTS>)] [(label <SRCLABEL>)] [(cidr <SRCCIDR>)])]
             [(to   [(ports <DSTPORTS>)] [(label <DSTLABEL>)] [(cidr <DSTCIDR>)])] |

   icmp [(type <ICMPTYPE> [(code <ICMPCODE>)])]
        [(from [(label <SRCLABEL>)] [(cidr <SRCCIDR>)])]
        [(to   [(label <DSTLABEL>)] [(cidr <DSTCIDR>)])] |

   [(from [(label <SRCLABEL>)] [(cidr <SRCCIDR>)])]
   [(to   [(label <DSTLABEL>)] [(cidr <DSTCIDR>)])]
)]
```

## Worked Example
The following worked example provides a simple Kubernetes application to showcase Calico policy.  In this example, we'll deploy an nginx service on Kubernetes and limit access to pods with the label "access: true".  This example assumes you have configured Calico policy using the steps above.

>Note: This example requires a functioning SkyDNS service running on your cluster.

##### 1. Create a file called `nginx.yaml` with the following contents.  Note the policy declared on the nginx pod.
```
apiVersion: v1
kind: Service
metadata:
  name: nginx 
spec:
  ports:
  - port: 80 
    targetPort: 80 
  selector:
    app: nginx 
---
apiVersion: v1
kind: ReplicationController
metadata:
  name: nginx
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: nginx
      annotations:
        projectcalico.org/policy: "allow tcp from label access=true to ports 80"
    spec:
      containers:
      - name: nginx
        image: nginx
        ports:
        - containerPort: 80
```

##### 2. Deploy the `nginx` replicationController and service using the following command.
```
kubectl create -f nginx.yaml
```

Check that your pod is running:
```
kubectl get pods
```

##### 3. Access the service from a pod with the label "access: true".

The following command will start a pod with the label "access: true" and give you shell access. 
```
kubectl run --tty -i has-access --image=busybox --overrides='{"apiVersion": "v1", "spec": {"metadata": {"labels": {"access": "true", "run": "has-access"}}}}'
```

From within the pod we just created, try to access the nginx service we just created.
```
wget nginx -q -O - 2>&1
```

You should see the default contents of `index.html` served by the nginx service.  We've successfully accessed the nginx service on TCP port 80.

##### 4. Attempt to access the service from a pod without the label "access: true".

The previous step succeeded in accessing the nginx service since the pod we were using to access the service was labeled with `access: true`. In this step, we'll show that pods without that label are unable to access the nginx service. 

The following command will start a pod and give you shell access.
```
kubectl run --tty -i no-access --image=busybox 
```

From within the pod we just created, try to access the nginx service we just created.
```
wget nginx -q -O - 2>&1
```

The command should timeout, since the Calico distributed firewall has prevented access to nginx. 

## Additional Examples

### Example 1: Exposing outside of a namespace.
When `k8s-annotations` policy is enabled, Calico will reject incoming connections to pods from outside of their
namespace. 

The ReplicationController manifest in this example shows how to use annotations to expose pods outside of their namespace. 

This allows:
- incoming connections from pods in other namespaces.
- incoming connections from NodePort and LoadBalancer services (external connectivity). 
- incoming connections from compute hosts in your cluster.

to tcp and udp port 80 on the destination pods.

```
apiVersion: v1
kind: ReplicationController
metadata:
  name: frontend
spec:
  replicas: 3
  template:
    metadata:
      annotations:
        projectcalico.org/policy: "allow tcp to ports 80; allow udp to ports 80"
      labels:
        tier: frontend
    spec:
      containers:
      - name: php-redis
        image: gcr.io/google_samples/gb-frontend:v3
        ports:
        - containerPort: 80
```

### Example 2: Policy using labels
This example shows how to limit incoming connections to a subset of pods using labels.  The pods created by this
ReplicationController will accept all traffic from source pods in the same namespace with the label `tier=frontend`.  All other traffic will
be dropped.
```
apiVersion: v1
kind: ReplicationController
metadata:
  name: frontend
spec:
  replicas: 3
  template:
    metadata:
      annotations:
        projectcalico.org/policy: "allow from label tier=frontend"
      labels:
        tier: frontend
    spec:
      containers:
      - name: php-redis
        image: gcr.io/google_samples/gb-frontend:v3
        ports:
        - containerPort: 80
```


[k8s-network-model]: https://github.com/kubernetes/kubernetes/blob/master/docs/design/networking.md#networking

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/cni/kubernetes/AnnotationPolicy.md?pixel)](https://github.com/igrigorik/ga-beacon)
