If you are not sure which IPAM your cluster is using, the way to tell depends on install method.

{% tabs %}
  <label:Operator,active:true>
<%

The IPAM plugin can be queried on the default Installation resource.

{% raw %}
```
kubectl get installation default -o go-template --template {{.spec.cni.ipam.type}}
```
{% endraw %}

If your cluster is using Calico IPAM, the above command should return a result of `Calico`.

%>
  <label:Manifest>
<%

SSH to one of your Kubernetes nodes and examine the CNI configuration.

```
cat /etc/cni/net.d/10-calico.conflist
```

Look for the entry:

```
         "ipam": {
              "type": "calico-ipam"
          },
```

If it is present, you are using the {{site.prodname}} IPAM. If the IPAM is not {{site.prodname}}, or the 10-calico.conflist file does not exist, you cannot use these features in your cluster.

%>
{% endtabs %}
