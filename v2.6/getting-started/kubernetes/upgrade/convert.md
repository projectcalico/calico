---
title: Converting policies
redirect_from: latest/getting-started/kubernetes/upgrade/convert
---

If you are upgrading from the following, you must perform a one-time policy
conversion before you can upgrade the {{side.prodname}} components.

| Current version     | Datastore type           | Conversion required? |
| ------------------- | ------------------------ | -------------------- |
| earlier than v2.3.0 | Kubernetes API datastore | Yes                  |
| earlier than v2.4.0 | etcd                     | Yes                  |


{{side.prodname}}'s interpretation of Kubernetes `NetworkPolicy` changed after this to match the 
behavior defined [upstream](https://github.com/kubernetes/kubernetes/pull/39164#issue-197243974). 
To maintain behavior when upgrading, you should follow these steps prior to upgrading 
{{side.prodname}} to ensure your configured policy is enforced consistently throughout 
the upgrade process.

- **In any namespace that does not have a "DefaultDeny" annotation**

  Delete any `NetworkPolicy` objects in that namespace.  After upgrade, these 
  policies will become active and may block traffic that was previously allowed.
  
- **In any namespace that has a "DefaultDeny" annotation**
  
  Create a `NetworkPolicy` which matches all pods but does not allow any traffic. After 
  upgrade, the namespace annotation will have no effect, but this empty `NetworkPolicy` 
  will provide the same behavior.

Here is an example of a `NetworkPolicy` which selects all pods in the namespace, 
but does not allow any traffic:

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-deny
spec:
  podSelector:
```

## Next steps

Now that you've converted your policies, continue to:

- [Migrate data](/{{page.version}}/getting-started/kubernetes/upgrade/migrate): if required.

- [Upgrade the Calico components](/{{page.version}}/getting-started/kubernetes/upgrade/upgrade/): if you don't need to migrate your data.