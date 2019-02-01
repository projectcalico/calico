If you are on Kubernetes, we provide two manifests that make it easy to deploy `calicoctl`
as a pod.

- **etcd datastore**:

   ```
   kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/calicoctl.yaml
   ```
   
- **Kubernetes API datastore**:

   ```
   kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/calicoctl.yaml
   ```

In other environments, use the following command.

```
docker pull {{site.data.versions[page.version].first.registry}}{{site.imageNames["calicoctl"]}}:{{site.data.versions[page.version].first.components["calicoctl"].version}}
```
