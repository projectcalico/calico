## Installing calicoctl as a container on a single host

To install `calicoctl` as a container on a single host, log into the
target host and issue the following command.

```
docker pull {{page.registry}}{{page.imageNames["calicoctl"]}}:{{site.data.versions[page.version].first.title}}
```

**Next step**:

[Configure `calicoctl` to connect to your datastore](configure).


## Installing calicoctl as a Kubernetes pod


Use the YAML that matches your datastore type to deploy the `calicoctl` container to your nodes.

- **etcd**

   ```
   kubectl apply -f {{ "/manifests/calicoctl-etcd.yaml" | absolute_url }}
   ```

   > **Note**: You can also
   > [view the YAML in a new tab]({{ "/manifests/calicoctl-etcd.yaml" | absolute_url }}){:target="_blank"}.
   {: .alert .alert-info}

- **Kubernetes API datastore**

   ```
   kubectl apply -f {{ "/manifests/calicoctl.yaml" | absolute_url }}
   ```

   > **Note**: You can also
   > [view the YAML in a new tab]({{ "/manifests/calicoctl.yaml" | absolute_url }}){:target="_blank"}.
   {: .alert .alert-info}

You can then run commands using kubectl as shown below.

```
kubectl exec -ti -n kube-system calicoctl -- /calicoctl get profiles -o wide
```

An example response follows.

```bash
NAME                 TAGS
kns.default          kns.default
kns.kube-system      kns.kube-system
```
{: .no-select-button}

We recommend setting an alias as follows.

```
alias calicoctl="kubectl exec -i -n kube-system calicoctl /calicoctl -- "
```

   > **Note**: In order to use the `calicoctl` alias
   > when reading manifests, redirect the file into stdin, for example:
   > ```
   > calicoctl create -f - < my_manifest.yaml
   > ```
   {: .alert .alert-info}
