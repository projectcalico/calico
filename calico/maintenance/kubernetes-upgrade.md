---
title: Upgrade Calico on Kubernetes
description: Upgrade to a newer version of Calico for Kubernetes.
canonical_url: '/maintenance/kubernetes-upgrade'
---

## About upgrading {{site.prodname}}

This page describes how to upgrade to {{page.version}} from {{site.prodname}} v3.0 or later. The
procedure varies by datastore type and install method.

If you are using {{site.prodname}} in etcd mode on a Kubernetes cluster, we recommend upgrading to the Kubernetes API datastore [as discussed here]({{site.baseurl}}/maintenance/datastore-migration).

If you have installed {{site.prodname}} using the `calico.yaml` manifest, we recommend upgrading to the {{site.prodname}} operator, [as discussed here]({{site.baseurl}}/maintenance/operator-migration).


- [Upgrading an installation that was installed using Helm](#upgrading-an-installation-that-was-installed-using-helm)

- [Upgrading an installation that uses the operator](#upgrading-an-installation-that-uses-the-operator)

- [Upgrading an installation that uses manifests and the Kubernetes API datastore](#upgrading-an-installation-that-uses-manifests-and-the-kubernetes-api-datastore)

- [Upgrading an installation that connects directly to an etcd datastore](#upgrading-an-installation-that-uses-an-etcd-datastore)

> **Important**: Do not use older versions of `calicoctl` after the upgrade.
> This may result in unexpected behavior and data.
{: .alert .alert-danger}

{% include content/hostendpoints-upgrade.md orch="Kubernetes" %}

## Upgrading an installation that was installed using helm

Prior to release v3.23, the Calico helm chart itself deployed the `tigera-operator` namespace and required that the helm release was 
installed in the `default` namespace. Newer releases properly defer creation of the `tigera-operator` namespace to the user and allow installation
of the chart into the `tigera-operator` namespace.

When upgrading from a version of Calico v3.22 or lower to a version of Calico v3.23 or greater, you must complete the following steps to migrate
ownership of the helm resources to the new chart location.

### Upgrade from Calico versions prior to v3.23.0

1. Patch existing resources so that the new chart can assume ownership.

   ```
   kubectl patch installation default --type=merge -p '{"metadata": {"annotations": {"meta.helm.sh/release-namespace": "tigera-operator"}}}'
   kubectl patch apiserver default --type=merge -p '{"metadata": {"annotations": {"meta.helm.sh/release-namespace": "tigera-operator"}}}'
   kubectl patch podsecuritypolicy tigera-operator --type=merge -p '{"metadata": {"annotations": {"meta.helm.sh/release-namespace": "tigera-operator"}}}'
   kubectl patch -n tigera-operator deployment tigera-operator --type=merge -p '{"metadata": {"annotations": {"meta.helm.sh/release-namespace": "tigera-operator"}}}'
   kubectl patch -n tigera-operator serviceaccount tigera-operator --type=merge -p '{"metadata": {"annotations": {"meta.helm.sh/release-namespace": "tigera-operator"}}}'
   kubectl patch clusterrole tigera-operator --type=merge -p '{"metadata": {"annotations": {"meta.helm.sh/release-namespace": "tigera-operator"}}}'
   kubectl patch clusterrolebinding tigera-operator tigera-operator --type=merge -p '{"metadata": {"annotations": {"meta.helm.sh/release-namespace": "tigera-operator"}}}'
   ```

1. Install the helm chart in the `tigera-operator` namespace.

   ```
   helm install {{site.prodname | downcase}} projectcalico/tigera-operator --version {{site.data.versions[0].title}} --namespace tigera-operator
   ```

1. Once the install has succeeded, you can delete any old releases in the `default` namespace.

   ```
   kubectl delete secret -n default -l name=calico,owner=helm --dry-run
   ```

> **Note:** The above command uses --dry-run to avoid making changes to your cluster. We recommend reviewing
> the output and then re-running the command without --dry-run to commit to the changes.
{: .alert .alert-info}

### All other upgrades

1. Run the helm upgrade:

   ```bash
   helm upgrade {{site.prodname | downcase}} projectcalico/tigera-operator
   ```

## Upgrading an installation that uses the operator

1. Download the {{page.version}} operator manifest.

   ```bash
   curl {{site.data.versions.first.manifests_url}}/manifests/tigera-operator.yaml -O
   ```

1. Use the following command to initiate an upgrade.

   ```bash
   kubectl apply -f tigera-operator.yaml
   ```

## Upgrading an installation that uses manifests and the Kubernetes API datastore

1. Download the {{page.version}} manifest that corresponds to your original installation method.

   **{{site.prodname}} for policy and networking**
   ```bash
   curl {{site.data.versions.first.manifests_url}}/manifests/calico.yaml -O
   ```

   **{{site.prodname}} for policy and flannel for networking**
   ```bash
   curl {{site.data.versions.first.manifests_url}}/manifests/canal.yaml -O
   ```

   **{{site.prodname}} for policy (advanced)**
   ```bash
   curl {{site.data.versions.first.manifests_url}}/manifests/calico-policy-only.yaml -O
   ```

   > **Note**: If you manually modified the manifest, you must manually apply the
   > same changes to the downloaded manifest.
   {: .alert .alert-info}

1. Use the following command to initiate a rolling update, after replacing
   `<manifest-file-name>` with the file name of your {{page.version}} manifest.

   ```
   kubectl apply -f <manifest-file-name>
   ```

1. Watch the status of the upgrade as follows.

   ```
   watch kubectl get pods -n kube-system
   ```

   Verify that the status of all {{site.prodname}} pods indicate `Running`.

   ```
   {{site.noderunning}}-hvvg8     2/2   Running   0    3m
   {{site.noderunning}}-vm8kh     2/2   Running   0    3m
   {{site.noderunning}}-w92wk     2/2   Running   0    3m
   ```
   {: .no-select-button}

1. Remove any existing `calicoctl` instances, [install the new `calicoctl`](../maintenance/clis/calicoctl/install)
   and [configure it to connect to your datastore](../maintenance/clis/calicoctl/configure/overview).

1. Use the following command to check the {{site.prodname}} version number.

   ```bash
   calicoctl version
   ```

   It should return a `Cluster Version` of `{{page.version}}.x`.

1. If you have [enable application layer policy]({{site.baseurl}}/security/app-layer-policy),
   follow [the instructions below](#upgrading-if-you-have-application-layer-policy-enabled) to complete your upgrade. Skip this if you are not using Istio with {{site.prodname}}.

1. If you were upgrading from a version of Calico prior to v3.14 and followed the pre-upgrade steps for host endpoints above, review traffic logs from the temporary policy,
   add any global network policies needed to allow traffic, and delete the temporary network policy **allow-all-upgrade**.

1. Congratulations! You have upgraded to {{site.prodname}} {{page.version}}.


## Upgrading an installation that uses an etcd datastore

1. Download the {{page.version}} manifest that corresponds to your original installation method.

   **{{site.prodname}} for policy and networking**
   ```bash
   curl {{site.data.versions.first.manifests_url}}/manifests/calico-etcd.yaml -O
   ```

   **{{site.prodname}} for policy and flannel for networking**
   ```bash
   curl {{site.data.versions.first.manifests_url}}/manifests/canal-etcd.yaml -O
   ```

   > **Note**: You must manually apply the changes you made to the manifest
   > during installation to the downloaded {{page.version}} manifest. At a minimum,
   > you must set the `etcd_endpoints` value.
   {: .alert .alert-info}

1. Use the following command to initiate a rolling update, after replacing
   `<manifest-file-name>` with the file name of your {{page.version}} manifest.

   ```
   kubectl apply -f <manifest-file-name>
   ```

1. Watch the status of the upgrade as follows.

   ```
   watch kubectl get pods -n kube-system
   ```

   Verify that the status of all {{site.prodname}} pods indicate `Running`.

   ```
   calico-kube-controllers-6d4b9d6b5b-wlkfj   1/1       Running   0          3m
   {{site.noderunning}}-hvvg8                          1/2       Running   0          3m
   {{site.noderunning}}-vm8kh                          1/2       Running   0          3m
   {{site.noderunning}}-w92wk                          1/2       Running   0          3m
   ```
   {: .no-select-button}

   > **Tip**: The {{site.noderunning}} pods will report `1/2` in the `READY` column, as shown.
   {: .alert .alert-success}


1. Remove any existing `calicoctl` instances, [install the new `calicoctl`](../maintenance/clis/calicoctl/install)
   and [configure it to connect to your datastore](../maintenance/clis/calicoctl/configure/overview).

1. Use the following command to check the {{site.prodname}} version number.

   ```bash
   calicoctl version
   ```

   It should return a `Cluster Version` of `{{page.version}}`.

1. If you have [enabled application layer policy]({{site.baseurl}}/security/app-layer-policy),
   follow [the instructions below](#upgrading-if-you-have-application-layer-policy-enabled) to complete your upgrade. Skip this if you are not using Istio with {{site.prodname}}.

1. If you were upgrading from a version of Calico prior to v3.14 and followed the pre-upgrade steps for host endpoints above, review traffic logs from the temporary policy,
   add any global network policies needed to allow traffic, and delete the temporary network policy **allow-all-upgrade**.

1. Congratulations! You have upgraded to {{site.prodname}} {{page.version}}.

## Upgrading if you have Application Layer Policy enabled

Dikastes is versioned the same as the rest of {{site.prodname}}, but an upgraded `calico-node` will still be able to work with a downlevel Dikastes
so that you will not lose data plane connectivity during the upgrade.  Once `calico-node` is upgraded, you can begin redeploying your service pods
with the updated version of Dikastes.

If you have [enabled application layer policy]({{site.baseurl}}/security/app-layer-policy),
take the following steps to upgrade the Dikastes sidecars running in your application pods. Skip these steps if you are not using Istio with {{site.prodname}}.

1. Update the Istio sidecar injector template to use the new version of Dikastes. Replace `<your Istio version>` below with
   the full version string of your Istio install, for example `1.4.2`.

   ```bash
   kubectl apply -f {{site.data.versions.first.manifests_url}}/manifests/alp/istio-inject-configmap-<your Istio version>.yaml
   ```

1. Once the new template is in place, newly created pods use the upgraded version of Dikastes. Perform a rolling update of each of your service deployments
   to get them on the new version of Dikastes.

{% include content/auto-hostendpoints-migrate.md orch="Kubernetes" %}
