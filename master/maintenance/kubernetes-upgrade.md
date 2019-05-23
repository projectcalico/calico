---
title: Upgrading Calico on Kubernetes
canonical_url: 'https://docs.projectcalico.org/v3.7/maintenance/kubernetes-upgrade'
---

## About upgrading {{site.prodname}}

This page describes how to upgrade to {{page.version}} from {{site.prodname}} v3.0 or later. The
procedure varies by datastore type.

- [Upgrading an installation that uses the Kubernetes API datastore](#upgrading-an-installation-that-uses-the-kubernetes-api-datastore)

- [Upgrading an installation that connects directly to an etcd datastore](#upgrading-an-installation-that-uses-an-etcd-datastore)

> **Important**: Do not use older versions of `calicoctl` after the upgrade.
> This may result in unexpected behavior and data.
{: .alert .alert-danger}


## Upgrading an installation that uses the Kubernetes API datastore

1. Download the {{page.version}} manifest that corresponds to your original installation method.

   **{{site.prodname}} for policy and networking**
   ```bash
   curl {{site.url}}/{{page.version}}/manifests/calico.yaml -O
   ```

   **{{site.prodname}} for policy and flannel for networking**
   ```bash
   curl {{site.url}}/{{page.version}}/manifests/canal.yaml -O
   ```

   **{{site.prodname}} for policy (advanced)**
   ```bash
   curl {{site.url}}/{{page.version}}/manifests/calico-policy-only.yaml -O
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

1. Remove any existing `calicoctl` instances, [install the new `calicoctl`](../getting-started/calicoctl/install)
   and [configure it to connect to your datastore](../getting-started/calicoctl/configure/).

1. Use the following command to check the {{site.prodname}} version number.

   ```bash
   calicoctl version
   ```

   It should return a `Cluster Version` of `{{page.version}}.x`.

1. If you have [enabled Application Layer Policy](/{{page.version}}/getting-started/kubernetes/installation/app-layer-policy),
   follow [the instructions below](#upgrading-if-you-have-application-layer-policy-enabled) to complete your upgrade. Skip this if you are not using Istio with {{site.prodname}}.

1. Congratulations! You have upgraded to {{site.prodname}} {{page.version}}.


## Upgrading an installation that uses an etcd datastore

1. Download the {{page.version}} manifest that corresponds to your original installation method.

   **{{site.prodname}} for policy and networking**
   ```bash
   curl {{site.url}}/{{page.version}}/calico-etcd.yaml -O
   ```

   **{{site.prodname}} for policy and flannel for networking**
   ```bash
   curl {{site.url}}/{{page.version}}/canal-etcd.yaml -O
   ```

   > **Note**: You must must manually apply the changes you made to the manifest
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


1. Remove any existing `calicoctl` instances, [install the new `calicoctl`](../getting-started/calicoctl/install)
   and [configure it to connect to your datastore](../getting-started/calicoctl/configure/).

1. Use the following command to check the {{site.prodname}} version number.

   ```bash
   calicoctl version
   ```

   It should return a `Cluster Version` of `{{page.version}}`.

1. If you have [enabled Application Layer Policy](/{{page.version}}/getting-started/kubernetes/installation/app-layer-policy),
   follow [the instructions below](#upgrading-if-you-have-application-layer-policy-enabled) to complete your upgrade. Skip this if you are not using Istio with {{site.prodname}}.

1. Congratulations! You have upgraded to {{site.prodname}} {{page.version}}.

## Upgrading if you have Application Layer Policy enabled

Dikastes is versioned the same as the rest of {{site.prodname}}, but an upgraded `calico-node` will still be able to work with a downlevel Dikastes
so that you will not lose data plane connectivity during the upgrade.  Once `calico-node` is upgraded, you can begin redeploying your service pods
with the updated version of Dikastes. 

If you have [enabled Application Layer Policy](/{{page.version}}/getting-started/kubernetes/installation/app-layer-policy),
take the following steps to upgrade the Dikastes sidecars running in your application pods. Skip these steps if you are not using Istio with {{site.prodname}}.

1. Update the Istio sidecar injector template to use the new version of Dikastes. Replace `<your Istio version>` below with
   the full version string of your Istio install, for example `1.0.7`.

   ```bash
   kubectl apply -f {{site.url}}/{{page.version}}/manifests/alp/istio-inject-configmap-<your Istio version>.yaml
   ```

1. Once the new template is in place, newly created pods use the upgraded version of Dikastes. Perform a rolling update of each of your service deployments
   to get them on the new version of Dikastes.
