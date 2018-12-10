---
title: Upgrading Calico
redirect_from: latest/getting-started/kubernetes/upgrade/upgrade
canonical_url: 'https://docs.projectcalico.org/v3.3/getting-started/kubernetes/upgrade/upgrade'
---

## About upgrading {{site.prodname}}

The upgrade procedure varies according to how you originally installed {{site.prodname}}
and your datastore type.

- [Upgrading an installation that uses the Kubernetes API datastore](#upgrading-an-installation-that-uses-the-kubernetes-api-datastore)

- [Upgrading an installation that connects directly to an etcd datastore](#upgrading-an-installation-that-uses-an-etcd-datastore)

> **Important**: Do not use older versions of `calicoctl` after the upgrade.
> This may result in unexpected behavior and data.
{: .alert .alert-danger}


## Upgrading an installation that uses the Kubernetes API datastore

1. Download the {{page.version}} manifest that corresponds to your original installation method.

   **{{site.prodname}} for policy and networking**
   ```bash
   curl \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/calico-networking/1.7/calico.yaml \
   -O
   ```

   **{{site.prodname}} for policy and flannel for networking**
   ```bash
   curl \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/canal/canal.yaml \
   -O
   ```

   **{{site.prodname}} for policy (advanced)**
   ```bash
   curl \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/policy-only/1.7/calico.yaml \
   -O
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

1. Remove any existing `calicoctl` instances, [install the new `calicoctl`](../../../usage/calicoctl/install)
   and [configure it to connect to your datastore](../../../usage/calicoctl/configure/).

1. Use the following command to check the {{site.prodname}} version number.

   ```bash
   calicoctl version
   ```

   It should return a `Cluster Version` of `{{page.version}}.x`.

   > **Note**: If upgrading from {{site.prodname}} 2.6.x and an error occurs during
   > the upgrade, refer to [Downgrading Calico](/{{page.version}}/getting-started/kubernetes/upgrade/downgrade).
   {: .alert .alert-info}

1. Congratulations! You have upgraded to {{site.prodname}} {{page.version}}.


## Upgrading an installation that uses an etcd datastore

1. Download the {{page.version}} manifest that corresponds to your original installation method.

   **{{site.prodname}} for policy and networking**
   ```bash
   curl \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/calico.yaml \
   -O
   ```

   **{{site.prodname}} for policy and flannel for networking**
   ```bash
   curl \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/canal/canal-etcd.yaml \
   -O
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

   > **Note**: If upgrading from {{site.prodname}} 2.6.x and an error occurs during
   > the upgrade, refer to an error occurs during the upgrade, refer to
   > [Downgrading {{site.prodname}}](/{{page.version}}/getting-started/kubernetes/upgrade/downgrade).
   {: .alert .alert-info}

1. Remove any existing `calicoctl` instances, [install the new `calicoctl`](../../../usage/calicoctl/install)
   and [configure it to connect to your datastore](../../../usage/calicoctl/configure/).

1. Use the following command to check the {{site.prodname}} version number.

   ```bash
   calicoctl version
   ```

   It should return a `Cluster Version` of `{{page.version}}.x`.

1. If you are upgrading from {{site.prodname}} 3.x, skip to the next step. Otherwise,
   for those upgrading from {{site.prodname}} 2.6.x, wait for some time to really
   ensure that the upgrade succeeded and no problems ensued. Then complete the
   upgrade by running `calico-upgrade complete`. After this, you can once again schedule
   pods and make changes to configuration and policy.

   > **Important**: If you experience errors after running `calico-upgrade complete`,
   > such as an inability to schedule pods, [downgrade {{site.prodname}} as soon as possible](/{{page.version}}/getting-started/kubernetes/upgrade/downgrade).
   {: .alert .alert-danger}

1. Congratulations! You have upgraded to {{site.prodname}} {{page.version}}.
