---
title: Upgrade Calico on OpenShift 4
description: Upgrade to a newer version of Calico for OpenShift.
canonical_url: '/maintenance/openshift-upgrade'
---

## About upgrading {{site.prodname}}

This page describes how to upgrade to {{page.version}} for OpenShift 4 from an existing {{site.prodname}} cluster.

{% include content/hostendpoints-upgrade.md orch="OpenShift" %}

## Upgrading Calico on OpenShift 4

Make a manifests directory.

```bash
mkdir manifests
```

{% include content/install-openshift-manifests.md install_type="upgrade" %}

Apply the updated manifests.

```bash
oc apply -f manifests/
```

You can now monitor the upgrade progress with the following command:

```bash
watch oc get tigerastatus
```

If you were upgrading from a version of Calico prior to v3.14 and followed the pre-upgrade steps for host endpoints above, review traffic logs from the temporary policy,
add any global network policies needed to allow traffic, and delete the temporary network policy **allow-all-upgrade**.

{% include content/auto-hostendpoints-migrate.md orch="OpenShift" %}
