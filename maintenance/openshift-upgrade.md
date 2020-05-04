---
title: Upgrade Calico on OpenShift 4
description: Upgrade to a newer version of Calico for OpenShift.
canonical_url: '/maintenance/openshift-upgrade'
---

## About upgrading {{site.prodname}}

This page describes how to upgrade to {{page.version}} for OpenShift 4 from an existing {{side.prodname}} cluster.

{% include content/hostendpoints-upgrade.md orch="OpenShift" %}

## Upgrading Calico on OpenShift 4

Make a manifests directory.

```bash
mkdir manifests
```

{% include content/install-openshift-manifests.md %}

Apply the updated manifests.

```bash
oc apply -f manifests/
```

You can now monitor the upgrade progress with the following command:

```bash
watch oc get tigerastatus
```
