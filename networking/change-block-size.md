---
title: Change IP pool block size
description: Expand or shrink the IP pool block size to efficiently manage IP addresses. 
---

### Big picture



### Value



### Features

This how-to guide uses the following {{site.prodname}} features:

- **IPPool** resource 

### Concepts

#### IP pools and cluster CIDRs



### Before you begin...

**Verify that you are using {{site.prodname}} IPAM**. 

To verify, ssh to one of your Kubernetes nodes and view the CNI configuration.  

```bash
cat /etc/cni/net.d/10-calico.conflist

```

Look for the "type" entry:

<pre>
   "ipam": {
         "type": "calico-ipam"
    }, 
</pre>

If the type is “calico-ipam”, you are good to go. If the IPAM is set to something else, or the 10-calico.conflist file does not exist, you cannot use this feature in your cluster. 

**Verify orchestrator support for changing the pod network CIDR**.

Although Kubernetes supports changing the pod network CIDR, not all orchestrators do. For example, OpenShift does not support this feature as described in [`osm_cluster_network_cidr configuration`](https://docs.openshift.org/latest/install_config/install/advanced_install.html#configuring-cluster-variables). Check your orchestrator documentation to verify. 

### How to

#### Expand or shrink IP pool block size

By default, the {{site.prodname}} IPAM block size for an IP pool is /26. You can expand the `blockSize` using a lower number (for example /8). Or, you can shrink a `blockSize` using a larger number (for example, /28). Changing the `blockSize` requires an extra step (creating a temporary IP pool), because you cannot change the `blockSize` after it is initially created.

The high-level steps to follow are:

1. Add a new temporary IP pool. 
   **Note**: The new IP pool must not be within the same cluster CIDR.
1. Disable the old IP pool.
   **Note**: Disabling an IP pool only prevents new IP address allocations; it does not affect the networking of existing pods.
1. Delete pods from the old IP pool.
   This includes any new pods that may have been created with the old IP pool prior to disabling the pool.
1. Verify that new pods get an address from the new IP pool.
1. Delete the old IP pool.
1. Create a new pool with custom CIDR block within the same cluster CIDR
1. Disable temporary IP pool.
1. Delete pods from the temporary IP pool.
1. Delete temporary IP pool

### Tutorial

