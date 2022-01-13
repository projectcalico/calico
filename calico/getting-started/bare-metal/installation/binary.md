---
title: Binary install without package manager
description: Install Calico binary on non-cluster hosts without a package manager.
canonical_url: '/getting-started/bare-metal/installation/binary'
---

### Big picture
Install {{site.prodname}} binary on non-cluster hosts without a package manager.

### Value
Install {{site.prodname}} directly when a package manager isn't available, or your provisioning system can easily handle copying binaries to hosts.

### Before you begin... 

1. Ensure the {{site.prodname}} datastore is up and accessible from the host
1. Ensure the host meets the minimum [system requirements](../requirements)
1. If you want to install {{site.prodname}} with networking (so that you can communicate with cluster workloads), you should choose the [container install method](./container)
1. Install `kubectl` (for Kubernetes datastore) or [Install and configure `calicoctl`]({{site.baseurl}}/maintenance/clis/calicoctl/) for etcd3 datastore.

### How to

This guide covers installing Felix, the {{site.prodname}} daemon that handles network policy.

#### Step 1: Download and extract the binary

This step requires Docker, but it can be run from any machine with Docker installed. It doesn't have to be the host you will run it on (i.e your laptop is fine).

1. Use the following command to download the {{site.nodecontainer}} image.

   ```bash
   docker pull {{site.nodecontainer}}:{{site.data.versions.first.components["calico/node"].version}}
   ```

1. Confirm that the image has loaded by typing `docker images`.

   ```bash
   REPOSITORY       TAG           IMAGE ID       CREATED         SIZE
   {{site.nodecontainer}}      {{site.data.versions.first.components["calico/node"].version}}        e07d59b0eb8a   2 minutes ago   42MB
   ```

1. Create a temporary {{site.nodecontainer}} container.

   ```bash
   docker create --name container {{site.nodecontainer}}:{{site.data.versions.first.components["calico/node"].version}}
   ```

1. Copy the calico-node binary from the container to the local file system.

   ```bash
   docker cp container:/bin/calico-node calico-node
   ```

1. Delete the temporary container.

   ```bash
   docker rm container
   ```

1. Set the extracted binary file to be executable.

   ```
   chmod +x calico-node
   ```

#### Step 2: Copy the `calico-node` binary

Copy the binary from Step 1 to the target machine, using any means (`scp`, `ftp`, USB stick, etc.).

#### Step 3: Create environment file

{% include content/environment-file.md install="binary" target="felix" %}

#### Step 4: Create a start-up script

Felix should be started at boot by your init system and the init system
**must** be configured to restart Felix if it stops. Felix relies on
that behavior for certain configuration changes.

If your distribution uses systemd, then you could use the following unit
file:

    [Unit]
    Description=Calico Felix agent
    After=syslog.target network.target

    [Service]
    User=root
    EnvironmentFile=/etc/calico/calico.env
    ExecStartPre=/usr/bin/mkdir -p /var/run/calico
    ExecStart=/usr/local/bin/calico-node -felix
    KillMode=process
    Restart=on-failure
    LimitNOFILE=32000

    [Install]
    WantedBy=multi-user.target

Once you've configured Felix, start it up via your init system.

```bash
service calico-felix start
```
#### Step 5: Initialize the datastore

{% include content/felix-init-datastore.md %}

