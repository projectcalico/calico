---
title: Binary install without package manager
canonical_url: 'https://docs.projectcalico.org/v3.7/getting-started/bare-metal/installation/binary'
---

## Download and install the binary

1. Use the following command to download the {{site.nodecontainer}} image.

   ```bash
   docker pull {{site.nodecontainer}}:{{site.data.versions[page.version].first.components["calico/node"].version}}
   ```

1. Confirm that the image has loaded by typing `docker images`.

   ```bash
   REPOSITORY       TAG           IMAGE ID       CREATED         SIZE
   {{site.nodecontainer}}      {{site.data.versions[page.version].first.components["calico/node"].version}}        e07d59b0eb8a   2 minutes ago   42MB
   ```

1. Create a temporary {{site.nodecontainer}} container.

   ```bash
   docker create --name container {{site.nodecontainer}}:{{site.data.versions[page.version].first.components["calico/node"].version}}
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

## Create a start-up script

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
    ExecStartPre=/usr/bin/mkdir -p /var/run/calico
    ExecStart=/usr/local/bin/calico-node -felix
    KillMode=process
    Restart=on-failure
    LimitNOFILE=32000

    [Install]
    WantedBy=multi-user.target

Or, for upstart:

    description "Felix (Calico agent)"
    author "Project Calico Maintainers <maintainers@projectcalico.org>"

    start on stopped rc RUNLEVEL=[2345]
    stop on runlevel [!2345]

    limit nofile 32000 32000

    respawn
    respawn limit 5 10

    chdir /var/run

    pre-start script
      mkdir -p /var/run/calico
      chown root:root /var/run/calico
    end script

    exec /usr/local/bin/calico-node -felix

## Configure Felix

Optionally, you can create a file at `/etc/calico/felix.cfg` to
configure Felix. The configuration file as well as other options for
configuring Felix (including environment variables) are described in
[this]({{site.baseurl}}/{{page.version}}/reference/felix/configuration) document.

If etcd is not running on the local machine, it's essential to configure
the `EtcdAddr` or `EtcdEndpoints` setting to tell Felix how to reach
etcd.

Felix tries to detect whether IPv6 is available on your platform but
the detection can fail on older (or more unusual) systems.  If Felix
exits soon after startup with `ipset` or `iptables` errors try
setting the `Ipv6Support` setting to `false`.

## Start Felix

Once you've configured Felix, start it up via your init system.

```bash
service calico-felix start
```

## Running Felix manually

For debugging, it's sometimes useful to run Felix manually and tell it
to emit its logs to screen. You can do that with the following command.

```bash
ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT> FELIX_LOGSEVERITYSCREEN=INFO /usr/local/bin/calico-node -felix
```
> **Note**: Add the `ETCD_ENDPOINTS` Env and replace `<ETCD_IP>:<ETCD_PORT>` with your etcd configuration when etcd isn't running locally. 
{: .alert .alert-info}
