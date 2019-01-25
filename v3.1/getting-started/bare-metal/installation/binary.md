---
title: Binary install without package manager
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/bare-metal/installation/binary'
---


## Prerequisites

Felix has the following pre-requisites:

-   For IPv4 support, Linux kernel v2.6.32 is required. We have tested
    against v2.6.32-573+. Note: if you intend to run containers, Docker
    requires kernel >=v3.10. The kernel's version can be checked with
    `uname -a`.
-   For IPv6 support, Linux kernel 3.10+ is required (due to the lack of
    reverse path filtering for IPv6 in older versions).
-   [conntrack-tools](http://conntrack-tools.netfilter.org/); in
    particular, the `conntrack` command must be available. We test
    against >=v1.4.1. To check the version, run `conntrack --version`.
-   [iptables](http://www.netfilter.org/projects/iptables/index.html);
    for IPv6 support, the `ip6tables` command must be available. We test
    against >=v1.4.7. To check the version, run `iptables --version`.
-   [ipset](http://ipset.netfilter.org/); we test against >=v6.11. To
    check the version, run `ipset --version`.
-   The conntrack, iptables and ipsets kernel modules must be available
    (or compiled-in).
    
> **Note**: If any of the commands above fail when run with the `--version`
> flag then you have an old version that doesn't support reporting
> its version.
>
{: .alert .alert-info}


## Download and install the binary

The calico-felix binary is distributed via the
[Github releases page](https://github.com/projectcalico/felix/releases).
Download the calico-felix attachment to your system, then make it executable
and move it to a location on your path, for example:

    curl -o calico-felix <URL of binary>
    chmod +x calico-felix
    sudo cp calico-felix /usr/local/bin

## Create a start-up script

Felix should be started at boot by your init system and the init system
**must** be configured to restart Felix if it stops. Felix relies on
that behaviour for certain configuration changes.

If your distribution uses systemd, then you could use the following unit
file:

    [Unit]
    Description=Calico Felix agent
    After=syslog.target network.target

    [Service]
    User=root
    ExecStartPre=/usr/bin/mkdir -p /var/run/calico
    ExecStart=/usr/local/bin/calico-felix
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

    exec /usr/local/bin/calico-felix

## Configure Felix


Optionally, you can create a file at `/etc/calico/felix.cfg` to
configure Felix. The configuration file as well as other options for
configuring felix (including environment variables) are described in
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
FELIX_LOGSEVERITYSCREEN=INFO /usr/local/bin/calico-felix
```