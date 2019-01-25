---
title: Binary install with package manager
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/bare-metal/installation/binary-mgr'
---

## Installing Felix

{% include ppa_repo_name %}

There are several ways to install Felix.

-   If you are running Ubuntu 14.04 or 16.04, you can install from our PPA:

        sudo add-apt-repository ppa:project-calico/{{ ppa_repo_name }}
        sudo apt-get update
        sudo apt-get upgrade
        sudo apt-get install calico-felix

-   If you are running a RedHat 7-derived distribution, you can install
    from our RPM repository:

        cat > /etc/yum.repos.d/calico.repo <<EOF
        [calico]
        name=Calico Repository
        baseurl=http://binaries.projectcalico.org/rpm/{{ ppa_repo_name }}/
        enabled=1
        skip_if_unavailable=0
        gpgcheck=1
        gpgkey=http://binaries.projectcalico.org/rpm/{{ ppa_repo_name }}/key
        priority=97
        EOF

        yum install calico-felix


Until you initialize the database, Felix will make a regular log that it
is in state "wait-for-ready". The default location for the log file is
`/var/log/calico/felix.log`.

## Initializing the etcd database

You should configure a `node` resource for each
host running Felix.  In this case, the database is initialized after
creating the first `node` resource.  For a deployment that does not include
the {{site.prodname}}/BGP integration, the specification of a node resource just 
requires the name of the node; for most deployments this will be the same as the
hostname.

```
calicoctl create -f - <<EOF
- apiVersion: projectcalico.org/v3
  kind: Node
  metadata:
    name: <node name or hostname>
EOF
```

The Felix logs should transition from periodic notifications 
that Felix is in the state `wait-for-ready` to a stream of initialization 
messages.

