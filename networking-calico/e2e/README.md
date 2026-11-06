# Calico OpenStack e2e tests

System tests for Calico as the networking provider for OpenStack.  The tests
run in a container, on a "test node" alongside an existing OpenStack cluster
that uses Calico, and drive that cluster through the OpenStack APIs and over
SSH: they create tenants, networks, security groups and VMs, and check that
connectivity between VMs, and between VMs and hosts, is as Calico policy says
it should be.

## Building the image

```sh
make e2e-image
```

builds the `openstack-e2e` image from:

- `calicotest/` - the test framework and test code, and in
  `calicotest/scripts/` the scripts used when running tests, including the
  image entrypoint (`e2e-entrypoint.sh`) and the `run-test.sh` wrapper it
  delegates to
- `scripts/` - `prepare-test-runtime.sh`, which builds the test venv
- `requirements.txt` - Python dependencies for the test venv
- `patches/` - OpenStack QoS packet-rate-limit patches, applied into the test
  venv when the image is built
- `Dockerfile` - which also fetches, from the permanent Debian archive, the
  Debian packages that the tests install onto test VMs (which are not assumed
  to have internet access)

## Known-good cluster layouts

The suite is not yet general: many tests assume a particular number of nodes,
and particular roles for them.  It is known to work with the following two
layouts, and probably only with those.

**Single region:**

- One controller node, running Keystone, Glance, Nova's control services,
  Placement, Neutron with networking-calico as its core plugin, and Calico's
  etcd v3 datastore.  The tests reach etcd, and in one case Keystone, at the
  host name `controller`, so that must resolve to this node.
- Three compute nodes, each running nova-compute, Felix and BIRD.  The tests
  take them in the order their sections appear in the layout file, and rely
  on that order.  The first also serves the shared (NFS) instance storage that
  live migration needs.  The migration tests keep a bystander VM on the first
  compute node, and migrate VMs between the second and third, while
  `test_graceful_restart` migrates VMs between all three.

**Multi-region:** as above for the first region, plus a second region with its
own controller and one compute node.  The second controller runs a full
OpenStack control plane, but no etcd: both regions share the first region's
Calico datastore, and `controller` still means the first region's controller.
The multi-region tests run only when the layout file describes two regions,
and are skipped otherwise.

Either way, the cluster also needs:

- Authentication enabled on etcd v3, at port 2379, with these fixed
  credentials: `calicouser` / `calicopasswd`, and `root` / `rootpasswd` for
  `etcdctl` in diags collection.
- Two images in Glance, described in [VM images](#vm-images):
  - `cirros-x86_64`: CirrOS 0.6, with the standard `cirros` / `gocubsgo` login.
  - `ipv6_enabled_image`: an Ubuntu image that allows password login as
    `ubuntu` / `ubuntu` and supports DHCPv6.  Some tests also use a web server,
    a SIP server and `tcpdump` inside it.
- A test node that runs Docker and:
  - can SSH, with a private key, to every node in the cluster, as a user with
    passwordless sudo;
  - has routes to the tenant VM networks, because the tests reach VMs
    directly; in the known-good layouts it runs BIRD and peers with Calico;
  - can resolve `controller`, and each node's name as given in the layout
    file, from inside a container that uses the host's network.

## VM images

Tigera's cluster installer uploads both images from the `calico-jenkins` GCS
bucket.

`cirros-x86_64` is
<https://storage.googleapis.com/calico-jenkins/cirros-0.6.0-x86_64-disk.img>,
an unmodified copy of upstream CirrOS 0.6.0: it is byte-for-byte identical to
<https://download.cirros-cloud.net/0.6.0/cirros-0.6.0-x86_64-disk.img>
(SHA-256 `94e1e2c94dbbae7d4bdc38e68590a1daf73c9de2d03dd693857b4b0a042548e8`).

`ipv6_enabled_image` is
<https://storage.googleapis.com/calico-jenkins/dl-ubuntu_w_ipv6_asterisk_apache.img>.
It was made by hand between January and March 2015, from the Ubuntu 14.04.1
(Trusty) server cloud image with serial 20150123.1, and ended up as a snapshot
of a VM booted from that image.  The changes were:

- The IPv6 preparation steps for Ubuntu in
  [Calico's OpenStack IPv6 docs](https://docs.tigera.io/calico/latest/networking/openstack/ipv6):
  - `new_ip6_prefixlen=128` at the start of `/sbin/dhclient-script`;
  - `/etc/sysctl.d/30-eth0-rs-delay.conf`, setting
    `net.ipv6.conf.eth0.router_solicitation_delay = 10`;
  - an `iface eth0 inet6 dhcp` stanza, with `accept_ra 1`, in
    `/etc/network/interfaces.d/eth0.cfg`.  That file also sets
    `dns-nameservers 8.8.8.8`.
- Password login: `lock_passwd: False` in `/etc/cloud/cloud.cfg`,
  `PasswordAuthentication yes` in `/etc/ssh/sshd_config`, and a password for
  `ubuntu`.
- Apache (`apache2`) and Asterisk (`asterisk`), from the Trusty archive, with
  their stock configuration.  `test_applications` fetches Apache's default
  page, and sends a SIP OPTIONS request to Asterisk's extension 1234, while
  `test_spoofing` uses Asterisk to set up a UDP flow.

Because the image is a snapshot of a VM that had booted, it also keeps that
VM's SSH host keys, its `authorized_keys` for `ubuntu` and `root`, and its
host name.  The tests don't depend on any of these.

## Cluster layout file

The tests read the cluster's description from
`/calico-test/config/cluster-layout.conf`.  For the single-region layout:

```ini
[DEFAULTS]
# Private key for SSH access to the nodes.
keyfile = /root/.ssh/id_rsa
# This test node's IP address as seen from the cluster; if omitted, the tests
# work it out from the test node's routes.
test_node_ip = 192.168.8.1
os_type = Ubuntu

# One section per node.  fqdn must be the node's host name, because the tests
# derive Nova availability zone names from it.
[control-1]
role = controller
fqdn = control-1
ip = 192.168.8.2
username = ubuntu
admin-password = <Keystone admin password>
region = regionone

# The compute nodes, in order; the first is the NFS server.
[compute-1]
role = compute
fqdn = compute-1
ip = 192.168.8.3
username = ubuntu
region = regionone

[compute-2]
role = compute
fqdn = compute-2
ip = 192.168.8.4
username = ubuntu
region = regionone

[compute-3]
role = compute
fqdn = compute-3
ip = 192.168.8.5
username = ubuntu
region = regionone
```

For the multi-region layout, add a second controller and its compute node,
with their own region name:

```ini
[control-2]
role = controller
fqdn = control-2
ip = 192.168.8.6
username = ubuntu
admin-password = <Keystone admin password>
region = regiontwo

[compute-r2]
role = compute
fqdn = compute-r2
ip = 192.168.8.7
username = ubuntu
region = regiontwo
```

## Running

```sh
docker run --rm --network host \
  -v <path to cluster-layout.conf>:/calico-test/config/cluster-layout.conf:ro \
  -v <path to SSH private key>:/root/.ssh/id_rsa:ro \
  -v <results dir>:/output \
  -e TEST_REQ=<selector> \
  openstack-e2e
```

where `TEST_REQ` is one of:

- `smoke` (the default): `test_mainline_connectivity.py` only
- `full-fv`: the whole suite
- `fail`: a deliberately failing test, for exercising failure handling
- `calicotest/openstack/<file>.py`: a single test file

JUnit XML results land in `<results dir>/results/`.  When a test fails, the
suite runs `calico-diags` on each node and collects the results into
`/calico-test/diags` in the container, so mount a directory there too if you
want to keep them.

To run changed test code without rebuilding the image, also mount a source
checkout's `calicotest/` over the image's copy:

```sh
  -v <checkout>/calicotest:/calico-test/calicotest
```

Only `calicotest/` can be overridden that way; everything else is only used to
build the image.
