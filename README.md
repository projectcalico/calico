[![Go Report Card](https://goreportcard.com/badge/github.com/projectcalico/node)](https://goreportcard.com/report/github.com/projectcalico/node)

# calico/node
<img src="http://docs.projectcalico.org/images/felix.png" width="100" height="100">

This repository contains the source for the `calico/node` container.

## Get Started Using Calico

For users who want to learn more about the project or get started with Calico, see the documentation on [docs.projectcalico.org](https://docs.projectcalico.org).

## Get Started Developing Calico

Contributions to this code are welcome! Before starting, make sure you've read [the Calico contributor guide][contrib].

### Dependencies

The entire build can be run within a container, which means the only dependencies you'll need are a [functioning Docker installation](https://docs.docker.com/engine/installation/).

### Building

The code in this repository can be built and tested using the Makefile.

- `make calico/node` will produce the `calico/node` docker image.

For more information, see `make help`.

[contrib]: https://github.com/projectcalico/calico/blob/master/CONTRIBUTING_CODE.md

## How can I run tests?

Tests for this repo are divided into the following categories:
- `fv`: Package scoped tests
- `st`: System integration tests
- `k8s-test`: Kubernetes integration tests

Assuming you have installed the necessary dependencies (see below for details), you can run any of the above categories using:

```
make <target>
```
Where `target` is one of `fv`, `st`, or `k8s-test`. You can also use `test`, which aggregates `fv` and `st`.

### Dependencies for running tests

If you want to be able to run tests locally, you will need to install:
- GNU make

For `st` system integration tests, node uses:
- Python (>= 2.7 ???)
- [Nose](https://nose.readthedocs.io/en/latest/)

For `fv` packaged scoped tests, node uses:
- Golang (>=1.7)
- [Ginkgo](https://github.com/onsi/ginkgo)

You will also need to install Ginkgo explicitly:
```
go get -u github.com/Masterminds/glide
go get -u github.com/onsi/ginkgo/ginkgo
```

For `k8s-test` Kubernetes tests, you will need to have `kubectl` setup on your machine. Go here for [instructions on setting up `kubectl` for your environment](https://kubernetes.io/docs/tasks/tools/install-kubectl/).

## How can I run a subset of the tests?

If you want to run tests for a specific package for more iterative development, you can filter down into a subset of tests using the following parameters:
- For filtering `st` tests, use `ST_TO_RUN`
- For filtering `k8s-test` tests, use `K8ST_TO_RUN`

For example, the following only runs tests within the `bgp` subfolder of the `st` category:
```
make st ST_TO_RUN="tests/st/bgp/"
```

To only run tests from a single file (e.g. `test_bgp.py`), use the following:
```
make st ST_TO_RUN="tests/st/bgp/test_bgp.py"
```

To only run a single test within a test file use the below syntax:
```
make st ST_TO_RUN="tests/st/bgp/test_bgp.py:TestReadiness.test_readiness_multihost"
```

The above examples should apply in the same fashion if you are using `K8ST_TO_RUN` instead for the `k8s-test` category.

## How do I debug tests?
There are a number of possible avenues you can use to debug failing tests.

1. Review the diagnostic logs after the tests finish running
- These only show for failed tests
- Be warned the logs are quite verbose
2. Use the parameter `DEBUG_FAILURES` with the Makefile
```
make st DEBUG_FAILURES=true
```
- This only applies to `st` tests
- A subset of the `st` are wrapped by `debug_failures(fn)` function found in `./tests/st/utils/utils.py`
- You should be able to wrap whatever test you want
- Uses Python's `pdb.set_trace()` library function, allows you to halt executing and step into the containers involved in the test for debugging
3. Use manual breakpoints
- A more primitive approach is just to add your own breakpoints (using something like `time.sleep(x)`)
- You should know where to add these after reviewing the diagnostic logs for failed tests (by looking at the stacktraces)

## Linux Dependencies
Below is a listing of userspace tools packaged into the node container. The list is not exhaustive, but highlights some of the key dependencies required for node to operate correctly.

- [`/usr/sbin/arp`](http://man7.org/linux/man-pages/man8/arp.8.html)
    - Manipulate the system ARP cache
    - Package: `net-tools`
- [`/usr/sbin/conntrack`](http://man7.org/linux/man-pages/man8/arp.8.html)
    - Netfilter connection tracking
    - Package: `conntrack`
- [`/bin/ip`](https://linux.die.net/man/8/ip)
    - Show / manipulate routing, devices, policy routing and tunnels
    - Package: `iproute2`
- [`/usr/sbin/iptables`](https://linux.die.net/man/8/iptables)
    - Admin tool for IPv4 packet filtering and NAT
    - Note, we're using the legacy version `iptables-legacy → xtables-legacy-multi` (divergence introduced in `iptables v1.8.2`)
    - Package: `iptables`
- [`/usr/sbin/iptables-restore`](https://linux.die.net/man/8/iptables-restore)
    - Note, we're using the legacy version `iptables-legacy-restore → xtables-legacy-multi` (divergence introduced in `iptables v1.8.2`)
    - Package: `iptables`
- [`/usr/sbin/iptables-save`](https://linux.die.net/man/8/iptables-save)
    - Note, we're using the legacy version `iptables-legacy-save → xtables-legacy-multi` (divergence introduced in `iptables v1.8.2`)
    - Package: `iptables`
- [`/usr/sbin/ip6tables`](https://linux.die.net/man/8/ip6tables)
    - Admin tool for IPv6 packet filtering and NAT
    - Note, we're using the legacy version `ip6tables-legacy → xtables-legacy-multi` (divergence introduced in `iptables v1.8.2`)
    - Package: `iptables`
- `/usr/sbin/ip6tables-restore`
    - Note, we using the legacy version `ip6tables-legacy-restore → xtables-legacy-multi` (divergence introduced in `iptables v1.8.2`)
    - Package: `iptables`
- `/usr/sbin/ip6tables-save`
    - Note, we using the legacy version `ip6tables-legacy-save → xtables-legacy-multi` (divergence introduced in `iptables v1.8.2`)
    - Package: `iptables`
- [`/bin/ps`](https://linux.die.net/man/1/ps)
    - Snapshot of the current processes
    - Package: `procps`
- [`/bin/kmod`](http://man7.org/linux/man-pages/man8/kmod.8.html)
    - Manage Linux Kernel modules
    - soft link for `depmod`, `insmod`, `lsmod`, `modinfo`, `modprobe`, `rmmo`
    - Package: `kmod`
- [`/sbin/runit`](http://smarden.org/runit/)
    - Init scheme with service supervision
    - Package: `runit`
- [`/usr/sbin/runsvchdir`](http://smarden.org/runit/runsvdir.8.html)
    - Starts and monitors a collection of runsv processes
    - Package: `runit`

### License

Calico binaries are licensed under the [Apache v2.0 license](LICENSE), with the exception of some [GPL licensed eBPF programs](https://github.com/projectcalico/felix/tree/master/bpf-gpl).

Calico imports packages with a number of apache-compatible licenses. For more information, see [filesystem/licenses](./filesystem/licenses). In addition, the base container image contains
pre-packaged software with a variety of licenses.
