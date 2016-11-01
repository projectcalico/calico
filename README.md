[![Build Status](https://semaphoreci.com/api/v1/calico/felix-2/branches/master/shields_badge.svg)](https://semaphoreci.com/calico/felix-2)
[![Coverage Status](https://coveralls.io/repos/projectcalico/felix/badge.svg?branch=master&service=github)](https://coveralls.io/github/projectcalico/felix?branch=master)
[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)
# Project Calico

Project Calico provides

- A simple, pure layer 3 networking approach with no overlays for networking
  "workloads" such as VMs and containers.
- A distributed firewall implementing rich and flexible network policy,
  imposed at ingress/egress to each workload.

For more information see [the Project Calico website](http://www.projectcalico.org/learn/).

This repository contains the source code for Project Calico's per-host
daemon, Felix.

## How do I get started with Project Calico?

Follow one of our [getting started guides](http://docs.projectcalico.org/master/getting-started/).

Calico can be used with a range of orchestrators including Docker, rkt,
Kubernetes, OpenStack and Mesos.

## How can I get support for Project Calico?

The best place to ask a question or get help from the community is the
[calico-users #slack](https://slack.projectcalico.org).  We also have
[an IRC channel](https://kiwiirc.com/client/irc.freenode.net/#calico).

In addition, the company behind Project Calico,
[Tigera, Inc.](https://www.tigera.io/) offers commercial support.

## Who is behind Project Calico?

[Tigera, Inc.](https://www.tigera.io/) is the company behind Project Calico
and is responsible for the ongoing management of the project. However, it
is open to any members of the community – individuals or organizations –
to get involved and contribute code.

Please [contact us](http://www.projectcalico.org/contact/) if you are
interested in getting involved and contributing to the project.

## Contributing

Thanks for thinking about contributing to Project Calico! The success of an
open source project is entirely down to the efforts of its contributors, so we
do genuinely want to thank you for even thinking of contributing.

Before you do so, you should check out our contributing guidelines in the
`CONTRIBUTING.md` file, to make sure it's as easy as possible for us to accept
your contribution.

## How do I build Felix?

Felix uses Docker for builds.  We develop on Ubuntu 16.04 but other
Linux distributions should work (we have not tried OS X).  To build
Felix, you will need to install:

- Docker >=1.12
- GNU make.
- Plenty of disk space (since the builds use some heavyweight
  full-OS containers in order to build debs and RPMs).

Then, run `make felix-docker-image`, for example, to build the `calico/felix`
container or `make help` for other options.

## How can I run Felix's unit tests?

After installing the prerequisites above, run `make ut` to run all the
tests, `make go-ut` to run Go tests only or `make python-ut` to run
Python tests.

## How can a subset of the go unit tests?

If you want to be able to run unit tests for specific packages for more iterative
development, you'll need to install

- GNU make
- go >=1.7

then run `make update-tools` to install ginkgo, which is the test tool used to
run Felix's unit tests.

There are several ways to run ginkgo.  One option is to change directory to the
package you want to test, then run `ginkgo`.  Another is to use ginkgo's
watch feature to monitor files for changes:
```
cd go
ginkgo watch -r
```
Ginkgo will re-run tests as files are modified and saved.

## How do I build packages/run Felix?

### Docker

After building the docker image (see above), you can run Felix with, for example:
`docker run --privileged --net=host -e FELIX_LOGSEVERITYSCREEN=INFO calico/felix`

### Debs and RPMs

The `Makefile` has targets for building debs and RPMS for different platforms.
By using docker, the build does not need to be run on the target platform.
```
make trusty-deb
make xenial-deb
make rpm
```
The packages (and source packages) are output to the dist directory.

By default, packages are built with a "snapshot" version number that is
greater than the current release version.

### Stand-alone bundle

The `make pyinstaller` target uses [PyInstaller](http://www.pyinstaller.org/)
to package Felix as a stand-alone bundle containing a Python distribution along
with Felix's Python dependencies.

To create a bundle run `make pyinstaller`.

The bundle will be output to `dist/calico-felix.tgz`.

Running the bundle requires

- libc version >=2.12
- Linux kernel >=2.6.32 (note: to support containers running on the
  host, kernel >=3.10 is required)
- `iptables`, `ipset` and `conntrack` (typically from the `conntrack-tools`
  package) to be available.

**Note:** the bundle itself doesn't require Docker.

To use the bundle,

- install the pre-requisites above
- unpack `calico-felix.tgz` on your target host (`/opt/calico-felix` would be
  a good place) and create a start-up script (for example, a systemd unit file
  or an upstart script) that runs the `calico-felix` binary found in the
  unpacked directory.  Your start-up script should be set to restart Felix on
  exit because Felix sometimes needs to restart to pick up configuration
  changes.
