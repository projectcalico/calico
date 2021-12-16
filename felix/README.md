![Build Status](https://tigera.semaphoreci.com/badges/felix.svg?style=shields&key=48267e65-4acc-4f27-a88f-c3df0e8e2c3b)
[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![Go Report Card](https://goreportcard.com/badge/github.com/projectcalico/felix)](https://goreportcard.com/report/github.com/projectcalico/felix)
# Project Calico

<blockquote>
Note that the documentation in this repo is targeted at Calico contributors.
<h1>Documentation for Calico users is here:<br><a href="http://docs.projectcalico.org">http://docs.projectcalico.org</a></h1>
</blockquote>

This repository contains the source code for Project Calico's per-host
daemon, Felix.

## Licensing

Felix itself, along with most of Calico, is licensed under the Apache v2.0 license.  The BPF programs
in the bpf-gpl directory are licensed under the GPL v2.0 for compatibility with Linux kernel helper 
functions. 

## How can I get support for contributing to Project Calico?

The best place to ask a question or get help from the community is the
[calico-users #slack](https://slack.projectcalico.org).  We also have
[an IRC channel](https://kiwiirc.com/client/irc.freenode.net/#calico).

## Who is behind Project Calico?

[Tigera, Inc.](https://www.tigera.io/) is the company behind Project Calico
and is responsible for the ongoing management of the project. However, it
is open to any members of the community – individuals or organizations –
to get involved and contribute code.

## Contributing

Thanks for thinking about contributing to Project Calico! The success of an
open source project is entirely down to the efforts of its contributors, so we
do genuinely want to thank you for even thinking of contributing.

Before you do so, you should check out our contributing guidelines in the
`CONTRIBUTING.md` file, to make sure it's as easy as possible for us to accept
your contribution.

## How do I build Felix?

Felix mostly uses Docker for builds.  We develop on Ubuntu 16.04 but other
Linux distributions should work (there are known `Makefile` issues that prevent building on OS X).  
To build Felix, you will need:

- A suitable linux box.
- To check out the code into your GOPATH.
- Docker >=1.12
- GNU make.
- Plenty of disk space (since the builds use some heavyweight
  full-OS containers in order to build debs and RPMs).

Then, as a one-off, run
```
make update-tools
```
which will install a couple more go tools that we haven't yet containerised.

Then, to build the calico-felix binary:
```
make build
```
or, the `calico/felix` docker image:
```
make image
```

### Other architectures
When you run `make build` or `make image`, it creates the felix binary or docker image for linux on your architecture. The outputs are as follows:

* Binary: `bin/calico-felix-${ARCH}`, e.g. `bin/calico-felix-amd64` or `bin/calico-felix-arm64`
* Image: `calico/felix:${TAG}-${ARCH}`, e.g. `calico/felix:3.0.0-amd64` or `calico/felix:latest-ppc64le`

When you are running on `amd64`, you can build the binaries and images for other platforms by setting the `ARCH` variable. For example:

```
$ make build ARCH=arm64 # OR
$ make image ARCH=ppc64le
```

If you wish to make **all** of the binaries or images, use the standard calico project targets `build-all` and `image-all`:

```
$ make build-all # OR
$ make image-all
```

Note that the `image` and `image-all` targets have the `build` targets as a dependency.

## How can I run Felix's unit tests?

To run all the UTs:
```
make ut
```

To start a `ginkgo watch`, which will re-run the relevant UTs as you update files:
```
make ut-watch
```

To get coverage stats:
```
make cover-report
```
or
```
make cover-browser
```

## How can I run a subset of the go unit tests?

If you want to be able to run unit tests for specific packages for more iterative
development, you'll need to install

- GNU make
- go >=1.10

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

After building the docker image (see above), you can run Felix and log to screen
with, for example:

```
docker run --privileged \
           --net=host \
           -v /run:/run \
           -e FELIX_LOGSEVERITYSCREEN=INFO \
           calico/felix
```

Notes:

- `--privileged` is required because Felix needs to execute iptables and other privileged commands.
- `--net=host` is required so that Felix can manipulate the routes and iptables tables in the host
  namespace (outside its container).
- `-v /run:/run` is required so that Felix shares the global iptables file lock with other
  processes; this allows Felix and other daemons that manipulate iptables to avoid clobbering each
  other's updates.
- `-e FELIX_LOGSEVERITYSCREEN=INFO` tells Felix to log at info level to stderr.

### Debs and RPMs

The `Makefile` has targets for building debs and RPMs for different platforms.
By using docker, the build does not need to be run on the target platform.
```
make deb
make rpm
```
The packages (and source packages) are output to the dist directory.
