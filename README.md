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

Calico can be used with a range of orchestrators:

- To get started with [Docker](http://www.docker.com/), [Kubernetes](http://kubernetes.io/) or [Mesos](http://mesos.apache.org/) follow the instructions
[in the calico-containers repo](https://github.com/projectcalico/calico-containers/blob/master/README.md).
- To get started with [OpenStack](http://www.openstack.org/) follow the
instructions [in our docs](http://docs.projectcalico.org/en/latest/openstack.html).

Technical documentation is at <http://docs.projectcalico.org/>. For
information about contributing to Calico itself, see the section titled
'Contributing' below.

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

## How do I hack on Felix?

We recommend using a Python virtualenv to isolate your dev environment.
We typically develop on Ubuntu 14.04 (if you're using a later version, 
make sure you develop with python2.7).  On Ubuntu, to install the dependencies,
create a virtualenv and install Calico into it:

    apt-get install git libffi-dev libyajl2 python-dev python-pip
    pip install coverage tox virtualenv
    virtualenv env
    source env/bin/activate
    pip install -e .
    
To run specific unit tests, use `nosetests`; for example:

    nosetests calico.felix.test.test_selectors
    
To deactivate the virtualenv:

    deactivate
    
To run the unit tests (from outside a virtualenv), run:

    ./run-unit-test.sh --develop
    
To run felix with log output to screen, first become root (using, 
for example `sudo -i`), then:

    cd <path to calico dir>
    source env/bin/activate
    FELIX_LOGSEVERITYSCREEN=INFO calico-felix
    
*Note:* Felix must be run as root because it needs to moanipulate the
kernel routing table and firewall rules.

## How do I build/run Felix

### Docker

Felix can be run inside Docker. See the `docker_build_and_run.sh` script for details on building and running it.
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico/README.md?pixel)](https://github.com/igrigorik/ga-beacon)

### Stand-alone bundle

The `build-pyi-bundle.sh` script uses [PyInstaller](http://www.pyinstaller.org/) 
to package Felix as a stand-alone bundle containing a Python distribution along
with Felix's Python dependencies.  

To create a bundle

- [install Docker](`build-pyi-bundle.sh`) on a Linux system (we haven't tested 
  the build on Mac)
- run `./build-pyi-bundle.sh`

The bundle will be output to `dist/calico-felix.tgz`.

Running the bundle requires

- libc version 2.12 or newer
- Linux kernel 2.6.32 or higher (note: to support containers running on the 
  host, kernel 3.10+ is required)
- `iptables`, `ipset` and `conntrack` (typically from the `conntrack-tools` 
  package) to be available.

**Note:** the bundle itself doesn't require Docker.

To use the bundle, 

- install the pre-requisites above
- unpack `calico-felix.tgz` on your target host (`/opt/calico-felix` would be 
  a good place) and create a start-up script (for example, a systemd unit file 
  or an upstart script) that runs the `calico-felix` binary found in the 
  unpacked directory.  Your start-up script should be set to restart Felix on 
  exit because Felix simetimes needs to restart to pick up configuration 
  changes. 

### Debs and RPMs

The Calico team build debs and RPMs for releases of Calico but right now the
processes involve our build server.  Please get in touch if you need to build 
your own packages.
