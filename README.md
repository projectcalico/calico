[![Coverage Status](https://coveralls.io/repos/projectcalico/calico/badge.svg?branch=master&service=github)](https://coveralls.io/github/projectcalico/calico?branch=master)
[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)
# Project Calico

Project Calico represents a new approach to virtual networking, based on the
same scalable IP networking principles as the Internet.  Unlike other virtual
networking approaches, Calico does not use overlays, instead providing a pure
Layer 3 approach to data center networking.  Calico is simple to deploy and
diagnose, provides a rich security policy, supports both IPv4 and IPv6 and can
be used across a combination of bare-metal, VM and container workloads.

Calico implements a highly efficient vRouter in each compute node that
leverages the existing Linux kernel forwarding engine without the need for
vSwitches. Each vRouter propagates workload reachability information (routes)
to the rest of the data center using BGP – either directly in small scale
deployments or via BGP route reflectors to reach Internet level scales in large
deployments.

Calico peers directly with the data center’s physical fabric (whether L2 or L3)
without the need for on/off ramps, NAT, tunnels, or overlays.

Calico supports rich and flexible network policy which it enforces using
bookended ACLs on each compute node to provide tenant isolation, security
groups, and external reachability constraints.

For more information see [the Project Calico website](http://www.projectcalico.org/learn/).

## How do I get started with Project Calico?

To get started on [OpenStack](http://www.openstack.org/) follow the
instructions [in our docs](http://docs.projectcalico.org/en/latest/openstack.html).
To get started on [Docker](http://www.docker.com/) follow the instructions
[in the calico-containers repo](https://github.com/projectcalico/calico-containers/blob/master/README.md).

Technical documentation is at <http://docs.projectcalico.org/>. For
information about contributing to Calico itself, see the section titled
'Contributing' below.

## How can I get support for Project Calico?

There are two options for getting support for Calico. You can simply
[get in contact](http://www.projectcalico.org/contact/) and ask any question
you like – there is an active group of users and developers who will usually
try their best to help you or point you in the right direction. Or you can work
with one of the commercial vendors and system integrators who provide
installation, integration, customization and support services for Calico.

Currently, we are aware of the following vendors who provide commercial support
services:

- Metaswitch Networks.

Please [contact us](http://www.projectcalico.org/contact/) if you are a
vendor providing commercial support services and wish to be added to this list.

## Who is behind Project Calico?

Project Calico was founded by Metaswitch Networks, who also contributed the
original implementation to open source and are responsible for the ongoing
management of the project. However, it is open to any members of the community
– individuals or organizations – to get involved and contribute code.

Please [contact us](http://www.projectcalico.org/contact/) if you are
interested in getting involved and contributing to the project.

## Contributing

Thanks for thinking about contributing to Project Calico! The success of an
open source project is entirely down to the efforts of its contributors, so we
do genuinely want to thank you for even thinking of contributing.

Before you do so, you should check out our contributing guidelines in the
`CONTRIBUTING.md` file, to make sure it's as easy as possible for us to accept
your contribution.

## How do I hack on Calico?

It's great that you're interested! In additional to being able to install
Calico from packages, you can install the source directly. If you want to work
on the code, we recommend installing the source directly in a Python
[virtual environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/).
In your virtual environment, switch to the directory containing the code and
type:

    pip install -e .

This will install the code and all its dependencies, *except for Neutron or
Docker dependencies*. This is all you need to work on Felix. If you want to
work on our OpenStack plugin, you'll also need to install Neutron: doing that
is outside the scope of this article.  If you want to work on Docker
integration please see the
[calico-docker](https://github.com/projectcalico/calico-docker) repo.

If you want to run the unit tests, first install dependencies:

    apt-get install git libffi-dev libyajl2 python-dev python-pip
    pip install coverage tox

Then, still at the root of the Calico directory (not inside a virtualenv), run:

    ./run-unit-test.sh -r

Tox runs the tests under Python 2.6, 2.7 and PyPy, which you will need to [install separately](http://pypy.readthedocs.org/en/latest/install.html).

### Fewer dependencies

If you only want to hack on one or two components you may not want to install
the dependencies for the others. To do that, you can set the `$CALICODEPS`
environment variable before installing the code. Set the variable to a
comma-separated list of the names of the components you want to install the
dependencies for.

For example, if you want to work on Felix, you will want to set it to `felix`.
With that set, you can then run `pip install -e .`, which will install the
subset of the dependencies needed for those components.

### Docker

Felix can be run inside Docker. See the `docker_build_and_run.sh` script for details on building and running it.
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
