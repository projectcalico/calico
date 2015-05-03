# Project Calico

Calico represents a new approach to virtual networking, based on the same
scalable IP networking principles as the Internet.

First established in enterprise data centers, virtual networking provides the
logical fabric that enables workloads in virtual machines to communicate
securely, ultimately over a shared physical fabric. Initially this was achieved
by using VLANs; as that approach quickly hit well-known scalability limits,
other techniques such as VXLAN, GRE-based tunnels and SDN controlled flows were
taken. All of these approaches introduced greater complexity and ultimately hit
scalability and performance limits inherent in extending an enterprise-class
layer 2 network over large numbers of servers and wide area links.

A new approach is required. One that recognizes that the vast majority of
today’s workloads are based on IP, and that leverages everything we already
know about how to build high-performance, large-scale networks.

Enter Project Calico. With Calico, we went back to the drawing board and
redesigned how virtual networks should be built, based on an intimate
understanding of the requirements of modern workloads and virtualization
environments.

## What does Calico do?

Calico integrates seamlessly with the cloud orchestration system (such as
OpenStack) to enable secure IP communication between virtual machines or containers. As VMs or containers
are created or destroyed, their IP addresses are advertised to the rest of the
network and they are able to send/receive data over IP just as they would with
the native networking implementation – but with higher
[security, scalability and performance](http://www.projectcalico.org/learn/).

## How do I get started with Project Calico?

To get started on
[OpenStack](http://www.openstack.org/) follow the instructions
[here](http://docs.projectcalico.org/en/latest/openstack.html). To get started on
[Docker](http://www.docker.com/) follow the instructions
[here](https://github.com/Metaswitch/calico-docker/blob/master/README.md).

Technical documentation is [here](http://docs.projectcalico.org/). For
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

This will install the code and all its dependencies, *except for Neutron or Docker dependencies*. This
is all you need to work on Felix. If you want to work on our OpenStack plugin,
you'll also need to install Neutron: doing that is outside the scope of this
article.  If you want to work on Docker integration please see the [calico-docker](https://github.com/Metaswitch/calico-docker) repo.

To run the unit tests, you'll also need to type:

    pip install nose mock

Then, still at the root of the calico directory, run:

    nosetests

### Fewer dependencies

If you only want to hack on one or two components you may not want to install
the dependencies for the others. To do that, you can set the `$CALICODEPS`
environment variable before installing the code. Set the variable to a
comma-separated list of the names of the components you want to install the
dependencies for.

For example, if you want to work on Felix, you will want to set it to `felix`.
With that set, you can then run `pip install -e .`, which will install the
subset of the dependencies needed for those components.
