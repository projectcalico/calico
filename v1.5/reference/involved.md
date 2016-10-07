---
title: Getting Involved
---

Calico is an open source project, and we'd love you to get involved.
Whether that might be by reading and participating on our mailing list,
or by diving into the code to propose enhancements or integrate with
other systems. To see the options for getting involved with Calico the
project, please take a look at the following.

## Mailing Lists

Project Calico runs two mailing lists:

-   [calico-announce](http://lists.projectcalico.org/mailman/listinfo/calico-announce_lists.projectcalico.org)
    provides a read-only list providing a regular update on Project
    Calico. Please subscribe so that you can keep up to date on
    the project.
-   [calico-tech](http://lists.projectcalico.org/mailman/listinfo/calico-tech_lists.projectcalico.org)
    provides a list for technical discussions and queries about the
    project. You're welcome to subscribe and to post any Calico-related
    discussion to this list, including problems, ideas, or requirements.

When reporting a problem on calico-tech, please try to:

-   provide a clear subject line
-   provide as much diagnostic information as possible.

That will help us (or anyone else) to answer your question quickly and
correctly.

## Read the Source, Luke!

All Calico's code is on [GitHub](https://github.com/projectcalico), in
the following repositories, separated by function.

-   [calico](https://github.com/projectcalico/calico) - All of the core
    Calico code except for that specific to Docker/container
    environments: the Felix agent, the OpenStack plugin; testing for all
    of those; and the source for Calico's documentation.
-   [calico-containers](https://github.com/projectcalico/calico-containers) -
    Calico code and components specific to Docker/container
    environments: the lightweight orchestrator for Docker environments,
    Powerstrip adapter, and so on; and instructions for demonstrating
    Calico networking in various container environments.
-   [calico-neutron](https://github.com/projectcalico/calico-neutron)
    -Calico-specific patched version of OpenStack Neutron.
-   [calico-nova](https://github.com/projectcalico/calico-nova) -
    Calico-specific patched version of OpenStack Nova.
-   [calico-dnsmasq](https://github.com/projectcalico/calico-dnsmasq)
    -Calico-specific patched version of Dnsmasq.
-   [calico-chef](https://github.com/projectcalico/calico-chef) - Chef
    cookbooks for installing test versions of OpenStack-using-Calico.

## Contributing

Calico follows the "Fork & Pull" model of collaborative development,
with changes being offered to the main Calico codebase via Pull
Requests. So you can contribute a fix, change or enhancement by forking
one of our repositories and making a GitHub pull request. If you're
interested in doing that:

-   Thanks!
-   See the [GitHub docs](https://help.github.com/articles/using-pull-requests) for how
    to create a Pull Request.
-   Check our [contibution guide](contribute) for more information.
