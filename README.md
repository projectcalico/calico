<!--- master only -->
[![Build Status](https://semaphoreci.com/api/v1/projects/9d7d365d-19cb-4699-8c84-b76da25ae271/473490/shields_badge.svg)](https://semaphoreci.com/calico/calico-docker--5)
[![CircleCI branch](https://img.shields.io/circleci/project/projectcalico/calico-containers/master.svg?label=calicoctl)](https://circleci.com/gh/projectcalico/calico-containers/tree/master)
[![Coverage Status](https://coveralls.io/repos/github/projectcalico/calico-containers/badge.svg?branch=master)](https://coveralls.io/github/projectcalico/calico-containers?branch=master)
[![Docker Pulls](https://img.shields.io/docker/pulls/calico/node.svg)](https://hub.docker.com/r/calico/node/)
[![](https://badge.imagelayers.io/calico/node:latest.svg)](https://imagelayers.io/?images=calico/node:latest)

[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)
<!--- end of master only -->

# Calico for Containers

Calico provides a highly scalable networking solution for connecting data
center workloads (containers, VMs, or bare metal).  It is based on the same
scalable IP networking principles as the internet: providing connectivity using
a pure Layer 3 approach.  Calico can be deployed without encapsulation or
overlays to provide high performance at massive scales.

Read more about it on the [Project Calico website](https://www.projectcalico.org).

When using Calico networking in containerized environments, each container
gets its own IP and fine grain security policy.  A `calico-node` service runs
on each node which handles all of the necessary IP routing, installation of
policy rules, and distribution of routes across the cluster of nodes.

This repository contains:
-  The `calico/node` container Dockerfile and build environment.  It contains
  the configuration and "glue" that pull together four separate processes to
  provide Calico networking:
  * Felix, the Calico worker process
  * BIRD, the route distribution process
    (there are separate processes for IPv4 and IPv6)
  * Confd, a templating process to auto-generate configuration for BIRD
-  A command line tool, `calicoctl`, which makes it easy to configure
   and start the Calico service listed above, and allows you to interact with
   the datastore (etcd) to define and apply rich security policy to the
   containers you create.
-  Build, test and release frameworks.

## Getting Started

**For more information on deploying and using calico, see [Calico Documentation](http://docs.projectcalico.org).**

## Contact

We welcome questions/comments/feedback (and pull requests).

* [Slack Calico Users Channel](https://slack.projectcalico.org)
* [Announcement Mailing List](http://lists.projectcalico.org/mailman/listinfo/calico-announce_lists.projectcalico.org)
* [Technical Mailing List](http://lists.projectcalico.org/mailman/listinfo/calico-tech_lists.projectcalico.org)
* IRC - [#calico](https://kiwiirc.com/client/irc.freenode.net/#calico)
* For issues related to Calico in a containerized environment, please
[raise issues](https://github.com/projectcalico/calico-containers/issues/new) on
GitHub.

## Contributing

If you are interested in contributing, please review our [contributing guidelines](CONTRIBUTING.md).

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
