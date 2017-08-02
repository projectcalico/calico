[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)
[![Docker Pulls](https://img.shields.io/docker/pulls/calico/node.svg)](https://hub.docker.com/r/calico/node/)
[![](https://badge.imagelayers.io/calico/node:latest.svg)](https://imagelayers.io/?images=calico/node:latest)

# Calico

This repository contains the source code for [Project Calico](https://www.projectcalico.org/)'s documentation and demos as well as the source for the `calico/node` container.

<blockquote>
Note that the README in this repo is targeted at Calico docs contributors.
<h1>Documentation for Calico users is here:<br><a href="http://docs.projectcalico.org">http://docs.projectcalico.org</a></h1>
</blockquote>


For information on `calico/node`, see the [documentation on calico/node architecture](http://docs.projectcalico.org/master/reference/architecture/components).

### Developing

Print useful actions with `make help`.

![Project Calico logo](http://docs.projectcalico.org/images/felix.png)


### Building `calico/node`

To build the `calico/node` container, run the following build step from
the root of the repository:

```
make -C calico_node calico/node
```

Use the build variables listed in the `Calico binaries` variable section
at the top of the Makefile to modify which components are included in the resulting image.
For example, the following command will produce a docker image called `calico/node:custom`
which uses custom Felix and Libnetwork binaries:

```
FELIX_CONTAINER_NAME=calico/felix:1.4.3 \
LIBNETWORK_PLUGIN_CONTAINER_NAME=calico/libnetwork-plugin:v1.0.0-beta \
BUILD_CONTAINER_NAME=calico/node:custom \
make calico/node
```

The canonical source for which versions are included in the `calico/node` image come from the `_date/versions.yml` file.


### Building the docs

See [CONTRIBUTING_DOCS.md](CONTRIBUTING_DOCS.md)