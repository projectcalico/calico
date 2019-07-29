
# Calico packaging

This repo aims to automate and document every step needed to build and
publish Calico packages, for use [with
OpenStack](https://docs.projectcalico.org/master/getting-started/openstack/installation/)
or [on bare metal
hosts](https://docs.projectcalico.org/master/getting-started/bare-metal/installation/).

A single

    make release-publish

command will build and publish a set of packages corresponding to
current Calico master code, to our PPA and RPM repo named "master";
similarly,

    make release-publish VERSION=vX.Y.Z

will build and publish a set of packages for version X.Y.Z, to our PPA
and RPM repo named "calico-X.Y".

For documentation, this file should contain everything needed to
understand how our packaging works, what components we package, and
why.

## Status

`make release-publish` exists but currently only builds and publishes
packages for networking-calico.

To do:

-  Also build packages for Felix, etcd3gw and dnsmasq.
-  If possible, automate new PPA creation (which is currently still a
   manual step).
-  Perhaps support preparing a PPA/RPM repo for code that is still in
   development.
-  Review support for building packages on ppc64 instead of amd64.

## Usage

`make release-publish`, with the following required environment
variables.

-  `HOST` and `GCLOUD_ARGS` set to indicate the GCP name of the RPM
   host, and a GCP identity that permits logging into that host.

-  `SECRET_KEY` set to a file containing the GPG secret key for a
   member of the [Project Calico team on
   Launchpad](https://launchpad.net/~project-calico).

## Packaging platforms

We build and publish packages for these platforms:

-  Ubuntu 14.04 (Trusty), 16.04 (Xenial) and 18.04 (Bionic).  The
   hosting for these packages is in PPAs at
   https://launchpad.net/~project-calico.

-  CentOS 7 or RHEL 7.  The hosting for these packages is in RPM repos
   at binaries.projectcalico.org (for example
   http://binaries.projectcalico.org/rpm/calico-3.8/).

## Packaged components

The components that we package and host are:

-  networking-calico - for all platforms.

-  Felix - for all platforms.

-  etcd3gw - for CentOS/RHEL 7 only.

   Note: for Ubuntu there is no packaging for etcd3gw, and we instead
   [document](https://docs.projectcalico.org/master/getting-started/openstack/installation/ubuntu)
   that the installer must do `pip install etcd3gw`.

-  dnsmasq - for all platforms.
