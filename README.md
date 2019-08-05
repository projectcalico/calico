
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

`make release-publish` currently builds and publishes packages for
Felix, networking-calico and etcd3gw.

Still to do:

-  Also build packages for dnsmasq.
-  If possible, automate new PPA creation (which is currently still a
   manual step).
-  Review support for building packages on ppc64 instead of amd64.

## Usage

`make release-publish`, with the following required environment
variables.

-  `HOST` and `GCLOUD_ARGS` set to indicate the GCP name of the RPM
   host, and a GCP identity that permits logging into that host.

-  `SECRET_KEY` set to a file containing the GPG secret key for a
   member of the [Project Calico team on
   Launchpad](https://launchpad.net/~project-calico).

Supported, optional environment variables:

-  `VERSION`: specify the Calico version to build packages for.
   Default is `master`.

-  `REPO_NAME`: override the PPA and RPM repo name to publish to.
   Default is automatically derived from `VERSION`.

-  `FELIX_REPO`: override the Git repository to get Felix code from.
   Default is https://github.com/projectcalico/felix.git.

-  `FELIX_CHECKOUT`: override the point in the Git repository to check
   out (a Git commit ID, tag or branch name).  Default is
   automatically derived from `VERSION`.

-  `NETWORKING_CALICO_REPO`: override the Git repository to get
   networking-calico code from.  Default is
   https://opendev.org/openstack/networking-calico.git.

-  `NETWORKING_CALICO_CHECKOUT`: override the point in the Git
   repository to check out (a Git commit ID, tag or branch name).
   Default is automatically derived from `VERSION`.

-  `STEPS`: override the parts of the process to execute.  Default is
   all of the following:

   -  `ppa`: Check that PPA exists.

   -  `rpm_repo`: Ensure that the RPM repository exists.

   -  `bld_images`: Build required container images for building
      packages for each target platform.

   -  `net_cal`: Build networking-calico packages.

   -  `felix`: Build Felix packages.

   -  `etcd3gw`: Build etcd3gw packages (RPM only).

   -  `pub_debs`: Publish all Debian packages.

   -  `pub_rpms`: Publish all RPMs.

Note that `pub_debs` means uploading Debian source packages to
Launchpad, and it can still take a long time for Launchpad to build
and publish binary Debian packages.  Usually about an hour, but
occasionally many hours.  A package is only really ready for use when
its line on the PPA package details page ([for
example](https://launchpad.net/~project-calico/+archive/ubuntu/master/+packages))
has a green tick in the Build Status column and a date in the
Published column.

(RPMs, on the other hand, are ready immediately after the `pub_rpms` step.)

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
