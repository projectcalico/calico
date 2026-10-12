
# Calico packaging

This repo automates and documents every step needed to build and
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

This file documents everything needed to understand how our packaging
works, what components we package, and why.

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

-  `STEPS`: override the parts of the process to execute.  Default is
   all of the following:

   -  `bld_images`: Build required container images for building
      packages for each target platform.

   -  `net_cal`: Build networking-calico packages.

   -  `felix`: Build Felix packages.

   -  `calicoctl`: Build calicoctl packages.

   -  `etcd3gw`: Build etcd3gw packages (RPM only).

   -  `dnsmasq`: Build dnsmasq packages.

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

-  Ubuntu 20.04 (Focal) and 22.04 (Jammy). The hosting for these
   packages is in PPAs at https://launchpad.net/~project-calico.

-  CentOS 7 or RHEL 7.  The hosting for these packages is in RPM repos
   at binaries.projectcalico.org (for example
   http://binaries.projectcalico.org/rpm/calico-3.8/).

## Debian source packages and versioning

Our Debian source packages are `3.0 (quilt)` format: a `.orig` tarball holding
the upstream content, plus a small `.debian` tarball holding `debian/`.  The
`.orig` tarball is not a real upstream release; `make-packages.sh` generates it
from the working tree, once per build, just before building the per-series
source packages.

Each Ubuntu series needs its own package version, because Launchpad will not
accept a second upload of a version that the archive already holds.  The series
therefore goes in the *Debian revision*, giving versions like
`3:3.34.0~rc0.post5329-noble`, and leaving the upstream version -- and so the
name of the `.orig` tarball -- the same for all three series.

That split matters for the PPA size quota.  Launchpad charges the quota for
every file it still holds, including superseded ones it has not yet garbage
collected, and it counts a given filename only once.  One `.orig` tarball
shared by three series therefore costs a third of what three per-series copies
of it cost, which for Felix is the difference between 56MiB and 168MiB on every
snapshot build.  Before this scheme the series was part of the upstream
version, so each series got its own near-identical copy, and the `master` PPA
regularly exceeded its 8GiB quota and started rejecting uploads.

Two ordering properties are deliberate, and worth preserving if you change the
scheme:

-  A newer Ubuntu series sorts above an older one, because `focal` < `jammy` <
   `noble` alphabetically.

-  There is no `~` in the revision.  `~` sorts *before* the thing it is
   attached to, which once made a release package compare as older than the
   pre-release it was meant to replace; see commit 1499c035ee.

## Public PPAs and RPM repositories

There is a PPA and RPM repo, named `calico-X.Y`, for each Calico X.Y
release series.  Packages are updated through the cycle for an X.Y
series (X.Y.0, X.Y.1 etc.), so the repo always provides our latest
packages for that series.

There is also a PPA and RPM repo named `master`, with packages that
are built every night from our latest development code.

## Packaged components

The components that we package and host are:

-  networking-calico - for all platforms.

-  Felix - for all platforms.

-  calicoctl - for all platforms.  This packages the same standalone
   CLI binary that is also published on the GitHub release page, as a
   convenience for hosts that are already installing Calico from these
   repositories.

-  etcd3gw - for CentOS/RHEL 7 only.

   Note: for Ubuntu there is no packaging for etcd3gw, and we instead
   [document](https://docs.projectcalico.org/master/getting-started/openstack/installation/ubuntu)
   that the installer must do `pip install etcd3gw`.

-  dnsmasq - see below.

For OpenStack and bare metal installs we don't currently need any
other Calico components.

## Dnsmasq

We have contributed various patches to Dnsmasq since 2014; all of
these have been accepted
[upstream](http://www.thekelleys.org.uk/dnsmasq/doc.html).  The
timeline of those patches and how they interleave with Dnsmasq
releases is as follows.

-  v2.71
-  2014-06-11 Allow wildcard aliases in --bridge-interface option
-  v2.72
-  2015-03-19 DHCPv4 with --bridge-interface broken by 3rd party - but
   not realized by us until a year later
-  2015-06-10 Fix logging of unknown interface in
   --bridge-interface...
-  2015-06-10 Extend --bridge-interface aliasing to DHCPv6.
-  2015-06-10 Allow router advertisements to have the "off-link"...
-  2015-06-10 Apply --bridge-interface aliasing to solicited router...
-  2015-06-10 Apply --bridge-interfaces to unsolicited router
   advertisements.
-  2015-06-10 Documentation updates for --bridge-interface and "off...
-  v2.73
-  v2.74
-  v2.75
-  2016-05-03 Fix for DHCP in transmission interface when --bridge...
-  v2.76
-  v2.77
-  2017-09-26 CVE-2017-1449[123456] (see also
   https://github.com/projectcalico/calico/issues/1169)
-  v2.78
-  2018-01-18 Remove limit of 67 on the number of VMs per compute node
-  v2.79

To get all of these patches requires Dnsmasq v2.79 or later.  Our Ubuntu
platforms have that, but not CentOS/RHEL 7, so for CentOS/RHEL we build
and host v2.79 packages ourselves.  The source for that comes from the
following tags in [our Dnsmasq
fork](https://github.com/projectcalico/calico-dnsmasq).

-  For CentOS/RHEL 7, `rpm_2.79`.
