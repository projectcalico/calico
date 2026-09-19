
# Calico packaging

This repo automates and documents every step needed to build and
publish Calico packages, for use [with
OpenStack](https://docs.projectcalico.org/master/getting-started/openstack/installation/)
or [on bare metal
hosts](https://docs.projectcalico.org/master/getting-started/bare-metal/installation/).

    make build

builds a set of packages corresponding to current Calico master code, into
`output/`, and

    make publish

uploads them to our PPA and RPM repo named "master".  `VERSION=vX.Y.Z` builds
and publishes for version X.Y.Z instead, to the PPA and RPM repo named
"calico-X.Y".

This file documents how to run the pipeline, what we package, and why.  The
design - the target graph, the invariants, and the reasoning - is in
[`DESIGN.md`](DESIGN.md).

## Usage

Build, publish and test are independent phases.  Run them together or one at a
time; nothing is rebuilt that is already built, and nothing is uploaded that is
already uploaded, so a failed run can simply be repeated.

    make images                  # the per-platform build containers
    make build                   # deb source packages and RPMs, into output/
    make build-binaries          # binary .debs, for local install and testing
    make test                    # install what we built, in clean containers
    make publish                 # upload everything
    make clean                   # remove output/

    make print-config            # what VERSION resolves to, before doing anything
    make help                    # every target

Finer-grained targets exist for everything: `build-ubuntu`, `build-rhel`,
`build-ubuntu-felix`, `build-binaries-noble`, `test-ubuntu-jammy`,
`publish-ubuntu`, `publish-rhel-gar`, `publish-rhel-bpo`, and so on.

`make release` and `make release-publish` are kept for CI compatibility: they
clean first and then do the same work, which is what the shell script this
replaced always did.

### Tools you need

Building needs `docker`, `rsync`, `dch` (from `devscripts`) and `patchelf`.
Publishing RPMs additionally needs `gcloud`, `jq` and `rpm`.  Each target
checks for what it uses and names anything missing.

### Publishing

Publishing to the PPA needs a signing key for a member of the [Project Calico
team on Launchpad](https://launchpad.net/~project-calico), as either:

-  `SECRET_KEY_ID` - a key id, fingerprint or uid in your own GnuPG keyring.
   The key is exported into a private temporary directory for the duration of
   one upload and deleted afterwards.  If the key has a passphrase, gpg-agent
   prompts for it; set `SECRET_KEY_PASSPHRASE_FILE` for unattended use.

-  `SECRET_KEY` - a path to a key file.  This wins if both are set, which is
   how CI still works unchanged.

Publishing RPMs needs `HOST` and `GCLOUD_ARGS` to point at the RPM host and a
GCP identity that can log into it.  Both now default to the real values, so a
local run needs no setup.

Uploading Debian *source* packages to Launchpad is not the end of the story:
Launchpad then builds and publishes the binary packages itself, usually in about
an hour, occasionally many hours.  A package is only really ready for use when
its line on the PPA package details page ([for
example](https://launchpad.net/~project-calico/+archive/ubuntu/master/+packages))
has a green tick in the Build Status column and a date in the Published column.
`make build-binaries` exists so that you do not have to wait for that to find
out whether a source package builds at all.

(RPMs, on the other hand, are ready as soon as `make publish-rhel` finishes.)

### Configuration

Everything is overridable on the command line or from the environment; see
[`mk/config.mk`](mk/config.mk) for the full list and the defaults.  The ones
worth knowing:

-  `VERSION`: the Calico version to build packages for.  Default `master`.

-  `REPO_NAME`, `GCLOUD_REPO_NAME`: the PPA/RPM repo and Google Artifact
   Registry repo to publish to.  Both are derived from `VERSION`.

-  `UBUNTU_SERIES`, `EL_VERSIONS`: which platforms to build for.

-  `FORCE_VERSION`, `DEB_VERSION`, `RPM_VERSION`: override the version that
   would otherwise come from git state.

### The calico-felix binary in these packages

The `calico-felix` we package is **not** `felix/bin/calico-felix`. It is built
separately, by [`mk/felix-el8.mk`](mk/felix-el8.mk), inside the EL 8 build
container, and lands in `output/felix-el8/bin/calico-felix`.

The reason is glibc. `calico/go-build` is AlmaLinux 9 based, so a binary from it
needs `GLIBC_2.34` and will not run on EL 8 (2.28) or Ubuntu 20.04 (2.31) - the
RPM's generated `Requires: libc.so.6(GLIBC_2.34)` cannot even be satisfied.
Building in the oldest distribution we package for gives one binary that runs on
all of them:

| built in | glibc floor | runs on |
|---|---|---|
| calico/go-build (AlmaLinux 9) | 2.34 | jammy, noble, EL 9+ |
| this pipeline's el8 image | 2.28 | focal, jammy, noble, EL 8+ |

So `libbpf.a` and the cgo binary are rebuilt in the el8 image, exactly as
calico-private does for calico-node's RHEL 8 RPM (`node/Makefile.rhel8`). The BPF
programs are clang-built kernel bytecode and are unaffected, so they still come
from felix's normal `make build-bpf`.

`make felix-binary` builds just that binary, if you want to inspect it:

    make felix-binary
    objdump -T output/felix-el8/bin/calico-felix | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -1

Delete `mk/felix-el8.mk` and its `include` line once every platform we package
for has a glibc at least as new as go-build's.

### Iterating locally

`output/` is the state: a target whose file is already there does not run
again.  So after a failed publish, `make publish` picks up where it stopped,
and after changing one component, `make build-ubuntu-felix` rebuilds only that.

The one thing to know is that the shipped binaries -
`output/felix-el8/bin/calico-felix` and `calicoctl/bin/calicoctl` - are built once
per `output/` tree, and recorded by a stamp under `output/.stamps/`.  If you
change a component's source and want the packages to pick it up, remove its stamp
(or run `make clean`).

## Packaging platforms

We build and publish packages for these platforms:

-  Ubuntu 20.04 (Focal), 22.04 (Jammy) and 24.04 (Noble). The hosting
   for these packages is in PPAs at https://launchpad.net/~project-calico.

-  RHEL 8 and its rebuilds (AlmaLinux, Rocky, CentOS Stream 8).  The
   hosting for these packages is in RPM repos at
   binaries.projectcalico.org (for example
   http://binaries.projectcalico.org/rpm/calico-3.8/), and in a Google
   Artifact Registry yum repo.

   EL 8 is the floor rather than a target: it is the oldest EL we build
   for, so the binaries we build there run on EL 9 and later too.  RPMs
   for CentOS/RHEL 7 are no longer built - EL 7 is EOL, and its glibc
   2.17 could not run our `calico-felix` binary even before that.

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

Two components used to be packaged here and no longer are, both because
they existed only for CentOS/RHEL 7:

-  etcd3gw.  Its spec built Python 2 packages, which EL 8 cannot.  As for
   Ubuntu, which never had etcd3gw packaging, we
   [document](https://docs.projectcalico.org/master/getting-started/openstack/installation/ubuntu)
   that the installer must do `pip install etcd3gw`.

-  dnsmasq.  We built it only because CentOS 7 was stuck on 2.76 and our
   patches need 2.79; EL 8 ships 2.79 itself.  See below for the history,
   which is still worth keeping.

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

To get all of these patches requires Dnsmasq v2.79 or later.  Every platform we
now package for has that: our Ubuntu series all do, and EL 8 ships 2.79.  Only
CentOS/RHEL 7, stuck on 2.76, did not - which is why we used to build and host
v2.79 ourselves, from the `rpm_2.79` branch of [our Dnsmasq
fork](https://github.com/projectcalico/calico-dnsmasq).

We therefore no longer build it, and the component is gone from
[`mk/components.mk`](mk/components.mk) - which keeps a comment saying so, and
where the fork is, in case a platform ever regresses below 2.79.
