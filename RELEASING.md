# Release process

networking-calico is released by creating a signed tag and pushing
that tag to the Gerrit remote.  This tags the current code and
triggers a release to PyPI.

## Prerequisites

You must be [signed up as an OpenStack
developer](https://docs.openstack.org/infra/manual/developers.html#account-setup)
and a member of the [`networking-calico-release` group on
Gerrit](https://review.opendev.org/#/admin/groups/1015,members).

## Tagging a release

1. Decide the version number for the release.  Usually this is the
   same as the wider Calico release.

1. Create a signed `<version>` tag on the release commit (without any leading
   `v`; for example `3.8.2`), with content `networking-calico <version>
   release`, and push this to the gerrit remote.

# Debian and RPM packages

For the preparation of Debian and RPM packages, see
https://github.com/projectcalico/packaging.

(Tigera builds and publishes packages for each Calico release as a
whole, once all the Calico components have been released.)
