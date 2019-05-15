# Release process

There are two main steps to complete:

- [Tagging a release](#tagging-a-release)
- [Releasing debs and rpms](#releasing-debs-and-rpms)

## Tagging a release

Prerequisite: You must be [signed up as an OpenStack
developer](https://docs.openstack.org/infra/manual/developers.html#account-setup)
and a member of the [`networking-calico-release` group on
Gerrit](https://review.opendev.org/#/admin/groups/1015,members).

1. Decide the new version number for the release.  Usually this is the
   same as the wider Calico release.

1. Create a signed `<version>` tag on the release commit (without any leading
   `v`; for example `1.4.3`), with content `networking-calico <version>
   release`, and push this to the gerrit remote.

## Releasing debs and rpms

1. Get (or update to) the latest code from
   https://github.com/projectcalico/packaging, in `<packaging_dir>`.

1. In `<packaging_dir>`, run `make deb rpm` to build RPMs and Debian
   packages.

1. In `<packaging_dir>`, run `utils/publish-rpms.sh` to publish the
   RPMs.  (Note: This requires credentials for accessing
   binaries.projectcalico.org.)

1. In `<packaging_dir>`, use `debsign` to sign the Debian source
   packages (`networking-calico_*_source.changes`) and `dput` to
   upload those to [the right Project Calico PPA on
   Launchpad](https://launchpad.net/~project-calico):

   ```
   debsign -k<your key ID> networking-calico_*_source.changes
   dput ppa:project-calico/calico-X.Y networking-calico_*_source.changes
   ```

   (Note: This requires being a member of the Project Calico group on
   Launchpad and signing with a GPG key that has been uploaded to your
   profile.)

   It can take a long time for Launchpad to build and publish binary
   packages. Usually about an hour, but occasionally many hours.

   The PPA is only ready for use when the PPA package details page
   shows all green ticks in its Build Status column.
