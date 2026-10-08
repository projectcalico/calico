#!/bin/bash -e

# Build Debian and RPM packages for the current Git HEAD.
#
# Usage: make-packages.sh [deb] [rpm]

# Get the location of this script.  Other scripts that we use must be in the
# same location.
scriptdir=$(dirname "$(realpath "$0")")

# Get the location of the rpm builder script.
rpmDir=$(dirname "$scriptdir")/rpm

# Include function library.
. ${scriptdir}/lib.sh

# Get the version based on Git state, and the Git commit ID.
version=${FORCE_VERSION:-$(git_auto_version)}
version=$(strip_v ${version})
sha=$(git_commit_id)

# Timestamp of the current Git commit.  Used below in place of the current
# time, so that building the same commit twice produces the same .orig tarball.
source_date_epoch=$(git log -1 --format=%ct)

DOCKER_RUN_RM="docker run --rm --user $(id -u):$(id -g) -v $rpmDir:/rpm -v $(dirname "$(pwd)"):/code -w /code/$(basename "$(pwd)")"

# Determine if this is a release (i.e. corresponds exactly to a Git tag) or a
# snapshot.
release=true
case ${version} in
    *.post* )
    release=false
    ;;
esac

if [ "${PKG_NAME}" = networking-calico ]; then
    sed -i "s/version=\"0.0.0\"/version=\"${version}\"/" setup.py
fi

# Build the requested package types.
for package_type in "$@"; do

    case ${package_type} in

    deb )
        if [ "${PKG_NAME}" = felix ]; then
            # Felix is built with RHEL/UBI and links against libpcap.so.1. We need this patchelf
            # until Debian changes the soname from .0.8 to .1.
            # FIXME remove the following patchelf command once Debian dependency is updated.
            patchelf --replace-needed libpcap.so.1 libpcap.so.0.8 bin/calico-felix
        fi

        # The Debian version that we are about to generate.  Note that this
        # is the *upstream* version only; the Ubuntu series goes into the
        # Debian revision, below.
        debver=${FORCE_VERSION_DEB:-$(git_version_to_deb "${version}")}
        debver=$(strip_v "${debver}")

        excludes="${DPKG_EXCL:--I}"

        # Our packages are "3.0 (quilt)" format, so each source package is a
        # shared .orig tarball plus a small per-series .debian tarball.  That
        # matters because Launchpad charges a PPA's size quota for every file
        # it is still holding, including superseded ones that it has not yet
        # garbage collected, and it de-duplicates by filename: one .orig
        # tarball that all three series reference costs a third of what three
        # near-identical per-series copies of it cost.
        #
        # Build that .orig tarball here, once, from the same working tree that
        # the per-series builds below package up.  It must be byte-for-byte
        # reproducible, so that re-running this job for a version that is
        # already partly published regenerates an identical file, rather than
        # one that Launchpad would reject as a conflicting upload of a file it
        # already has.  --sort, --mtime and the ownership options take care of
        # the tar metadata.  The content is reproducible because nothing that
        # goes into it records the time of the build: the RPM changelog stanza
        # below is dated from the commit, and create-update-packages.sh builds
        # the binaries that we ship with DATE set from the commit as well.
        pkg_dir=$(basename "$(pwd)")
        orig_tarball=../${PKG_NAME}_${debver}.orig.tar.xz
        mapfile -t tar_excludes < <(deb_tar_excludes "${excludes}")
        rm -f "${orig_tarball}"

        # The debian/ exclusion is anchored, so that it drops this package's
        # own debian/ directory and not, say, felix's vendored
        # bpf-gpl/libbpf/.github/actions/debian/.
        tar --create --xz --file "${orig_tarball}" \
            --anchored --exclude="${pkg_dir}/debian" --no-anchored \
            "${tar_excludes[@]}" \
            --sort=name --mtime="@${source_date_epoch}" \
            --owner=0 --group=0 --numeric-owner \
            --transform "s,^${pkg_dir},${PKG_NAME}-${debver}," \
            -C .. "${pkg_dir}"

        for series in focal jammy noble; do
            if ${release}; then
                changelog_message="${NAME} v${debver} (from Git commit ${sha})."
            else
                changelog_message="Development snapshot (from Git commit ${sha})."
            fi

            # Each series needs its own version, because Launchpad will not
            # accept a second upload of a version that the archive already
            # has.  The series therefore goes in the Debian revision, where
            # it leaves the upstream version -- and hence the name of the
            # .orig tarball -- the same for all three series.  Previously it
            # was part of the upstream version, which is what forced us to
            # ship three separate copies of that tarball.
            #
            # Two ordering properties still hold.  A newer Ubuntu series
            # sorts above an older one, because focal < jammy < noble
            # alphabetically -- that is what 1499c035ee was protecting.  And
            # there is deliberately no "~" anywhere in the revision, because
            # "~" sorts *before* the thing it is attached to, which is the
            # trap that 1499c035ee was fixing.
            rm -f debian/changelog debian/changelog.dch
            dch --controlmaint --create --package "${PKG_NAME}" -v "${DEB_EPOCH}${debver}-${series}" "${changelog_message}"
            dch --controlmaint --release --distribution $series ""

            # -sa includes the .orig tarball in every series' upload.  The
            # tempting alternative, uploading it with the first series only
            # and using -sd for the rest, does not work here: Launchpad can
            # only find an already-held .orig via a publication record for it
            # (Archive.getFileByName), and it has not finished processing the
            # first upload by the time we send the second.  The rest would be
            # rejected with "Unable to find ... in upload or distribution".
            #
            # Uploading it three times costs nothing against the PPA's size
            # quota, which is what we are actually trying to reduce.  The
            # quota sums DISTINCT (filename, sha1, filesize) over the files
            # the archive still holds (Archive.sources_size), so three
            # uploads of one identical, identically-named tarball are counted
            # once -- whereas the three differently-named tarballs that the
            # old per-series upstream version produced were counted three
            # times.  It costs no extra upload bandwidth either, since we
            # were already sending three copies of a tarball this size.
            ${DOCKER_RUN_RM} calico-build/${series} dpkg-buildpackage ${excludes} -sa -S -d | ts "[build $series]"
        done

        cat <<-EOF

    +---------------------------------------------------------------------------+
    | Debs have been built.                                                     |
    +---------------------------------------------------------------------------+

EOF
        ;;

    rpm )
        rpm_spec=rpm/${PKG_NAME}.spec
        if [ -f ${rpm_spec}.in ]; then
        debver=${FORCE_VERSION_RPM:-$(git_version_to_rpm "${version}")}
        debver=$(strip_v "${debver}")
        cp -f "${rpm_spec}.in" "${rpm_spec}"

        # Generate RPM version and release.
        IFS=_ read ver qual <<< "${debver}"
        if test "${qual}"; then
            rpmver=${ver}
            rpmrel=0.1.${qual}
        else
            rpmver=${ver}
            rpmrel=1
        fi

        # Update the Version: and Release: lines.
        sed -i "s/^Version:.*$/Version:        ${rpmver#*:}/" "${rpm_spec}"
        sed -i "s/^Release:.*$/Release:        ${rpmrel}%{?dist}/" "${rpm_spec}"

        # Add a stanza to the %changelog section.  Date it from the commit
        # rather than the current time: the generated spec ends up in the
        # Debian .orig tarball too, which must be reproducible.  For the same
        # reason, render it in UTC and the C locale, so that the result does
        # not depend on the build host's timezone or language settings.
        timestamp=$(LC_ALL=C date -u -d "@${source_date_epoch}" "+%a %b %d %Y")
        {
            cat <<EOF
* ${timestamp} Daniel Fox<dan.fox@tigera.io> ${rpmver}-${rpmrel}
EOF
            if ${release}; then
            cat <<EOF
  - ${NAME} v${version} (from Git commit ${sha}).
EOF
            else
            cat <<EOF
  - Development snapshot (from Git commit ${sha}).
EOF
            fi
            echo

        } | sed -i '/^%changelog/ r /dev/stdin' "${rpm_spec}"
        fi

        elversions=7
        for elversion in ${elversions}; do
        # Skip the rpm build if we are missing the matching build image.
        imageid=$(docker images -q "calico-build/centos${elversion}:latest")
        [ -n "$imageid" ] && ${DOCKER_RUN_RM} -e "EL_VERSION=el${elversion}" \
            -e FORCE_VERSION="${FORCE_VERSION}" \
            -e RPM_TAR_ARGS="${RPM_TAR_ARGS}" \
            "$imageid" /rpm/build-rpms
        done

        cat <<-EOF
    +---------------------------------------------------------------------------+
    | RPMs have been built at dist/rpms.                                        |
    +---------------------------------------------------------------------------+

EOF
        ;;

    * )
        echo "ERROR: unknown package type \"${package_type}\""
        exit 255
        ;;

    esac

done
