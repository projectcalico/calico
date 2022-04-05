#!/bin/bash -ex

REPO_NAME=${REPO_NAME:-master}
test -n "$SECRET_KEY"

rootdir=`git rev-parse --show-toplevel`
keydir=`mktemp -t -d calico-publish-debs.XXXXXX`
cp -a $SECRET_KEY ${keydir}/key

# Sign all source packages.
if [ -t 0 ]; then
    # STDIN is a terminal, so whoever is running this code can provide a pass phrase for
    # their GPG key.  Pass STDIN through to the Docker container, to enable that.
    interactive=-ti
else
    # STDIN is not a terminal - probably we're running in our CI system.  We mustn't pass
    # -ti to docker-run, and $SECRET_KEY must not require a pass phrase.
    interactive=
fi
docker run --rm ${interactive} -v ${rootdir}:/code -v ${keydir}:/keydir -w /code/hack/release/packaging/output calico-build/bionic /bin/sh -c "gpg --import --batch < /keydir/key && debsign -k'*@' *_*_source.changes"

for series in trusty xenial bionic focal; do
    # Get the packages and versions that already exist in the PPA, so we can avoid
    # uploading the same package and version as already exist.  (As they would be rejected
    # anyway by Launchpad.)
    sources_url="http://ppa.launchpad.net/project-calico/${REPO_NAME}/ubuntu/dists/${series}/main/source/Sources.gz"
    existing_packages=$(wget -q -O - ${sources_url} | gzip -d | awk '/^Package:/{printf("%s_", $2);} /^Version:/{sub(/^1:/,"", $2); print $2;}')
    echo "Existing source packages for ${series} in project-calico/${REPO_NAME} are:"
    echo "${existing_packages}"

    # Use the Distribution header to map changes files to Ubuntu versions, as some of our
    # packages don't include the Ubuntu version name in the changes file name.
    for changes_file in `grep -l "Distribution: ${series}" *_source.changes`; do
        already_exists=false
        for existing in ${existing_packages}; do
            if [ ${changes_file} = ${existing}_source.changes ]; then
                already_exists=true
                break
            fi
        done
        ${already_exists} || docker run --rm -v ${rootdir}:/code -w /code calico-build/${series} dput -u ppa:project-calico/${REPO_NAME} ${changes_file}
    done
done
