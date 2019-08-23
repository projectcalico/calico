#!/bin/bash -ex

REPO_NAME=${REPO_NAME:-master}
test -n "$SECRET_KEY"

keydir=`mktemp -t -d calico-publish-debs.XXXXXX`
cp -a $SECRET_KEY ${keydir}/key

docker run --rm -v `pwd`:/code -v ${keydir}:/keydir calico-build/bionic /bin/sh -c "gpg --import < /keydir/key && debsign -kCalico *_*_source.changes"
for series in trusty xenial bionic; do
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
	${already_exists} || docker run --rm -v `pwd`:/code -w /code calico-build/${series} dput -u ppa:project-calico/${REPO_NAME} ${changes_file}
    done
done
