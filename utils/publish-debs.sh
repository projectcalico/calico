#!/bin/bash -ex

REPO_NAME=${REPO_NAME:-master}
test -n "$SECRET_KEY"

keydir=`mktemp -t -d calico-publish-debs.XXXXXX`
cp -a $SECRET_KEY ${keydir}/key

docker run --rm -v `pwd`:/code -v ${keydir}:/keydir calico-build/bionic /bin/sh -c "gpg --import < /keydir/key && debsign -kCalico networking-calico_*_source.changes"
for series in trusty xenial bionic; do
    docker run --rm -v `pwd`:/code calico-build/${series} /bin/sh -c "dput -u ppa:project-calico/${REPO_NAME} /code/networking-calico_*${series}_source.changes"
done
