#!/bin/bash
set -e

# this script is used by Netlify to construct docs.projectcalico.org
# to do this, it builds several different sites:
# - latest
# - master
# - legacy-release
# - each archive release

if [ -z "$CURRENT_RELEASE" ]; then
    echo "must set \$CURRENT_RELEASE"
    exit 1
fi

if [ -z "$(which jekyll)" ]; then
    gem install github-pages
fi

if [ -z "$(which helm)" ]; then
    make bin/helm
    export PATH=$PATH:$(pwd)/bin
fi

DESTINATION=$(pwd)/_site

# If this is a deploy-preview, correctly set the URL to the generated Netlify subdomain
JEKYLL_CONFIG=_config.yml
if [ "$CONTEXT" == "deploy-preview" ]; then
    echo "url: $DEPLOY_PRIME_URL" >_config_url.yml
    JEKYLL_CONFIG=$JEKYLL_CONFIG,$(pwd)/_config_url.yml
fi

function build() {
    echo "[DEBUG] building branch $1 into dir $2"
    TEMP_DIR=$(mktemp -d)

    git clone --depth=1 https://github.com/projectcalico/calico -b $1 $TEMP_DIR

    pushd $TEMP_DIR
    jekyll build --config $JEKYLL_CONFIG --baseurl=$2 --destination _site/$2
    popd

    rsync -r $TEMP_DIR/_site .
}

# master builds skip the git clone and build the site in the current tree
function build_master() {
    echo "archive: true" >_config_jekyll.yml
    jekyll build --config $JEKYLL_CONFIG,$(pwd)/_config_jekyll.yml --baseurl /master --destination _site/master
}

function build_archives() {
    grep -oP '^- \K(.*)' _data/archives.yml | xargs -I _ echo release-_ | while read branch; do
        if [[ "$branch" == release-legacy*  ]]; then
            branch="release-legacy"
        fi
        build $branch
    done
}

echo "[INFO] building master site"
build_master

echo "[INFO] building archives"
build_archives
