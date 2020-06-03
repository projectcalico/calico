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

# build builds a branch $1 into the dir _site/$2. If $2 is not provided, the
# branch is built into _site/
function build() {
    echo "[DEBUG] building branch $1 into dir $2"
    TEMP_DIR=$(mktemp -d)

    git clone --depth=1 https://github.com/projectcalico/calico -b $1 $TEMP_DIR

    pushd $TEMP_DIR
    jekyll build --config $JEKYLL_CONFIG,$EXTRA_CONFIG --baseurl=$2 --destination _site/$2
    popd

    rsync -r $TEMP_DIR/_site .
}

# build_master builds skip the git clone and build the site in the current tree
function build_master() {
    jekyll build --config $JEKYLL_CONFIG --baseurl /master --destination _site/master
}

# build_archives builds the archives. The release-legacy branch is special
# and is built into _site directly (the legacy docs were a version per dir).
# Newer archive versions are built into its own directory for that version.
function build_archives() {
    (echo "$CURRENT_RELEASE" && grep -oP '^- \K(.*)' _data/archives.yml) | while read branch; do
        EXTRA_CONFIG=$EXTRA_CONFIG,$(pwd)/netlify/_config_noindex.yml
        if [[ "$branch" == legacy* ]]; then
            if [ -z "$CUSTOM_ARCHIVE_PATH" ]; then
                build release-legacy
            else
                build release-legacy $CUSTOM_ARCHIVE_PATH
                EXTRA_CONFIG=$EXTRA_CONFIG,$(pwd)/netlify/_manifests_only.yml build release-legacy /
            fi
        else
            if [ -z "$CUSTOM_ARCHIVE_PATH" ]; then
                build release-${branch} /${branch}
            else
                build release-${branch} $CUSTOM_ARCHIVE_PATH/${branch}
                EXTRA_CONFIG=$EXTRA_CONFIG,$(pwd)/netlify/_manifests_only.yml build release-${branch} /${branch}
            fi
        fi
    done
}

echo "[INFO] building master site"
build_master

echo "[INFO] building archives"
build_archives
mv _site/sitemap.xml _site/release-legacy-sitemap.xml

echo "[INFO] building current release"
EXTRA_CONFIG=$(pwd)/netlify/_config_latest.yml build release-$CURRENT_RELEASE
mv _site/sitemap.xml _site/latest-sitemap.xml

if [ ! -z "$CANDIDATE_RELEASE" ]; then
    echo "[INFO] building candidate release"
    build release-$CANDIDATE_RELEASE /$CANDIDATE_RELEASE
fi

mv netlify/sitemap-index.xml _site/sitemap.xml
mv netlify/_redirects _site/_redirects
