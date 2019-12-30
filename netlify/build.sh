#!/bin/bash
set -e

# netlify does not have docker installed, so we will install dependencies using bundle and
# execute the build ourselves.

# install helm and set $PATH to pick it up
export PATH=$PATH:/opt/build/repo/bin
make bin/helm

bundle install --gemfile ./netlify/Gemfile

JEKYLL_CONFIG=_config.yml
if [ "$CONTEXT" == "deploy-preview" ]; then
    echo "url: $DEPLOY_PRIME_URL" >_config_url.yml
    JEKYLL_CONFIG=$JEKYLL_CONFIG,_config_url.yml
fi

# deploy preview only
bundle exec --gemfile ./netlify/Gemfile \
  jekyll build --config $JEKYLL_CONFIG
