#!/bin/bash

set -e
set -o pipefail

for out_file in semaphore.yml semaphore-scheduled-builds.yml; do
  echo "# !! WARNING, DO NOT EDIT !! This file is generated from semaphore.yml.tpl." >$out_file
  echo "# To update, modify the template and then run 'make gen-semaphore-yaml'." >>$out_file

  cat semaphore.yml.d/01-preamble.yml >>$out_file
  cat semaphore.yml.d/02-global_job_config.yml >>$out_file
  cat semaphore.yml.d/03-promotions.yml >>$out_file

  # use sed to properly indent blocks
  echo "blocks:" >>$out_file

  ls semaphore.yml.d/blocks/*.yml | sort | xargs cat | sed -e 's/^./  &/' >>$out_file

  cat semaphore.yml.d/99-after_pipeline.yml >>$out_file
done

grep -o --perl '\$\{CHANGE_IN\(\K[^)]+' --no-filename semaphore.yml | \
  sort --reverse -u | \
  while read -r dep; do
    sed -i "s&\${CHANGE_IN($dep)}&$(cd .. && go run ./hack/cmd/deps sem-change-in $dep)&g" semaphore.yml
    sed -i "s&\${CHANGE_IN($dep)}&true&g" semaphore-scheduled-builds.yml
  done

sed -i "s/\${FORCE_RUN}/false/g" semaphore.yml
sed -i "s/\${FORCE_RUN}/true/g" semaphore-scheduled-builds.yml
