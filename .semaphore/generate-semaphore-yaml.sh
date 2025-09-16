#!/bin/bash

set -e
set -o pipefail

# Check that all change_in clauses ignore the pipeline file.  We now regenerate the
# pipeline file often, so any jobs that need this should depend on it explicitly.
if find semaphore.yml.d/ -name '*.yml' -print0 | xargs -0 grep change_in | grep -v pipeline_file; then
  echo
  echo "ERROR: All change_in clauses must include the \"pipeline_file: 'ignore'\""
  echo "option to prevent unnecessary job runs when the pipeline file is updated."
  echo "Or, if you really want a job to run when the pipeline file changes, add"
  echo "\"pipeline_file: 'track'\"."
  echo
  exit 1
fi

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
    sed -i "s&\${CHANGE_IN($dep)}&true&g" semaphore-scheduled-builds.yml
  done

pushd ..
go run ./hack/cmd/deps replace-sem-change-in ./.semaphore/semaphore.yml
popd

sed -i "s/\${FORCE_RUN}/false/g" semaphore.yml
sed -i "s/\${FORCE_RUN}/true/g" semaphore-scheduled-builds.yml
