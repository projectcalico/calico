#!/bin/bash

out_file=semaphore.yml
echo "# !! WARNING, DO NOT EDIT !! This file is generated from semaphore.yml.tpl." >$out_file
echo "# To update, modify the template and then run 'make gen-semaphore-yaml'." >>$out_file

cat semaphore.yml.d/01-preamble.yml >>$out_file
cat semaphore.yml.d/02-global_job_config.yml >>$out_file
cat semaphore.yml.d/03-promotions.yml >>$out_file

echo "blocks:" >>$out_file
cat semaphore.yml.d/blocks/*.yml >>$out_file

sed -i "s/\${FORCE_RUN}/false/g" semaphore.yml
