#!/usr/bin/env bash

for out_file in semaphore.yml semaphore-scheduled-builds.yml; do
  echo "# !! WARNING, DO NOT EDIT !! This file is generated from semaphore.yml.tpl." > $out_file
  echo "# To update, modify the template and then run 'make gen-semaphore-yaml'." >> $out_file
  cat semaphore.yml.tpl >> $out_file
done

sed -i "s/\${FORCE_RUN}/false/g" semaphore.yml
sed -i "s/\${FORCE_RUN}/true/g" semaphore-scheduled-builds.yml
