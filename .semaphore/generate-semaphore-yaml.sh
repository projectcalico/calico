#!/usr/bin/env bash

cp semaphore.yml.tpl semaphore.yml
cp semaphore.yml.tpl semaphore-scheduled-builds.yml

sed -i "s/\${FORCE_RUN}/false/g" semaphore.yml
sed -i "s/\${FORCE_RUN}/true/g" semaphore-scheduled-builds.yml