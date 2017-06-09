#!/bin/bash
k8s_ver="v1.6.2"

if [ ! -d /k8s ]; then
  mkdir /k8s
  # fetch_k8s_binaries.sh downloads to a subdirectory k8s so cd to the the
  # parent directory
  cd /
  /opt/k8s/setup/fetch_k8s_binaries.sh $@
fi

mkdir -p /opt/bin

for x in $@; do
  binary=$x
  ver_binary=${binary}-$k8s_ver
  if [ ! -f /k8s/${ver_binary}.downloaded ]; then
    echo "ERROR: $binary version $k8s_ver was not downloaded"
    exit 1
  fi
  cp /k8s/${ver_binary} /opt/bin/$binary
  /usr/bin/chmod +x /opt/bin/$binary
done
