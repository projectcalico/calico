#!/bin/bash
k8s_ver="v1.6.2"

if [ $# -eq 0 ]; then
    binaries="kubectl kube-apiserver kube-controller-manager kubelet kube-proxy kube-scheduler"
else
    binaries="$@"
fi

mkdir -p k8s

for x in $binaries; do
  ver_binary=${x}-$k8s_ver
  if [ ! -f k8s/${ver_binary}.downloaded ]; then
    /usr/bin/wget -O k8s/${ver_binary} https://storage.googleapis.com/kubernetes-release/release/$k8s_ver/bin/linux/amd64/$x
    if [ $? -eq 0 ]; then
      touch k8s/${ver_binary}.downloaded
    fi
  else
    echo "$x ($k8s_ver) already downloaded"
  fi
done
