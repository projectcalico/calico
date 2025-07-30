#!/bin/bash

set -e

images=(
    operator
    calico-node
    calico-typha
    calico-apiserver
    calicoctl
    calico-cni
    csi
    node-driver-registrar
    pod2daemon
    kube-controllers
    goldmane
    whisker
    whisker-backend
)

for image in "${images[@]}"; do
    echo "Loading image: ${image}"
    ${KIND} load image-archive "./${image}.tar" || {
        echo "Failed to load image: ${image}"
        exit 1
    }
done
echo "All images loaded successfully."