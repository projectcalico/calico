#!/bin/bash

# Prerequisites to run this script:
# 1. Build e2e.test binary by running: make build
# 2. Create aws-kubeadm cluster with 3 worker nodes and with same subnet and dual stack
# 3. Copy over external_ip and external_key files from banzai .local directory
# 4. Copy kubeconfig from banzai .local directory to $HOME/.kube/config

export PRODUCT="calico"
export K8S_VERSION='stable-1.31'
export RELEASE_STREAM='v3.21'
export PROVISIONER='aws-kubeadm'
export INSTALLER='operator'
export DATAPLANE="CalicoBPF"
export EXT_USER="ubuntu"
export EXT_KEY=./external_key
export EXT_IP=$(cat ./external_ip)

./bin/k8s/e2e.test \
        --kubeconfig=$HOME/.kube/config \
        --ginkgo.focus="Maglev" \
        -ginkgo.v | tee result.log
