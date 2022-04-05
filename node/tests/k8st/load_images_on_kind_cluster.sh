#!/bin/bash

function load_image() {
    local node=$1
    docker cp ./calico-node.tar ${node}:/calico-node.tar
    docker cp ./calico-apiserver.tar ${node}:/calico-apiserver.tar
    docker cp ./calicoctl.tar ${node}:/calicoctl.tar
    docker cp ./calico-cni.tar ${node}:/calico-cni.tar
    docker cp ./pod2daemon.tar ${node}:/pod2daemon.tar
    docker cp ./kube-controllers.tar ${node}:/kube-controllers.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calico-node.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calico-apiserver.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calicoctl.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calico-cni.tar
    docker exec -t ${node} ctr -n=k8s.io images import /pod2daemon.tar
    docker exec -t ${node} ctr -n=k8s.io images import /kube-controllers.tar
    docker exec -t ${node} rm /calico-node.tar /calicoctl.tar /calico-cni.tar /pod2daemon.tar /kube-controllers.tar /calico-apiserver.tar
}

load_image kind-control-plane
load_image kind-worker
load_image kind-worker2
load_image kind-worker3
