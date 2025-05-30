#!/bin/bash

function load_image() {
    local node=$1
    docker cp ./operator.tar ${node}:/operator.tar
    docker cp ./calico-node.tar ${node}:/calico-node.tar
    docker cp ./calico-typha.tar ${node}:/calico-typha.tar
    docker cp ./calico-apiserver.tar ${node}:/calico-apiserver.tar
    docker cp ./calicoctl.tar ${node}:/calicoctl.tar
    docker cp ./calico-cni.tar ${node}:/calico-cni.tar
    docker cp ./csi.tar ${node}:/csi.tar
    docker cp ./node-driver-registrar.tar ${node}:/node-driver-registrar.tar
    docker cp ./pod2daemon.tar ${node}:/pod2daemon.tar
    docker cp ./kube-controllers.tar ${node}:/kube-controllers.tar
    docker cp ./goldmane.tar ${node}:/goldmane.tar
    docker cp ./whisker.tar ${node}:/whisker.tar
    docker cp ./whisker-backend.tar ${node}:/whisker-backend.tar
    docker exec -t ${node} ctr -n=k8s.io images import /operator.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calico-node.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calico-typha.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calico-apiserver.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calicoctl.tar
    docker exec -t ${node} ctr -n=k8s.io images import /calico-cni.tar
    docker exec -t ${node} ctr -n=k8s.io images import /csi.tar
    docker exec -t ${node} ctr -n=k8s.io images import /node-driver-registrar.tar
    docker exec -t ${node} ctr -n=k8s.io images import /pod2daemon.tar
    docker exec -t ${node} ctr -n=k8s.io images import /kube-controllers.tar
    docker exec -t ${node} ctr -n=k8s.io images import /goldmane.tar
    docker exec -t ${node} ctr -n=k8s.io images import /whisker.tar
    docker exec -t ${node} ctr -n=k8s.io images import /whisker-backend.tar
    docker exec -t ${node} rm /calico-node.tar /calico-typha.tar /calicoctl.tar /calico-cni.tar /pod2daemon.tar /csi.tar /node-driver-registrar.tar /kube-controllers.tar /calico-apiserver.tar /operator.tar /goldmane.tar /whisker.tar /whisker-backend.tar
}

load_image kind-control-plane
load_image kind-worker
load_image kind-worker2
load_image kind-worker3
