#!/bin/bash
CURRENT_DIR=$(dirname "$0")
kubectl create ns demo --kubeconfig $1

kubectl apply -f $CURRENT_DIR/porter.yaml --kubeconfig $1
kubectl apply -f $CURRENT_DIR/nginx.yaml --kubeconfig $1
kubectl apply -f $CURRENT_DIR/client.yaml --kubeconfig $1
kubectl apply -f $CURRENT_DIR/ingress.yaml --kubeconfig $1
kubectl apply -f $CURRENT_DIR/egress.yaml --kubeconfig $1
