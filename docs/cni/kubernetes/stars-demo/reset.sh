#!/bin/bash

kubectl delete rc,svc --all --namespace=client
kubectl delete rc,svc --all --namespace=management-ui
kubectl delete rc,svc --all --namespace=stars

kubectl delete ns stars
kubectl delete ns client
kubectl delete ns management-ui

policy delete frontend-policy --namespace=stars
policy delete backend-policy --namespace=stars
policy delete allow-ui --namespace=stars
policy delete allow-ui --namespace=client
