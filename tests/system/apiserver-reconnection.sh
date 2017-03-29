#!/bin/bash -ex

# Utilities.
function get_container_ip {
    docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $1
}

function create_namespace {
    name=$1
    curl -k -H "Content-Type: application/yaml" -XPOST --data-binary @- https://172.17.0.3:6443/api/v1/namespaces <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${name}
EOF
    sleep 1
}

ETCD_IP=`get_container_ip st-etcd`
K8S_IP=`get_container_ip st-apiserver`

# Run policy controller.
docker rm -f calico-policy-controller || true
sleep 2
docker run --detach --name=calico-policy-controller \
       -e K8S_API=https://${K8S_IP}:6443 \
       -e K8S_INSECURE_SKIP_TLS_VERIFY=true \
       -e ETCD_ENDPOINTS=http://${ETCD_IP}:2379 \
       calico/kube-policy-controller
sleep 2

# Create a namespace.
NS_NAME=chocolate
create_namespace ${NS_NAME}

# Check for that namespace in etcd.
docker exec st-etcd etcdctl ls --recursive /calico | grep ${NS_NAME}

for n in `seq 0 9`; do

    # Stop k8s API
    make stop-k8s-apiserver

    # Wait 60 seconds
    sleep 60

    # Start k8s API and etcd
    make run-k8s-apiserver

    # Wait 20 seconds
    sleep 20

    # Create k8s namespace
    create_namespace testns${n}

    # Check for that namespace in etcd.
    docker exec st-etcd etcdctl ls --recursive /calico | grep testns${n}

done
