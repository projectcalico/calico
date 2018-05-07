#!/bin/bash -ex

IMAGE=$1

function get_container_ip {
    docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $1
}

ETCD_IP=`get_container_ip st-etcd`
K8S_IP=`get_container_ip st-apiserver`

while ! docker exec st-apiserver kubectl create clusterrolebinding anonymous-admin --clusterrole=cluster-admin --user=system:anonymous; do
    sleep 2
done

function create_namespace {
    name=$1
    curl -k -H "Content-Type: application/yaml" -XPOST --data-binary @- https://${K8S_IP}:6443/api/v1/namespaces <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${name}
EOF
    sleep 1
}

# Create a kubeconfig to be used for the test.
cat >${PWD}/st-kubeconfig.yaml <<EOF
apiVersion: v1
kind: Config
clusters:
- name: test 
  cluster:
    insecure-skip-tls-verify: true
    server: https://${K8S_IP}:6443
users:
- name: calico
contexts:
- name: test-context
  context:
    cluster: test  
    user: calico
current-context: test-context
EOF

# Run policy controller.
docker rm -f calico-policy-controller || true
sleep 2
docker run --detach --name=calico-policy-controller \
	-v ${PWD}/st-kubeconfig.yaml:/st-kubeconfig.yaml \
	-e ETCD_ENDPOINTS=http://${ETCD_IP}:2379 \
	-e KUBECONFIG=/st-kubeconfig.yaml \
	-e ENABLED_CONTROLLERS="workloadendpoint,profile,policy" \
	-e LOG_LEVEL="debug" \
	${IMAGE}
sleep 2

# Create a trap which emits policy controller logs on failure.
trap "echo 'Test failed - printing logs:'; docker logs calico-policy-controller" ERR

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
