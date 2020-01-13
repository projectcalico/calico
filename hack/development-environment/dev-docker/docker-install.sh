#!/bin/bash
echo "This recipe sets up a kind-k8s cluster w/ calico"

REGISTRY="calico-dev"
function check() {
	if [[ -z $ROOT_CALICO_REPOS_DIR ]] ;  then
	    echo "Need to specify ROOT_CALICO_REPOS_DIR = "
		exit 1
	fi
	if [[ -z $BUILD_CALICO ]] ; then
           BUILD_CALICO="true"
	fi
}

# It is compulsory to mount calico directory to the same path in docker
# because the container uses host's docker and that docker uses host's file system
function start_docker_build_container() {
	echo "Building and running a docker container for building calico..."
	docker build -t calico-build-container-img . 
	docker stop calico-build-container
	docker rm calico-build-container
	docker run --name calico-build-container -ti -v /var/run/docker.sock:/var/run/docker.sock -v \
	$ROOT_CALICO_REPOS_DIR:$ROOT_CALICO_REPOS_DIR -d --privileged calico-build-container-img
}

function build_calico(){
	echo "Building calico..."
	docker exec -ti calico-build-container bash -c "cd $ROOT_CALICO_REPOS_DIR/calico; \
	make dev-clean dev-image REGISTRY=$REGISTRY TAG_COMMAND\D='echo latest'"
	docker exec -ti calico-build-container bash -c "cd $ROOT_CALICO_REPOS_DIR/calico; \
	make dev-manifests REGISTRY=$REGISTRY TAG_COMMAND='echo latest'"
}

function install_k8s() {
	echo "Creating kind cluster..."
    if kind delete cluster --name calico-test; then
    	times echo "deleted old kind cluster, creating a new one..."
    fi	    
    kind create cluster --name calico-test --config calico-conf.yaml
    export KUBECONFIG="$(kind get kubeconfig-path --name=calico-test)"
    for i in "cni-plugin" "node" "pod2daemon" "kube-controllers"; do 
        echo "...$i"
    done
    export KUBECONFIG="$(kind get kubeconfig-path --name=calico-test)"
    until kubectl cluster-info;  do
        echo "`date`waiting for cluster..."
        sleep 2
    done
}

# Copy local docker images into the container daemon running inside kind.
function load_images() {
	echo "Copying images into kind cluster..."
	for i in "cni-plugin" "node" "pod2daemon" "kube-controllers"; do 
            echo "...$i"
            kind load docker-image $REGISTRY/$i:latest-amd64 --name calico-test
	done
}

function install_calico() {
	echo "Installing calico..."
    pushd $ROOT_CALICO_REPOS_DIR/calico/_output/dev-manifests
        kubectl --context kind-calico-test apply -f ./calico.yaml 
        kubectl --context kind-calico-test get pods -n kube-system
    popd
	kubectl --context kind-calico-test -n kube-system set env daemonset/calico-node FELIX_IGNORELOOSERPF=true
	kubectl --context kind-calico-test -n kube-system set env daemonset/calico-node FELIX_XDPENABLED=false
	sleep 5
}

CALICO_SUCCESS="failed"
function calico_test() {
    for i in {0..10}; do
        calico_kubecontroller=$(kubectl --context kind-calico-test get pods -n kube-system | grep calico-kube | grep Running | wc -l)
		calico_node=$(kubectl --context kind-calico-test get pods -n kube-system | grep calico-node | grep Running | wc -l)

        set x
        if [[ $calico_kubecontroller -eq 1  && $calico_node -ge 1 ]]; then
            CALICO_SUCCESS="successful"
            return
        else
            CALICO_SUCCESS="*** Error: Calico containers are not running... \n ***"
        fi
        sleep 5
    done
}

check
start_docker_build_container
build_calico
install_k8s
load_images
install_calico
calico_test

kubectl --context kind-calico-test get pods --all-namespaces | grep calico
if [[ $CALICO_SUCCESS == "successful" ]]; then
	echo "Your kind cluster is up. Calico installation: $CALICO_SUCCESS."
    exit 0
else
    echo "FAILED: Calico installation failed...  Error : $CALICO_SUCCESS"
    exit 1
fi
