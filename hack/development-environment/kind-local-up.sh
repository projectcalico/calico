#!/bin/bash

# Thanks to https://alexbrand.dev/post/creating-a-kind-cluster-with-calico-networking/ for this snippet :)
cat << EOF > calico-conf.yaml
kind: Cluster
apiVersion: kind.sigs.k8s.io/v1alpha3
networking:
  disableDefaultCNI: true # disable kindnet
  podSubnet: 192.168.0.0/16 # set to Calico's default subnet
nodes:
- role: control-plane
- role: worker
EOF

# Where all your source lives...

function check() {
	if [[ "$ROOT_CALICO_REPOS_DIR" == "" ]] ;  then
	    echo "Need to specify ROOT_CALICO_REPOS_DIR = "
	fi
	if [[ "$BUILD_CALICO" == "" ]] ; then 
            BUILD_CALICO="true"
	fi
}

echo "calico source ---> $ROOT_CALICO_REPOS_DIR"

echo "$ROOT_CALICO_REPOS_DIR is the input dir for calico sources"
set +x
if [ ! -d ${ROOT_CALICO_REPOS_DIR}/node ]; then
    ls -altrh $ROOT_CALICO_REPOS_DIR
    echo "clone down all the calico repos before starting/"
    exit 1
fi

function build() {
    pushd $ROOT_CALICO_REPOS_DIR/calico/
	echo "MAKE DEV_IMAGE ***********************************************"
	make dev-image REGISTRY=cd LOCAL_BUILD=true TAG_COMMAND='echo latest'
	echo "MAKE DEV_MANIFESTS *******************************************"
        make dev-manifests REGISTRY=cd TAG_COMMAND='echo latest'
    popd
}

function load_images() {
	# Now, we need to copy local docker images into the container
	# daemon running inside kind.
	echo "Copying images into kind cluster !!!"
	for i in "cni-plugin" "node" "pod2daemon" "kube-controllers"; do 
            echo "...$i"
            kind load docker-image cd/$i:latest-amd64 --name calico-test
	done
}

function install_k8s() {
    if kind delete cluster --name calico-test; then
    	echo "deleted old kind cluster, creating a new one..."
    fi	    
    kind create cluster --name calico-test --config calico-conf.yaml
    export KUBECONFIG="$(kind get kubeconfig-path --name=calico-test)"
    for i in "cni-plugin" "node" "pod2daemon" "kube-controllers"; do 
        echo "...$i"
    done
    chmod 755 ~/.kube/kind-config-kind
    export KUBECONFIG="$(kind get kubeconfig-path --name=calico-test)"
    until kubectl cluster-info;  do
        echo "`date`waiting for cluster..."
        sleep 2
    done
}

function install_calico() {
    kubectl get pods
    pushd $ROOT_CALICO_REPOS_DIR/calico/_output/dev-manifests
        kubectl apply -f ./calico.yaml
        kubectl get pods -n kube-system
    popd
	kubectl -n kube-system set env daemonset/calico-node FELIX_IGNORELOOSERPF=true
	kubectl -n kube-system set env daemonset/calico-node FELIX_XDPENABLED=false
	sleep 5 ; kubectl -n kube-system get pods | grep calico-node
    echo "will wait for calico to start running now... "
    while true ; do
        kubectl -n kube-system get pods
        sleep 3
    done
}

check

if [[ ! "${BUILD_CALICO}" == "false" ]] ; then
    build
fi
if [[ ! -d ${ROOT_CALICO_REPOS_DIR}/calico/_output ]] ; then
    echo "No build output directory ! Provide a build of calico before we finish installation."
    exit 1
fi

if [[ ! "${BUILD_CALICO}" == "false" ]] ; then
    build
fi
if [[ ! -d ${ROOT_CALICO_REPOS_DIR}/calico/_output ]] ; then
    echo "No build output directory ! Provide a build of calico before we finish installation"
    exit 1
fi

install_k8s
load_images
install_calico
