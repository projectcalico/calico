#!/bin/bash
echo "This recipe setsup a k8s cluster w/ calico"

MASTER_OR_WORKER="$3"

# Setup a k8s baseline
function setup() {
    update-alternatives --set iptables /usr/sbin/iptables-legacy
    sudo yum install -y git wget
    sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    sudo yum install -y docker-ce docker-ce-cli containerd.io
    sudo systemctl enable docker
}

# build all images for deploying from src
function build() {
    cd /calico_all/calico

    # check if required repositories to build calico images exist
    RESULT="pass"
    for c in "felix" "typha" "kube-controllers" "calicoctl" "cni-plugin" "app-policy" "pod2daemon" "node" "libcalico-go" "confd"; do
        if [ ! -d "../"$c ]; then echo "Missing repository $c" >/dev/stderr && RESULT="fail"; fi
    done

    if [[ "$RESULT" == "fail" ]]; then
        exit 1
    fi

    sudo setenforce 0
    sudo systemctl restart docker
    make dev-image REGISTRY=cd LOCAL_BUILD=true
    make dev-manifests REGISTRY=cd
}

# A smoke test for docker image build
function smoketest() {
    RESULT="pass"
    for c in "node" "pod2daemon" "calicoctl" "kube" "typha"; do
        if docker images | grep cd | grep $c -q; then echo "calico image build success for $c"; else echo "calico image build failed for $c" && RESULT="fail"; fi
    done

    if [[ "$RESULT" == "fail" ]]; then
        exit 1
    fi
}

#####################################################################################
############# This is work in progress, will add more over time #####################
#####################################################################################
function k8s_install() {
    swapoff -a
    echo '1' >/proc/sys/net/bridge/bridge-nf-call-iptables
    # Set SELinux in permissive mode (effectively disabling it)
    setenforce 0
    source /vagrant/kubeadmrepo.sh
    sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config
    yum install -y kubelet kubeadm kubectl --disableexcludes=kubernetes
    systemctl enable --now docker
    systemctl enable --now kubelet

    if [[ "$MASTER_OR_WORKER" == "master" ]]; then
        # install calico
        sudo kubeadm init --pod-network-cidr=192.168.0.0/16 --ignore-preflight-errors=NumCPU
        systemctl daemon-reload
        systemctl restart kubelet
    else
        echo "$MASTER_OR_WORKER <- node type"
    fi
    mkdir -p ~/.kube/
    cp /etc/kubernetes/admin.conf ~/.kube/config
    chmod 755 ~/.kube/config
}

function calico_install() {
    pushd /calico_all/calico/_output/dev-manifests
    kubectl apply -f ./calico.yaml
    kubectl get pods -n kube-system
    popd
}

CALICO_SUCCESS="false"
function calico_test() {
    for i in {0..10}; do
        numpods=$(kubectl get pods -n kube-system | grep calico | grep Running | wc -l)
        set x
        if [[ $numpods -eq 2 ]]; then
            CALICO_SUCCESS="passed"
            return
        else
            CALICO_SUCCESS="*** Error: Number of running pods != 2...  $numpods \n$(kubectl get pods -n kube-system | grep calico) \n ***"
        fi
        sleep 5
    done
}

echo "############## Building Calico from source ############################"
setup
build
smoketest

echo "############## Images built.  Now deploying kubernetes ################"
k8s_install
calico_install
calico_test

kubectl get pods --all-namespaces
echo "Your dev VM is up, vagrant ssh to access it.   TEST RESULT: $CALICO_SUCCESS."
if [[ $CALICO_SUCCESS == "passed" ]]; then
    exit 0
else
    echo "FAILED: Calico installation failed...  Error : $CALICO_SUCCESS"
    exit 1
fi
