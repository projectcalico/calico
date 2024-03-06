#!/bin/bash

KUBE_VERSION=$1
BACKEND=$2
FV_TYPE=$3

sudo mkdir -p /etc/docker
cat <<EOF | sudo tee /etc/docker/daemon.json
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2"
}
EOF
sudo systemctl enable --now docker
sudo systemctl daemon-reload
sudo systemctl restart docker
sudo usermod -aG docker ubuntu

sudo apt-get update -y

# Set up repository and install updated containerd
# https://forum.linuxfoundation.org/discussion/862825/kubeadm-init-error-cri-v1-runtime-api-is-not-implemented
# https://docs.docker.com/engine/install/ubuntu/#set-up-the-repository
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL --retry 5 https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod 644 /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -y
sudo apt remove containerd
sudo apt install containerd.io
sudo rm /etc/containerd/config.toml
sudo systemctl enable --now containerd
sudo systemctl daemon-reload
sudo systemctl restart containerd

KUBE_REPO_VERSION=$(echo ${KUBE_VERSION} | cut -d '.' -f 1,2)
# Download the k8s repo signing key
curl -fsSL --retry 5 "https://pkgs.k8s.io/core:/stable:/v${KUBE_REPO_VERSION}/deb/Release.key" | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
sudo chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg
# Add the Kubernetes apt repository
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v${KUBE_REPO_VERSION}/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list

K8S_PKG_VERSION=${KUBE_VERSION}-1.1
sudo apt-get update && sudo apt-get install -y kubelet=${K8S_PKG_VERSION} kubeadm=${K8S_PKG_VERSION} kubectl=${K8S_PKG_VERSION}
sudo swapoff -a

K8S_VERSION=stable-$(echo ${KUBE_VERSION} | cut -d. -f1,2)
sudo kubeadm init --kubernetes-version ${K8S_VERSION} --pod-network-cidr=192.168.0.0/16
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $ubuntu:$ubuntu $HOME/.kube/config

if [ "$FV_TYPE" == "cni-plugin" ]; then
  exit 0
fi

function retry_kubectl() {
  kubectl_command=$1
  kube=$(command -v "kubectl")
  if [[ "${kube}" == "" ]]; then
      echo "[ERROR] kubectl not found locally".
      exit 1
  fi
  kubectl_retries=$2
  kubectl_success=1
  kubectl_output=""
  until [[ ${kubectl_success} -eq 0 ]] || [[ kubectl_retries -lt 1 ]]; do
    echo "Attempting to run ${kube} $kubectl_command, attempts remaining=$kubectl_retries"
    kubectl_output=$(eval "${kube} ${kubectl_command}")
    kubectl_success=$?
    ((kubectl_retries--))
    sleep 1
  done
  echo "${kubectl_output}"
  if [[ ${kubectl_success} -ne 0 ]]; then
      echo "[ERROR] kubectl retry failed".
      exit 1
  fi
}

# install calico
ROOT="./winfv"
docs_url=`curl https://latest-os.docs.eng.tigera.net/master.txt`
kubectl create -f ${docs_url}/manifests/tigera-operator.yaml
sleep 5

# Deply OS Calico but for EE FV, apply EE crds and RBAC later.
echo "Applying custom resources..."
kubectl apply -f ${ROOT}/infra/installation-${BACKEND}.yaml
kubectl get installation default -oyaml

echo "Checking that kube-dns is up"
retry_kubectl "wait pod -l k8s-app=kube-dns --for=condition=Ready -n kube-system --timeout=300s" 30
echo "Calico is running."

kubectl taint nodes --all node-role.kubernetes.io/master-

# strict affinity
curl -O -L  https://github.com/projectcalico/calicoctl/releases/download/v3.17.1/calicoctl
chmod +x calicoctl
export CALICO_DATASTORE_TYPE=kubernetes
export CALICO_KUBECONFIG=~/.kube/config
./calicoctl get node
./calicoctl ipam configure --strictaffinity=true
echo "ipam configured"

pushd $ROOT/infra
./setup.sh
if [ "$FV_TYPE" == "tigera-felix" ]; then
  # Latest OS or EE crds is copied from felix's fv/infrastructure/crds.
  kubectl apply -f ee/crd
  # Stop operator setups OS RBAC role.
  kubectl annotate clusterrole calico-node unsupported.operator.tigera.io/ignore="true"
  sleep 5
  # Latest EE calico-node RBAC role is predefined.
  kubectl apply -f ee/role.yaml
  kubectl apply -f ee/license.yaml
fi
popd
