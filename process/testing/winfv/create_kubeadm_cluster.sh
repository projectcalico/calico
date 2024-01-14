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
# Download the Google Cloud public signing key
sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://dl.k8s.io/apt/doc/apt-key.gpg
# Add the Kubernetes apt repository
echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list

K8S_PKG_VERSION=${KUBE_VERSION}-00
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

# Deploy OS Calico but for EE FV, apply EE crds and RBAC later.
echo "Applying custom resources..."
kubectl apply -f ${ROOT}/infra/installation-${BACKEND}.yaml
kubectl get installation default -oyaml

echo "Checking that kube-dns is up"
retry_kubectl "wait pod -l k8s-app=kube-dns --for=condition=Ready -n kube-system --timeout=300s" 30
echo "Calico is running."

kubectl taint nodes --all node-role.kubernetes.io/master-

# strict affinity
curl -sSf -L --retry 5 https://github.com/projectcalico/calico/releases/download/v3.27.0/calicoctl-linux-amd64 -o calicoctl
chmod +x calicoctl
export CALICO_DATASTORE_TYPE=kubernetes
export CALICO_KUBECONFIG=~/.kube/config
./calicoctl --allow-version-mismatch get node
./calicoctl --allow-version-mismatch ipam configure --strictaffinity=true
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
