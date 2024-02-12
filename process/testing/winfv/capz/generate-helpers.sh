#!/bin/bash

set -e
LOCAL_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

: ${KUBECTL:=$LOCAL_PATH/bin/kubectl}

KCAPZ="${KUBECTL} --kubeconfig=./kubeconfig"

APISERVER=$(${KCAPZ} config view -o jsonpath="{.clusters[?(@.name == \"${CLUSTER_NAME_CAPZ}\")].cluster.server}" | awk -F/ '{print $3}' | awk -F: '{print $1}')
if [ -z "${APISERVER}" ] ; then
  echo "Failed to get apiserver public ip"
  exit 1
fi
echo
echo APISERVER: ${APISERVER}

${KCAPZ} get node -o wide

echo
echo "Generating helper files"
CONNECT_FILE="ssh-node.sh"
echo "#---------Connect to Instance--------" | tee ${CONNECT_FILE}
echo "#usage: ./ssh-node.sh 6 to ssh into 10.1.0.6" | tee -a ${CONNECT_FILE}
echo "#usage: ./ssh-node.sh 6 'Get-Service -Name kubelet' > output" | tee -a ${CONNECT_FILE}
echo ssh -t -i $LOCAL_PATH/.sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o \'ProxyCommand ssh -i $LOCAL_PATH/.sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -W %h:%p capi@${APISERVER}\' capi@10.1.0.\$1 \$2 | tee -a ${CONNECT_FILE}
chmod +x ${CONNECT_FILE}
echo

SCP_FILE="scp-to-node.sh"
echo "#---------Copy files to Instance--------" | tee ${SCP_FILE}
echo "#usage: ./scp-to-node.sh 6 kubeconfig c:\\\\k\\\\kubeconfig -- copy kubeconfig to 10.1.0.6" | tee -a ${SCP_FILE}
echo "#usage: ./scp-to-node.sh 6 images/ebpf-for-windows-c-temp.zip 'c:\\' -- copy temp zip to 10.1.0.6" | tee -a ${SCP_FILE}
echo scp -i $LOCAL_PATH/.sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o \'ProxyCommand ssh -i $LOCAL_PATH/.sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -W %h:%p capi@${APISERVER}\' \$2 capi@10.1.0.\$1:\$3 | tee -a ${SCP_FILE}
chmod +x ${SCP_FILE}
echo

SCP_FROM_NODE="scp-from-node.sh"
echo "#---------Copy files to Instance--------" | tee ${SCP_FROM_NODE}
echo "#usage: ./scp-from-node.sh 6 c:/k/calico.log ./calico.log" | tee -a ${SCP_FROM_NODE}
echo scp -r -i $LOCAL_PATH/.sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o \'ProxyCommand ssh -i $LOCAL_PATH/.sshkey -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -W %h:%p capi@${APISERVER}\' capi@10.1.0.\$1:\$2 \$3 | tee -a ${SCP_FROM_NODE}
chmod +x ${SCP_FROM_NODE}

# Update env file with Windows ips
sed -i "/^export ID[0-9]=\"[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\"/d" ./export-env.sh

IP0=`$KCAPZ get node win-p-win000000 -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'`
echo; echo "Windows nodes IPs"
echo "IP0: $IP0"

if [[ $WIN_NODE_COUNT -gt 1 ]]; then
  IP1=`$KCAPZ get node win-p-win000001 -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'`
  echo "IP1: $IP1"
fi
