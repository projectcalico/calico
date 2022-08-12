#!/usr/bin/env bash

set -e
set -x

FV_DIR="/home/semaphore/process/testing/winfv"
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:=docker}"

pushd ${FV_DIR}
# Prepare local files
cp ~/.docker/config.json docker_auth.json
cp ~/$SEMAPHORE_GIT_DIR/internal/pkg/testutils/private.key private.key
cp ~/$SEMAPHORE_GIT_DIR/bin/windows/*.exe .

# Prepare key for windows fv.
ssh-keygen -f master_ssh_key -N ''
puttygen ${MASTER_CONNECT_KEY} -O private -o ${WIN_PPK_KEY}
chmod 600 $WIN_PPK_KEY
aws ec2 import-key-pair --key-name ${KEYPAIR_NAME} --public-key-material file://${MASTER_CONNECT_KEY_PUB}

# Set up the cluster. Set FV timeout to 40 minutes.
NAME_PREFIX="$CLUSTER_NAME" KUBE_VERSION="$K8S_VERSION" WINDOWS_KEYPAIR_NAME="$KEYPAIR_NAME" \
WINDOWS_PEM_FILE="$MASTER_CONNECT_KEY" WINDOWS_PPK_FILE="$WIN_PPK_KEY" WINDOWS_OS="Windows1809container" \
CONTAINER_RUNTIME="$CONTAINER_RUNTIME" FV_TIMEOUT=2400 ./setup-fv.sh -q | tee fv.log

# Run FV
MASTER_IP=$(grep ubuntu@ fv.log | cut -d '@' -f2)
SSH_CMD=$(echo ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ${MASTER_CONNECT_KEY} ubuntu@${MASTER_IP})

${SSH_CMD} ls -ltr /home/ubuntu
${SSH_CMD} ls -ltr /home/ubuntu/winfv
${SSH_CMD} touch /home/ubuntu/winfv/file-ready
${SSH_CMD} time /home/ubuntu/winfv/wait-report.sh
${SSH_CMD} ls -ltr /home/ubuntu/report
popd

# Get results and logs 
SCP_CMD=$(echo scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ${FV_DIR}/${MASTER_CONNECT_KEY})
${SCP_CMD} -r ubuntu@${MASTER_IP}:/home/ubuntu/report /home/semaphore

ls -ltr ./report
mkdir /home/semaphore/fv.log
# check if *.log glob contains any files so that mv doesn't fail
compgen -G /home/semaphore/report/*.log > /dev/null && mv /home/semaphore/report/*.log /home/semaphore/fv.log

# Stop for debug
echo "Check for pause file..."
while [ -f /home/semaphore/pause-for-debug ];
do
    echo "#"
    sleep 30
done

# Search for error code file
if [ -f /home/semaphore/report/error-codes ];
then
    echo "Windows FV return error."
    exit 1
fi
   
echo "Run Windows FV is done."
