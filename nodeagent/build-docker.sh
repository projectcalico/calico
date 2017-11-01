#!/bin/bash

function usage() {
  [[ -n "${1}" ]] && echo "${1}"

  cat <<EOF
usage: ${BASH_SOURCE[0]} [options ...]"
  options::
   -c ... do a clean build
   -t ... tag to use
EOF
  exit 2
}

ROOT="$(pwd)"
TARGET_DIR="${ROOT}/bin/"
DEBUG_IMAGE_NAME="quay.io/saurabh/nodeagent:latest"
IMAGE="nodeagent"

CLEAN_BUILD=0
while getopts ct: arg; do
  case ${arg} in
     c) CLEAN_BUILD=1 ;;
     t) DEBUG_IMAGE_NAME="${OPTARG}";;
     *) usage "Invalid option: -${OPTARG}";;
  esac
done

if [ $CLEAN_BUILD -eq 1 ]; then
  rm -rf ${TARGET_DIR}
  sh build.sh
fi

mkdir -p ${TARGET_DIR}
mv ./${IMAGE} ${TARGET_DIR}/
cp ./${IMAGE}.sh ${TARGET_DIR}/
cp docker/Dockerfile.debug ${TARGET_DIR}/
docker build -f ${TARGET_DIR}/Dockerfile.debug -t "${DEBUG_IMAGE_NAME}" ${TARGET_DIR}
echo "Push ${DEBUG_IMAGE_NAME} to a registry now"
