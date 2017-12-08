#!/bin/bash
## Build the docker image for nodeagent (default)
## Invoke it from the base directory of the repo

usage() {
  [[ -n "${1}" ]] && echo "${1}"

  cat <<EOF
usage: ${BASH_SOURCE[0]} [options ...]"
  options::
   -c ... do a clean build
   -t ... tag to use
   -i ... image to build
EOF
  exit 2
}

ROOT="$(pwd)"
IMAGE="nodeagent"
REG="quay.io"
TAG=$(git show --format=%h --no-patch)


CLEAN_BUILD=0
while getopts ct:i:r: arg; do
  case ${arg} in
     c) CLEAN_BUILD=1 ;;
     t) TAG="${OPTARG}" ;;
     i) IMAGE="${OPTARG}" ;;
     r) REG="${OPTARG}" ;;
     *) usage "Invalid option: -${OPTARG}" ;;
  esac
done

DEBUG_IMAGE_NAME="${REG}/${USER}/${IMAGE}:${TAG}"
TARGET_DIR="${ROOT}/bin/${IMAGE}"

if [ $CLEAN_BUILD -eq 1 ]; then
  rm -rf ${TARGET_DIR}
  bazel build //${IMAGE}:${IMAGE}
fi

genfiles=$(bazel info bazel-bin)
opdir="linux_amd64_stripped"
OPFILE=${genfiles}/${IMAGE}/${opdir}/${IMAGE}
hostdir=${ROOT}/${IMAGE}/docker

if [ ! -f ${OPFILE} ]; then
   echo "No file ${OPFILE}"
   exit 2
fi

mkdir -p ${TARGET_DIR}

cp ${OPFILE} ${TARGET_DIR}/
cp ${hostdir}/${IMAGE}.sh ${TARGET_DIR}/
cp ${hostdir}/Dockerfile.debug ${TARGET_DIR}/
docker build -f ${TARGET_DIR}/Dockerfile.debug -t "${DEBUG_IMAGE_NAME}" ${TARGET_DIR}
echo "Push ${DEBUG_IMAGE_NAME} to a registry now"
