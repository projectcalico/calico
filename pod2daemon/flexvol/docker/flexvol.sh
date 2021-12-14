#!/bin/sh
# Copyright (c) 2018 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

## Copies the flexvolume driver to the desired location on the host system

set -o errexit

usage() {
  [[ -n "${1}" ]] && echo "${1}"

  cat <<EOF
usage: ${BASH_SOURCE[0]} [options ...]
  options::
   -s ... source directory for driver image
   -t ... target directory where the driver image is copied
   -i ... source binary name
   -d ... destination binary name
EOF
   exit 2
}

SRCDIR=/usr/local/bin
DSTDIR=/host/driver
IMAGE=flexvol
DSTIMAGE=uds

while getopts s:t:i:d: arg; do
  case ${arg} in
    s) SRCDIR="${OPTARG}" ;;
    t) DSTDIR="${OPTARG}" ;;
    i) IMAGE="${OPTARG}" ;;
    d) DSTIMAGE="${OPTARG}" ;;
    *) usage "Invalid option: -${OPTARG}" ;;
  esac
done

if [ ! -f ${SRCDIR}/${IMAGE} ]; then
  echo "Image not present ${SRCDIR}/${IMAGE}"
  exit 2
fi

if [ ! -d ${DSTDIR} ]; then
  echo "Destination directory ${DSTDIR} not present!?"
  exit 2
fi

if [ -f ${DSTDIR}/${DSTIMAGE} ]; then
  echo "File exists ${DSTDIR}/${DSTIMAGE}. Copy over"
fi

cp ${SRCDIR}/${IMAGE} ${DSTDIR}/.${DSTIMAGE}
chmod 0550 ${DSTDIR}/.${DSTIMAGE}
mv ${DSTDIR}/.${DSTIMAGE} ${DSTDIR}/${DSTIMAGE}
