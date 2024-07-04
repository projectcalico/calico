#!/bin/bash
# Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

set -o errexit
set -o nounset
set -o pipefail
set -x

LINUX_PIP=$1

curl -LO https://github.com/kubernetes/minikube/releases/download/v1.33.0/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube && rm minikube-linux-amd64

minikube start  --listen-address=0.0.0.0 --apiserver-ips=$LINUX_PIP

PORT_INFO=$(docker port minikube | grep 8443)

port=$(echo $PORT_INFO | grep -oE '[0-9]{5}' | tail -1)
echo "apiserver listening at port $port"
echo $port > $HOME/port_info