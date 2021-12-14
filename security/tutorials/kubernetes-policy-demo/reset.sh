#!/bin/bash
# Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

kubectl delete rc,svc --all --namespace=client
kubectl delete rc,svc --all --namespace=management-ui
kubectl delete rc,svc --all --namespace=stars

kubectl delete ns stars
kubectl delete ns client
kubectl delete ns management-ui

policy delete frontend-policy --namespace=stars
policy delete backend-policy --namespace=stars
policy delete allow-ui --namespace=stars
policy delete allow-ui --namespace=client
