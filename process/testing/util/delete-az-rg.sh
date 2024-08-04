#!/usr/bin/env bash

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

RESOURCE_GROUP=$1

if ! az group show --name "${RESOURCE_GROUP}" --subscription ${AZ_SUBSCRIPTION_ID} 2>&1 | grep ResourceGroupNotFound; then
  echo "Deleting azure resource group ${RESOURCE_GROUP}"
  az group delete --name "${RESOURCE_GROUP}" --subscription ${AZ_SUBSCRIPTION_ID} --yes
else
  echo "No resource group ${RESOURCE_GROUP} found. Doing nothing"
fi
