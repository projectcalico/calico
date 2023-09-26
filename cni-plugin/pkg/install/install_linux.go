//go:build !windows

// Copyright (c) 2020 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package install

func defaultNetConf() string {
	netconf := `{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "log_level": "__LOG_LEVEL__",
      "log_file_path": "__LOG_FILE_PATH__",
      "datastore_type": "__DATASTORE_TYPE__",
      "nodename": "__KUBERNETES_NODE_NAME__",
      "mtu": __CNI_MTU__,
      "ipam": {"type": "calico-ipam"},
      "policy": {"type": "k8s"},
      "kubernetes": {"kubeconfig": "__KUBECONFIG_FILEPATH__"}
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {"portMappings": true}
    }
  ]
}`
	return netconf
}

// This function is currently a no-op for Linux
func replacePlatformSpecificVars(c config, netconf string) string {
	return netconf
}
