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
  "name": "Calico",
  "windows_use_single_network": true,
  "cniVersion": "0.3.1",
  "type": "calico",
  "mode": "vxlan",
  "vxlan_mac_prefix":  "__MAC_PREFIX__",
  "vxlan_vni": __VNI__,
  "policy": {
    "type": "k8s"
  },
  "log_level": "info",
  "capabilities": {"dns": true},
  "DNS":  {
    "Search":  [
      "svc.cluster.local"
    ]
  },
  "datastore_type": "__DATASTORE_TYPE__",
  "kubernetes": {
    "kubeconfig": "__KUBECONFIG_FILEPATH__"
  },
  "ipam": {
    "type": "calico-ipam",
    "subnet": "usePodCidr"
  },
  "policies":  [
    {
      "Name":  "EndpointPolicy",
      "Value":  {
        "Type":  "__ROUTE_TYPE__",
        "ExceptionList":  [
          "__K8S_SERVICE_CIDR__"
        ]
      }
    },
    {
      "Name":  "EndpointPolicy",
      "Value":  {
        "Type":  "__ROUTE_TYPE__",
        "DestinationPrefix":  "__K8S_SERVICE_CIDR__",
        "NeedEncap":  true
      }
    }
  ]
}
`
	return netconf
}
