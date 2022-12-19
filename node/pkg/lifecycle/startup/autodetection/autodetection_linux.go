// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package autodetection

// Default interfaces to exclude for any logic following the first-found
// auto detect IP method
var DEFAULT_INTERFACES_TO_EXCLUDE []string = []string{
	"^docker.*", "^cbr.*", "^dummy.*",
	"^virbr.*", "^lxcbr.*", "^veth.*", "^lo",
	"^cali.*", "^tunl.*", "^flannel.*", "^kube-ipvs.*", "^cni.*",
	"^vxlan\\.calico.*", "^vxlan-v6\\.calico.*", "^wireguard\\.cali.*", "^wg-v6\\.cali.*",
	"^nodelocaldns.*",
}
