// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

// Dummy version of the HCN API for compilation on Linux.
package hcn

import "encoding/json"

type EndpointPolicyType string

const (
	PortMapping                EndpointPolicyType = "PortMapping"
	ACL                        EndpointPolicyType = "ACL"
	QOS                        EndpointPolicyType = "QOS"
	L2Driver                   EndpointPolicyType = "L2Driver"
	OutBoundNAT                EndpointPolicyType = "OutBoundNAT"
	SDNRoute                   EndpointPolicyType = "SDNRoute"
	L4Proxy                    EndpointPolicyType = "L4Proxy"
	L4WFPPROXY                 EndpointPolicyType = "L4WFPPROXY"
	PortName                   EndpointPolicyType = "PortName"
	EncapOverhead              EndpointPolicyType = "EncapOverhead"
	NetworkProviderAddress     EndpointPolicyType = "ProviderAddress"
	NetworkInterfaceConstraint EndpointPolicyType = "InterfaceConstraint"
)

type EndpointPolicy struct {
	Type     EndpointPolicyType `json:""`
	Settings json.RawMessage    `json:",omitempty"`
}
