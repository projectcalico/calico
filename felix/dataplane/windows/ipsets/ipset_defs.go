// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.
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

package ipsets

import (
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type IPSetMetadata = ipsets.IPSetMetadata
type IPFamily = ipsets.IPFamily
type IPSetType = ipsets.IPSetType
type IPVersionConfig = ipsets.IPVersionConfig

const (
	IPSetTypeHashIPPort = ipsets.IPSetTypeHashIPPort
)

const (
	IPFamilyV4 = ipsets.IPFamilyV4
	IPFamilyV6 = ipsets.IPFamilyV6
)

// ipSet holds the state for a particular IP set.
type ipSet struct {
	IPSetMetadata
	Members set.Set
}

// IPVersionConfig wraps up the metadata for a particular IP version.
// type IPVersionConfig struct {
// Family IPFamily
// }

func NewIPVersionConfig(family IPFamily) *IPVersionConfig {
	return &IPVersionConfig{
		Family: family,
	}
}
