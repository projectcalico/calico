// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package types

import (
	"fmt"

	"github.com/projectcalico/calico/felix/proto"
)

type PolicyID struct {
	Tier string
	Name string
}

func (p PolicyID) String() string {
	return fmt.Sprintf("{Tier: %s, Name: %s}", p.Tier, p.Name)
}

func ProtoToPolicyID(p *proto.PolicyID) PolicyID {
	return PolicyID{
		Tier: p.GetTier(),
		Name: p.GetName(),
	}
}

func PolicyIDToProto(p PolicyID) *proto.PolicyID {
	return &proto.PolicyID{
		Tier: p.Tier,
		Name: p.Name,
	}
}
