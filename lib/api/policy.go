// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package api

import (
	. "github.com/tigera/libcalico-go/lib/api/unversioned"
)

type PolicyMetadata struct {
	ObjectMetadata
	Name string `json:"name,omitempty" validate:"omitempty,name"`
}

type PolicySpec struct {
	Order        *float32 `json:"order" validate:"order"`
	IngressRules []Rule   `json:"ingress,omitempty" validate:"omitempty,dive"`
	EgressRules  []Rule   `json:"egress,omitempty" validate:"omitempty,dive"`
	Selector     string   `json:"selector" validate:"selector"`
}

type Policy struct {
	TypeMetadata
	Metadata PolicyMetadata `json:"metadata,omitempty"`
	Spec     PolicySpec     `json:"spec,omitempty"`
}

func NewPolicy() *Policy {
	return &Policy{TypeMetadata: TypeMetadata{Kind: "policy", APIVersion: "v1"}}
}

type PolicyList struct {
	TypeMetadata
	Metadata ListMetadata `json:"metadata,omitempty"`
	Items    []Policy     `json:"items" validate:"dive"`
}

func NewPolicyList() *PolicyList {
	return &PolicyList{TypeMetadata: TypeMetadata{Kind: "policyList", APIVersion: "v1"}}
}
