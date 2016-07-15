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

type ProfileMetadata struct {
	ObjectMetadata
	Labels map[string]string `json:"labels,omitempty" validate:"omitempty,labels"`
}

type ProfileSpec struct {
	IngressRules []Rule   `json:"ingress,omitempty" validate:"omitempty,dive"`
	EgressRules  []Rule   `json:"egress,omitempty" validate:"omitempty,dive"`
	Tags         []string `json:"tags,omitempty" validate:"omitempty,dive,tag"`
}

type Profile struct {
	TypeMetadata
	Metadata ProfileMetadata `json:"metadata,omitempty"`
	Spec     ProfileSpec     `json:"spec,omitempty"`
}

func NewProfile() *Profile {
	return &Profile{TypeMetadata: TypeMetadata{Kind: "profile", APIVersion: "v1"}}
}

type ProfileList struct {
	TypeMetadata
	Metadata ListMetadata `json:"metadata,omitempty"`
	Items    []Profile    `json:"items" validate:"dive,omitempty"`
}

func NewProfileList() *ProfileList {
	return &ProfileList{TypeMetadata: TypeMetadata{Kind: "profileList", APIVersion: "v1"}}
}
