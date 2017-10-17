// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package custom

import (
	"encoding/json"

	"github.com/projectcalico/libcalico-go/lib/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GlobalNetworkPolicy is the CustomResourceDefinition of a Calico Policy resource in
// the Kubernetes API.
type GlobalNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ObjectMeta `json:"metadata"`
	Spec            api.PolicySpec    `json:"spec"`
}

// GlobalNetworkPolicyList is a list of GlobalNetworkPolicy resources.
type GlobalNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ListMeta       `json:"metadata"`
	Items           []GlobalNetworkPolicy `json:"items"`
}

// GetObjectKind returns the kind of this object.  Required to satisfy Object interface
func (e *GlobalNetworkPolicy) GetObjectKind() schema.ObjectKind {
	return &e.TypeMeta
}

// GetOjbectMeta returns the object metadata of this object. Required to satisfy ObjectMetaAccessor interface
func (e *GlobalNetworkPolicy) GetObjectMeta() metav1.Object {
	return &e.Metadata
}

// GetObjectKind returns the kind of this object. Required to satisfy Object interface
func (el *GlobalNetworkPolicyList) GetObjectKind() schema.ObjectKind {
	return &el.TypeMeta
}

// GetListMeta returns the list metadata of this object. Required to satisfy ListMetaAccessor interface
func (el *GlobalNetworkPolicyList) GetListMeta() metav1.List {
	return &el.Metadata
}

// The code below is used only to work around a known problem with third-party
// resources and ugorji. If/when these issues are resolved, the code below
// should no longer be required.

type GlobalNetworkPolicyListCopy GlobalNetworkPolicyList
type GlobalNetworkPolicyCopy GlobalNetworkPolicy

func (g *GlobalNetworkPolicy) UnmarshalJSON(data []byte) error {
	tmp := GlobalNetworkPolicyCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := GlobalNetworkPolicy(tmp)
	*g = tmp2
	return nil
}

func (l *GlobalNetworkPolicyList) UnmarshalJSON(data []byte) error {
	tmp := GlobalNetworkPolicyListCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := GlobalNetworkPolicyList(tmp)
	*l = tmp2
	return nil
}
