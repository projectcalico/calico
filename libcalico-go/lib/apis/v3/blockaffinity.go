// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package v3

import (
	"crypto/sha3"
	"encoding/hex"
	"strconv"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

const (
	KindBlockAffinity     = "BlockAffinity"
	KindBlockAffinityList = "BlockAffinityList"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BlockAffinity maintains a block affinity's state
type BlockAffinity struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the BlockAffinity.
	Spec BlockAffinitySpec `json:"spec,omitempty"`
}

// BlockAffinitySpec contains the specification for a BlockAffinity resource.
type BlockAffinitySpec struct {
	State string `json:"state"`
	Node  string `json:"node"`
	Type  string `json:"type,omitempty"`
	CIDR  string `json:"cidr"`

	// Deleted indicates that this block affinity is being deleted.
	// This field is a string for compatibility with older releases that
	// mistakenly treat this field as a string.
	Deleted string `json:"deleted"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BlockAffinityList contains a list of BlockAffinity resources.
type BlockAffinityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []BlockAffinity `json:"items"`
}

// NewBlockAffinity creates a new (zeroed) BlockAffinity struct with the TypeMetadata initialised to the current
// version.
func NewBlockAffinity() *BlockAffinity {
	return &BlockAffinity{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindBlockAffinity,
			APIVersion: apiv3.GroupVersionCurrent,
		},
	}
}

// NewBlockAffinityList creates a new (zeroed) BlockAffinityList struct with the TypeMetadata initialised to the current
// version.
func NewBlockAffinityList() *BlockAffinityList {
	return &BlockAffinityList{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindBlockAffinityList,
			APIVersion: apiv3.GroupVersionCurrent,
		},
	}
}

func EnsureBlockAffinityLabels(ba *BlockAffinity) {
	if ba.Labels == nil {
		ba.Labels = make(map[string]string)
	}
	// Hostnames can be longer than labels are allowed to be, so we hash it down.
	ba.Labels[apiv3.LabelHostnameHash] = HashHostname(ba.Spec.Node)
	ba.Labels[apiv3.LabelAffinityType] = ba.Spec.Type
	var ipVersion string
	if strings.Contains(ba.Spec.CIDR, ":") {
		ipVersion = "6"
	} else {
		ipVersion = "4"
	}
	ba.Labels[apiv3.LabelIPVersion] = ipVersion
}

func CalculateBlockAffinityLabelSelector(list model.BlockAffinityListOptions) labels.Selector {
	labelsToMatch := map[string]string{}
	if list.Host != "" {
		labelsToMatch[apiv3.LabelHostnameHash] = HashHostname(list.Host)
	}
	if list.AffinityType != "" {
		labelsToMatch[apiv3.LabelAffinityType] = list.AffinityType
	}
	if list.IPVersion != 0 {
		labelsToMatch[apiv3.LabelIPVersion] = strconv.Itoa(list.IPVersion)
	}
	var labelSelector labels.Selector
	if len(labelsToMatch) > 0 {
		labelSelector = labels.SelectorFromSet(labelsToMatch)
	}
	return labelSelector
}

func HashHostname(hostname string) string {
	var hasher sha3.SHA3
	_, err := hasher.Write([]byte(hostname))
	if err != nil {
		// Hashers are contracted never to fail, only return an error to satisfy io.Writer.
		panic("SHA3.Write failed: " + err.Error())
	}
	h := hasher.Sum(nil)
	return hex.EncodeToString(h)
}
