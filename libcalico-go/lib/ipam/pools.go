// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.

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
package ipam

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

// Interface used to access the enabled IPPools.
type PoolAccessorInterface interface {
	// Returns a list of enabled pools sorted in alphanumeric name order.
	GetEnabledPools(ipVersion int) ([]v3.IPPool, error)
	// Returns a list of all pools sorted in alphanumeric name order.
	GetAllPools() ([]v3.IPPool, error)
}

// SelectsNode determines whether or not the IPPool's nodeSelector
// matches the labels on the given node.
func SelectsNode(pool v3.IPPool, n libapiv3.Node) (bool, error) {
	// No node selector means that the pool matches the node.
	if len(pool.Spec.NodeSelector) == 0 {
		return true, nil
	}
	// Check for valid selector syntax.
	sel, err := selector.Parse(pool.Spec.NodeSelector)
	if err != nil {
		return false, err
	}
	// Return whether or not the selector matches.
	return sel.Evaluate(n.Labels), nil
}
