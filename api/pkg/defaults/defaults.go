// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
package defaults

import (
	"fmt"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Default applies defaulting logic to the given object if it is a type that we
// know about.  It returns true if it made any changes to the object.
func Default(obj v1.Object) (bool, error) {
	switch o := obj.(type) {
	case *v3.NetworkPolicy:
		return defaultNetworkPolicy(o)
	case *v3.GlobalNetworkPolicy:
		return defaultGlobalNetworkPolicy(o)
	case *v3.StagedNetworkPolicy:
		return defaultStagedNetworkPolicy(o)
	case *v3.StagedGlobalNetworkPolicy:
		return defaultStagedGlobalNetworkPolicy(o)
	}
	return false, fmt.Errorf("no defaulting logic for object of type %T", obj)
}
