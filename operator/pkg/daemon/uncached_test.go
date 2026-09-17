// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package daemon

import (
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The cache strips managedFields, so the shared-config writer cannot resolve ownership from a
// cached copy of the resources it governs.
func TestUncachedObjectsReadsManagedFieldsLive(t *testing.T) {
	objects := uncachedObjects([]client.Object{&corev1.Secret{}})

	var felixConfig, bgpConfig, caller bool
	for _, obj := range objects {
		switch obj.(type) {
		case *v3.FelixConfiguration:
			felixConfig = true
		case *v3.BGPConfiguration:
			bgpConfig = true
		case *corev1.Secret:
			caller = true
		}
	}
	if !felixConfig {
		t.Error("expected FelixConfiguration to be read uncached")
	}
	if !bgpConfig {
		t.Error("expected BGPConfiguration to be read uncached")
	}
	if !caller {
		t.Error("expected the caller's own uncached objects to be kept")
	}
}
