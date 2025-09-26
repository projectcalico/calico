// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package rawcrdclient

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	schemecrdv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/crd.projectcalico.org/v1/scheme"
)

// New returns a new controller-runtime client configured to access
// raw CRDs.  This is used in tests to create invalid or pre-upgrade resources
// that cannot be created with the main client due to its validation(!)
//
// If usev3 is true, the client will be configured to use the projectcalico.org/v3 API group. Otherwise, it will
// use the crd.projectcalico.org/v1 API group.
func New(cfg *rest.Config, usev3 bool) (client.Client, error) {
	cfgCopy := *cfg

	// Force JSON, our types aren't all instrumented for protobuf.
	cfgCopy.ContentConfig.ContentType = "application/json"
	cfgCopy.ContentConfig.AcceptContentTypes = "application/json"

	scheme := runtime.NewScheme()
	var err error
	if usev3 {
		err = v3.AddToScheme(scheme)
	} else {
		err = schemecrdv1.AddCalicoResourcesToScheme(scheme)
	}
	if err != nil {
		return nil, err
	}
	return client.New(&cfgCopy, client.Options{Scheme: scheme})
}
