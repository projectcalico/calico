// Copyright (c) 2017-2022 Tigera, Inc. All rights reserved.

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

package clients

import (
	"fmt"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	apiv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/upgrade/migrator/clients/v1/k8s"
)

type V1ClientInterface interface {
	Apply(d *model.KVPair) (*model.KVPair, error)
	Update(d *model.KVPair) (*model.KVPair, error)
	Get(k model.Key) (*model.KVPair, error)
	List(l model.ListInterface) ([]*model.KVPair, error)
	IsKDD() bool
}

// LoadKDDClientV1FromAPIConfigV3 loads the KDD v1 client given the
// v3 API Config (since the v1 and v3 client use the same access information).
func LoadKDDClientV1FromAPIConfigV3(apiConfigv3 *apiconfig.CalicoAPIConfig) (V1ClientInterface, error) {
	if apiConfigv3.Spec.DatastoreType != apiconfig.Kubernetes {
		return nil, fmt.Errorf("not valid for this datastore type: %s", apiConfigv3.Spec.DatastoreType)
	}
	kc := &apiv1.KubeConfig{
		Kubeconfig:               apiConfigv3.Spec.Kubeconfig,
		K8sAPIEndpoint:           apiConfigv3.Spec.K8sAPIEndpoint,
		K8sKeyFile:               apiConfigv3.Spec.K8sKeyFile,
		K8sCertFile:              apiConfigv3.Spec.K8sCertFile,
		K8sCAFile:                apiConfigv3.Spec.K8sCAFile,
		K8sAPIToken:              apiConfigv3.Spec.K8sAPIToken,
		K8sInsecureSkipTLSVerify: apiConfigv3.Spec.K8sInsecureSkipTLSVerify,
	}

	// Create the backend etcdv2 client (v1 API). We wrap this in the compat module to handle
	// multi-key backed resources.
	return k8s.NewKubeClient(kc)
}
