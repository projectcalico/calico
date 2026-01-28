// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package resources

import (
	"errors"
	"reflect"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
)

const (
	KubeControllersConfigResourceName = "KubeControllersConfigurations"
)

func NewKubeControllersConfigClient(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	return &customResourceClient{
		restClient:      r,
		resource:        KubeControllersConfigResourceName,
		k8sResourceType: reflect.TypeOf(apiv3.KubeControllersConfiguration{}),
		k8sListType:     reflect.TypeOf(apiv3.KubeControllersConfigurationList{}),
		kind:            apiv3.KindKubeControllersConfiguration,
		validator:       kubeControllersConfigValidator{},
		apiGroup:        group,
	}
}

type kubeControllersConfigValidator struct{}

func (v kubeControllersConfigValidator) Validate(res Resource) error {
	config := res.(*apiv3.KubeControllersConfiguration)
	if node := config.Spec.Controllers.Node; node != nil {
		log.Debugf("Validate SyncLabels for Kubernetes datastore type: %s", node.SyncLabels)
		if node.SyncLabels == apiv3.Disabled {
			log.Debugf("SyncLabels value cannot be set to disabled with Kubernetes datastore driver.")
			return errors.New("invalid SyncLabels value")
		}
	}
	return nil
}
