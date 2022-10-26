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
	"reflect"

	log "github.com/sirupsen/logrus"
	"gopkg.in/go-playground/validator.v9"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

const (
	KubeControllersConfigResourceName = "KubeControllersConfigurations"
	KubeControllersConfigCRDName      = "kubecontrollersconfigurations.crd.projectcalico.org"
)

func NewKubeControllersConfigClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            KubeControllersConfigCRDName,
		resource:        KubeControllersConfigResourceName,
		description:     "Calico Kubernetes Controllers Configuration",
		k8sResourceType: reflect.TypeOf(apiv3.KubeControllersConfiguration{}),
		k8sResourceTypeMeta: metav1.TypeMeta{
			Kind:       apiv3.KindKubeControllersConfiguration,
			APIVersion: apiv3.GroupVersionCurrent,
		},
		k8sListType:  reflect.TypeOf(apiv3.KubeControllersConfigurationList{}),
		resourceKind: apiv3.KindKubeControllersConfiguration,
		validator:    kubeControllersConfigValidator{},
	}
}

type kubeControllersConfigValidator struct{}

func (v kubeControllersConfigValidator) Validate(res Resource) error {
	config := res.(*apiv3.KubeControllersConfiguration)
	if node := config.Spec.Controllers.Node; node != nil {
		if label := node.SyncLabels; label != "" {
			validate := validator.New()
			log.Debugf("Validate SyncLabels for Kubernetes datastore type: %s", label)
			if err := validate.VarWithValue(label, apiv3.Enabled, "eqfield"); err != nil {
				log.Debugf("SyncLabels value must be set to enabled with Kubernetes datastore driver.")
				return err
			}
		}
	}
	return nil
}
