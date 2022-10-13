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

	"k8s.io/client-go/rest"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
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
		validator:    validateSyncLabels,
	}
}

func validateSyncLabels(re Resource) error {
	kubeControllersConfiguration := re.(*apiv3.KubeControllersConfiguration)
	syncLabels := kubeControllersConfiguration.Spec.Controllers.Node.SyncLabels
	err := validator.ValidateSyncLabels(syncLabels)
	return err
}
