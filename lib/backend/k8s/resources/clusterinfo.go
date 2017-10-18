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

package resources

import (
	"reflect"

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/model"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	ClusterInfoResourceName = "ClusterInformations"
	ClusterInfoCRDName      = "clusterinformations.crd.projectcalico.org"
)

func NewClusterInfoClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            ClusterInfoCRDName,
		resource:        ClusterInfoResourceName,
		description:     "Calico Cluster Information",
		k8sResourceType: reflect.TypeOf(apiv2.ClusterInformation{}),
		k8sListType:     reflect.TypeOf(apiv2.ClusterInformationList{}),
		converter:       ClusterInfoConverter{},
	}
}

// ClusterInfoConverter implements the K8sResourceConverter interface.
type ClusterInfoConverter struct {
}

func (_ ClusterInfoConverter) ListInterfaceToKey(l model.ListInterface) model.Key {
	pl := l.(model.ResourceListOptions)
	if pl.Name != "" {
		return model.ResourceKey{Name: pl.Name, Kind: pl.Kind}
	}
	return nil
}

func (_ ClusterInfoConverter) KeyToName(k model.Key) (string, error) {
	return k.(model.ResourceKey).Name, nil
}

func (_ ClusterInfoConverter) NameToKey(name string) (model.Key, error) {
	return model.ResourceKey{
		Name: name,
		Kind: apiv2.KindClusterInformation,
	}, nil
}

func (c ClusterInfoConverter) ToKVPair(r Resource) (*model.KVPair, error) {
	t := r.(*apiv2.ClusterInformation)

	// Clear any CRD TypeMeta fields and then create a KVPair.
	info := apiv2.NewClusterInformation()
	info.ObjectMeta.Name = t.ObjectMeta.Name
	info.ObjectMeta.Namespace = t.ObjectMeta.Namespace
	info.Spec = t.Spec
	return &model.KVPair{
		Key: model.ResourceKey{
			Name:      t.ObjectMeta.Name,
			Namespace: t.ObjectMeta.Namespace,
			Kind:      apiv2.KindClusterInformation,
		},
		Value:    info,
		Revision: t.ObjectMeta.ResourceVersion,
	}, nil
}

func (c ClusterInfoConverter) FromKVPair(kvp *model.KVPair) (Resource, error) {
	v := kvp.Value.(*apiv2.ClusterInformation)

	return &apiv2.ClusterInformation{
		ObjectMeta: metav1.ObjectMeta{
			Name:            v.ObjectMeta.Name,
			Namespace:       v.ObjectMeta.Namespace,
			ResourceVersion: kvp.Revision,
		},
		Spec: v.Spec,
	}, nil
}
