// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

const (
	IPReservationResourceName = "IPReservations"
	IPReservationCRDName      = "ipreservations.crd.projectcalico.org"
)

func NewIPReservationClient(c kubernetes.Interface, r rest.Interface) K8sResourceClient {
	return &customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            IPReservationCRDName,
		resource:        IPReservationResourceName,
		description:     "Calico IP Reservations",
		k8sResourceType: reflect.TypeOf(apiv3.IPReservation{}),
		k8sResourceTypeMeta: metav1.TypeMeta{
			Kind:       apiv3.KindIPReservation,
			APIVersion: apiv3.GroupVersionCurrent,
		},
		k8sListType:  reflect.TypeOf(apiv3.IPReservationList{}),
		resourceKind: apiv3.KindIPReservation,
	}
}
