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
	"encoding/json"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

const (
	labelsAnnotation      = "projectcalico.org/labels"
	annotationsAnnotation = "projectcalico.org/annotations"
)

// Interface that all Kubernetes and Calico resources implement.
type Resource interface {
	runtime.Object
	metav1.ObjectMetaAccessor
}

// Interface that all Kubernetes and Calico resource lists implement.
type ResourceList interface {
	runtime.Object
	metav1.ListMetaAccessor
}

// Function signature for conversion function to convert a K8s resouce to a
// KVPair equivalent.
type ConvertK8sResourceToKVPair func(Resource) (*model.KVPair, error)

// Store Calico Metadata in the k8s resource annotations for non-CRD backed resources.
// Currently this just stores Annotations and Labels and drops all other metadata
// attributes.
func SetK8sAnnotationsFromCalicoMetadata(k8sRes Resource, calicoRes Resource) {
	a := k8sRes.GetObjectMeta().GetAnnotations()
	if a == nil {
		a = make(map[string]string)
	}
	if labels := calicoRes.GetObjectMeta().GetLabels(); len(labels) > 0 {
		if lann, err := json.Marshal(labels); err != nil {
			log.WithError(err).Warning("unable to store labels as an annotation")
		} else {
			a[labelsAnnotation] = string(lann)
		}
	}
	if annotations := calicoRes.GetObjectMeta().GetAnnotations(); len(annotations) > 0 {
		if aann, err := json.Marshal(annotations); err != nil {
			log.WithError(err).Warning("unable to store annotations as an annotation")
		} else {
			a[annotationsAnnotation] = string(aann)
		}
	}
	k8sRes.GetObjectMeta().SetAnnotations(a)
}

// Extract the Calico resource Metadata from the k8s resource annotations for non-CRD
// backed resources.  This extracts the Annotations and Labels stored as a annotation,
// and fills in the CreationTimestamp and UID from the k8s resource.
func SetCalicoMetadataFromK8sAnnotations(calicoRes Resource, k8sRes Resource) {
	com := calicoRes.GetObjectMeta()
	kom := k8sRes.GetObjectMeta()
	com.SetResourceVersion(kom.GetResourceVersion())
	com.SetCreationTimestamp(kom.GetCreationTimestamp())
	a := kom.GetAnnotations()
	if a == nil {
		return
	}

	if lann, ok := a[labelsAnnotation]; ok {
		var labels map[string]string
		if err := json.Unmarshal([]byte(lann), &labels); err != nil {
			log.WithError(err).Warning("unable to parse labels annotation")
		} else {
			com.SetLabels(labels)
		}
	}
	if aann, ok := a[annotationsAnnotation]; ok {
		var annotations map[string]string
		if err := json.Unmarshal([]byte(aann), &annotations); err != nil {
			log.WithError(err).Warning("unable to parse annotations annotation")
		} else {
			com.SetAnnotations(annotations)
		}
	}
}
