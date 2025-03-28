// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.

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
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/json"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

const (
	labelsAnnotation      = "projectcalico.org/labels"
	annotationsAnnotation = "projectcalico.org/annotations"
	metadataAnnotation    = "projectcalico.org/metadata"
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

// Function signature for conversion function to convert a K8s resource to a
// KVPair equivalent.
type (
	ConvertK8sResourceToKVPair  func(Resource) (*model.KVPair, error)
	ConvertK8sResourceToKVPairs func(Resource) ([]*model.KVPair, error)
)

// ConvertK8sResourceOneToOneAdapter converts a ConvertK8sResourceToKVPair function to a ConvertK8sResourceToKVPairs function
func ConvertK8sResourceOneToOneAdapter(oneToOne ConvertK8sResourceToKVPair) ConvertK8sResourceToKVPairs {
	return func(r Resource) ([]*model.KVPair, error) {
		kvp, err := oneToOne(r)
		if err != nil {
			return nil, err
		} else if kvp != nil {
			return []*model.KVPair{kvp}, nil
		}

		return nil, nil
	}
}

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
	} else {
		// There are no Calico labels - nil out the k8s res.
		delete(a, labelsAnnotation)
	}
	if annotations := calicoRes.GetObjectMeta().GetAnnotations(); len(annotations) > 0 {
		if aann, err := json.Marshal(annotations); err != nil {
			log.WithError(err).Warning("unable to store annotations as an annotation")
		} else {
			a[annotationsAnnotation] = string(aann)
		}
	} else {
		// There are no Calico annotations - nil out the k8s res.
		delete(a, annotationsAnnotation)
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
	com.SetUID(kom.GetUID())
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

// Store Calico Metadata in the k8s resource annotations for CRD backed resources.
// This should store all Metadata except for those stored in Annotations and Labels and
// store them in annotations.
func ConvertCalicoResourceToK8sResource(resIn Resource) (Resource, error) {
	rom := resIn.GetObjectMeta()

	resKind := resIn.GetObjectKind().GroupVersionKind().Kind

	// Make sure to remove data that is passed to Kubernetes so it is not duplicated in
	// the metadata annotation.
	romCopy := &metav1.ObjectMeta{}
	rom.(*metav1.ObjectMeta).DeepCopyInto(romCopy)
	romCopy.Namespace = ""
	romCopy.ResourceVersion = ""
	romCopy.UID = ""
	if resKind != apiv3.KindGlobalNetworkPolicy &&
		resKind != apiv3.KindNetworkPolicy &&
		resKind != apiv3.KindStagedNetworkPolicy &&
		resKind != apiv3.KindStagedGlobalNetworkPolicy {
		// We only want to store the name for network policies, all other resources should not have the name stored in metadata annotations
		romCopy.Name = ""
	}

	// Any projectcalico.org/v3 owners need to be translated to their equivalent crd.projectcalico.org/v1 representations.
	// They will be converted back on read.
	var err error
	var refs []metav1.OwnerReference
	for _, ref := range romCopy.GetOwnerReferences() {
		// Skip any owners that aren't projectcalico.org/v3. These do not need translation.
		if ref.APIVersion == "projectcalico.org/v3" {
			// Update the UID and API version to indicate that the referenced UID is valid
			// on the crd.projectcalico.org/v1 API.
			ref.APIVersion = "crd.projectcalico.org/v1"
			ref.UID, err = conversion.ConvertUID(ref.UID)
			if err != nil {
				return nil, err
			}
		}
		refs = append(refs, ref)
	}
	romCopy.SetOwnerReferences(refs)

	// Marshal the data and store the json representation in the annotations.
	metadataBytes, err := json.Marshal(romCopy)
	if err != nil {
		return nil, err
	}

	annotations := make(map[string]string)
	annotations[metadataAnnotation] = string(metadataBytes)

	// Make sure to clear out all of the Calico Metadata out of the ObjectMeta except for
	// Name, Namespace, ResourceVersion, UID, and Annotations (built above).
	meta := &metav1.ObjectMeta{}
	meta.Name = rom.GetName()
	meta.Namespace = rom.GetNamespace()
	meta.ResourceVersion = rom.GetResourceVersion()

	switch resKind {
	// For NetworkPolicy and GlobalNetworkPolicy, we need to prefix the name with the tier name.
	// This ensures two policies with the same name, but in different tiers, do not resolve to the same backing object.
	case apiv3.KindGlobalNetworkPolicy:
		policy := resIn.(*apiv3.GlobalNetworkPolicy)
		backendName := names.TieredPolicyName(policy.Name)
		meta.Name = backendName
	case apiv3.KindNetworkPolicy:
		policy := resIn.(*apiv3.NetworkPolicy)
		backendName := names.TieredPolicyName(policy.Name)
		meta.Name = backendName
	case apiv3.KindStagedGlobalNetworkPolicy:
		policy := resIn.(*apiv3.StagedGlobalNetworkPolicy)
		backendName := names.TieredPolicyName(policy.Name)
		meta.Name = backendName
	case apiv3.KindStagedNetworkPolicy:
		policy := resIn.(*apiv3.StagedNetworkPolicy)
		backendName := names.TieredPolicyName(policy.Name)
		meta.Name = backendName
	}

	// Explicitly nil out the labels on the underlying object so that they are not duplicated.
	// We make an exception for projectcalico.org/ labels, which we own and may use on the v1 API.
	var v1Labels map[string]string
	for k, v := range rom.GetLabels() {
		if isOurs(k) {
			if v1Labels == nil {
				v1Labels = map[string]string{}
			}
			v1Labels[k] = v
		}
	}
	meta.Labels = v1Labels

	// Also maintain any annotations that we own.
	for k, v := range rom.GetAnnotations() {
		if isOurs(k) {
			annotations[k] = v
		}
	}

	if rom.GetUID() != "" {
		uid, err := conversion.ConvertUID(rom.GetUID())
		if err != nil {
			return nil, err
		}
		meta.UID = uid
	}
	resOut := resIn.DeepCopyObject().(Resource)
	romOut := resOut.GetObjectMeta()
	meta.DeepCopyInto(romOut.(*metav1.ObjectMeta))
	romOut.SetAnnotations(annotations)

	return resOut, nil
}

func isOurs(k string) bool {
	return strings.Contains(k, "projectcalico.org/") || strings.Contains(k, "operator.tigera.io/")
}

// Retrieve all of the Calico Metadata from the k8s resource annotations for CRD backed
// resources. This should remove the relevant Calico Metadata annotation when it has finished.
func ConvertK8sResourceToCalicoResource(res Resource) error {
	rom := res.GetObjectMeta()
	annotations := rom.GetAnnotations()

	if rom.GetUID() != "" {
		// We NEVER want to use the UID from the underlying CR so that we can guarantee uniqueness.
		// So, always generate a new one deterministically so that the UID is correct even
		// if there is no metadata annotation present.
		uid, err := conversion.ConvertUID(rom.GetUID())
		if err != nil {
			return err
		}
		rom.SetUID(uid)
	}

	if len(annotations) == 0 {
		// Make no changes if there are no annotations to read Calico Metadata out of.
		return nil
	}
	if _, ok := annotations[metadataAnnotation]; !ok {
		// No changes if there are no annotations stored on the Resource.
		return nil
	}

	meta := &metav1.ObjectMeta{}
	err := json.Unmarshal([]byte(annotations[metadataAnnotation]), meta)
	if err != nil {
		return err
	}

	// Any crd.projectcalico.org/v1 owners need to be translated to their equivalent projectcalico.org/v3 representations.
	var refs []metav1.OwnerReference
	for _, ref := range meta.GetOwnerReferences() {
		// Skip any owners that aren't crd.projectcalico.org/v1. These do not need translation.
		// We also need to translate projectcalico.org/v3 owners, if any, since these represent resources that were
		// written prior to the UID conversion fix.
		if ref.APIVersion == "crd.projectcalico.org/v1" || ref.APIVersion == "projectcalico.org/v3" {
			// Update the UID and API version to indicate that the referenced UID is valid
			// on the projectcalico.org/v3 API.
			ref.APIVersion = "projectcalico.org/v3"
			ref.UID, err = conversion.ConvertUID(ref.UID)
			if err != nil {
				return err
			}
		}
		refs = append(refs, ref)
	}
	meta.SetOwnerReferences(refs)

	// Clear out the annotations
	delete(annotations, metadataAnnotation)
	if len(annotations) == 0 {
		annotations = nil
	}

	// Start with the original labels and annotations from the v1 object, and merge in the values from the metadata
	// annotation. This logic helps maintain labels and annotations on upgrade from older versions, where they were stored
	// directly in the metadata of the v1 CRD.
	labels := rom.GetLabels()
	for k, v := range meta.GetLabels() {
		if labels == nil {
			labels = make(map[string]string)
		}
		labels[k] = v
	}
	for k, v := range meta.GetAnnotations() {
		if annotations == nil {
			annotations = make(map[string]string)
		}
		annotations[k] = v
	}

	// Manually write in the data not stored in the annotations: Name, Namespace, ResourceVersion,
	// so that they do not get overwritten.
	if meta.Name == "" {
		// We store the original v3 Name in our annotation when writing NetworkPolicy and GNP objects. If that's present, use it.
		// Otherwise, fill in the name from the underlying CRD.
		meta.Name = rom.GetName()
	}
	meta.Namespace = rom.GetNamespace()
	meta.ResourceVersion = rom.GetResourceVersion()
	meta.UID = rom.GetUID()
	meta.Labels = labels
	meta.Annotations = annotations

	// If no creation timestamp was stored in the metadata annotation, use the one from the CR.
	// The timestamp is normally set in the clientv3 code. However, for objects that bypass
	// the v3 client (e.g., IPAM), we won't have generated a creation timestamp and the field
	// is required on update calls.
	if meta.GetCreationTimestamp().Time.IsZero() {
		meta.SetCreationTimestamp(rom.GetCreationTimestamp())
	}

	// If no creation timestamp was stored in the metadata annotation, use the one from the CR.
	// The timestamp is normally set in the clientv3 code. However, for objects that bypass
	// the v3 client (e.g., IPAM), we won't have generated a creation timestamp and the field
	// is required on update calls.
	if meta.GetCreationTimestamp().Time.IsZero() {
		meta.SetCreationTimestamp(rom.GetCreationTimestamp())
	}

	// Overwrite the K8s metadata with the Calico metadata.
	meta.DeepCopyInto(rom.(*metav1.ObjectMeta))

	return nil
}

func watchOptionsToK8sListOptions(wo api.WatchOptions) metav1.ListOptions {
	return metav1.ListOptions{
		ResourceVersion:     wo.Revision,
		Watch:               true,
		AllowWatchBookmarks: wo.AllowWatchBookmarks,
	}
}
