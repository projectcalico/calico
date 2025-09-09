package model

import (
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const KindLabel = "projectcalico.org/kind"

// AddKindLabel adds "projectcalico.org/kind" to GlobalNetworkSet, NetworkSet, HostEndpoint
// and WorkloadEndpoint resources.
func AddKindLabel(kvp *KVPair) {
	if kvp == nil {
		return
	}

	var meta metav1.ObjectMetaAccessor
	var kind string

	switch resource := kvp.Value.(type) {
	case apiv3.GlobalNetworkSet, *apiv3.GlobalNetworkSet:
		meta = valuesToPtr[apiv3.GlobalNetworkSet](resource)
		kind = apiv3.KindGlobalNetworkSet
	case apiv3.NetworkSet, *apiv3.NetworkSet:
		meta = valuesToPtr[apiv3.NetworkSet](resource)
		kind = apiv3.KindNetworkSet
	case apiv3.HostEndpoint, *apiv3.HostEndpoint:
		meta = valuesToPtr[apiv3.HostEndpoint](resource)
		kind = apiv3.KindHostEndpoint
	case libapiv3.WorkloadEndpoint, *libapiv3.WorkloadEndpoint:
		meta = valuesToPtr[libapiv3.WorkloadEndpoint](resource)
		kind = libapiv3.KindWorkloadEndpoint
	default:
		return
	}

	appendLabel := func(labels map[string]string, kind string) map[string]string {
		if labels == nil {
			labels = map[string]string{}
		}
		labels[KindLabel] = kind
		return labels
	}

	labels := appendLabel(
		meta.GetObjectMeta().GetLabels(),
		kind,
	)
	meta.GetObjectMeta().SetLabels(labels)
	kvp.Value = meta
}

// RemoveKindLabel removes "projectcalico.org/kind" from GlobalNetworkSet, NetworkSet, HostEndpoint
// and WorkloadEndpoint resources.
// This function is useful to remove kind label before storing a resource in the datastore.
func RemoveKindLabel(kvp *KVPair) {
	if kvp == nil {
		return
	}

	var meta metav1.ObjectMetaAccessor

	switch resource := kvp.Value.(type) {
	case apiv3.GlobalNetworkSet, *apiv3.GlobalNetworkSet:
		meta = valuesToPtr[apiv3.GlobalNetworkSet](resource)
	case apiv3.NetworkSet, *apiv3.NetworkSet:
		meta = valuesToPtr[apiv3.NetworkSet](resource)
	case apiv3.HostEndpoint, *apiv3.HostEndpoint:
		meta = valuesToPtr[apiv3.HostEndpoint](resource)
	case libapiv3.WorkloadEndpoint, *libapiv3.WorkloadEndpoint:
		meta = valuesToPtr[libapiv3.WorkloadEndpoint](resource)
	default:
		return
	}

	meta.GetObjectMeta().GetLabels()
	labels := meta.GetObjectMeta().GetLabels()
	delete(labels, KindLabel)
	meta.GetObjectMeta().SetLabels(labels)
	kvp.Value = meta
}

// valuesToPtr will always return a pointer to the value provided.
// This is necessary to satisfy tests where non-pointers are provided to a model.KVPair.Value
func valuesToPtr[T any](value interface{}) *T {
	switch t := value.(type) {
	case T:
		return &t
	case *T:
		return t
	default:
		return nil
	}
}
