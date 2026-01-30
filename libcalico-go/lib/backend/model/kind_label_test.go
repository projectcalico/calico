package model_test

import (
	"maps"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	. "github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = DescribeTable(
	"add kind label to intended resources",
	func(kvp *KVPair, kind string) {
		oldLabels := getLabels(kvp)
		AddKindLabel(kvp)
		newLabels := getLabels(kvp)

		Expect(newLabels).To(HaveKey(KindLabel))
		Expect(newLabels[KindLabel]).To(Equal(kind))

		delete(newLabels, KindLabel)
		if len(newLabels) == 0 {
			newLabels = nil
		}

		Expect(oldLabels).To(Equal(newLabels))
	},
	Entry(
		"GlobalNetworkSet should have the label",
		&KVPair{
			Key: ResourceKey{
				Kind: "GlobalNetworkSet",
				Name: "gns",
			},
			Value: apiv3.GlobalNetworkSet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "gns",
				},
				Spec: apiv3.GlobalNetworkSetSpec{},
			},
		},
		apiv3.KindGlobalNetworkSet,
	),
	Entry(
		"GlobalNetworkSet even as a pointer should have the label",
		&KVPair{
			Key: ResourceKey{
				Kind: "GlobalNetworkSet",
				Name: "gns",
			},
			Value: &apiv3.GlobalNetworkSet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "gns",
				},
				Spec: apiv3.GlobalNetworkSetSpec{},
			},
		},
		apiv3.KindGlobalNetworkSet,
	),
	Entry(
		"NetworkSet should have the label",
		&KVPair{
			Key: ResourceKey{
				Kind: "NetworkSet",
				Name: "ns",
			},
			Value: apiv3.NetworkSet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ns",
					Labels: map[string]string{
						"x": "y",
					},
				},
				Spec: apiv3.NetworkSetSpec{},
			},
		},
		apiv3.KindNetworkSet,
	),
	Entry(
		"NetworkSet even as a pointer should have the label",
		&KVPair{
			Key: ResourceKey{
				Kind: "NetworkSet",
				Name: "ns",
			},
			Value: &apiv3.NetworkSet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ns",
					Labels: map[string]string{
						"x": "y",
					},
				},
				Spec: apiv3.NetworkSetSpec{},
			},
		},
		apiv3.KindNetworkSet,
	),
	Entry(
		"HostEndpoints should have the label",
		&KVPair{
			Key: ResourceKey{
				Kind: "HostEndpoint",
				Name: "ns",
			},
			Value: apiv3.HostEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hep",
					Labels: map[string]string{
						"x": "y",
						"a": "b",
					},
				},
				Spec: apiv3.HostEndpointSpec{},
			},
		},
		apiv3.KindHostEndpoint,
	),
	Entry(
		"HostEndpoint even as a pointer should have the label",
		&KVPair{
			Key: ResourceKey{
				Kind: "HostEndpoint",
				Name: "ns",
			},
			Value: &apiv3.HostEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hep",
					Labels: map[string]string{
						"x": "y",
						"a": "b",
					},
				},
				Spec: apiv3.HostEndpointSpec{},
			},
		},
		apiv3.KindHostEndpoint,
	),

	Entry(
		"WorkloadEndpoints should have the label",
		&KVPair{
			Key: ResourceKey{
				Kind: "WorkloadEndpoint",
				Name: "wep",
			},
			Value: libapiv3.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name: "wep",
					Labels: map[string]string{
						"x": "y",
						"a": "b",
					},
				},
				Spec: libapiv3.WorkloadEndpointSpec{},
			},
		},
		libapiv3.KindWorkloadEndpoint,
	),
	Entry(
		"WorkloadEndpoints even as a pointer should have the label",
		&KVPair{
			Key: ResourceKey{
				Kind: "WorkloadEndpoint",
				Name: "wep",
			},
			Value: &libapiv3.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name: "wep",
					Labels: map[string]string{
						"x": "y",
						"a": "b",
					},
				},
				Spec: libapiv3.WorkloadEndpointSpec{},
			},
		},
		libapiv3.KindWorkloadEndpoint,
	),
)

var _ = DescribeTable(
	"delete kind label from intended resources",
	func(kvp *KVPair) {
		// resource := kvp.Value.(metav1.ObjectMetaAccessor)
		oldLabels := getLabels(kvp)
		RemoveKindLabel(kvp)
		newLabels := getLabels(kvp)

		delete(oldLabels, model.KindLabel)
		// if len(oldLabels) == 0 {
		// 	oldLabels = nil
		// }
		Expect(newLabels).To(Equal(oldLabels))
	},
	Entry(
		"GlobalNetworkSet should have label deleted",
		&KVPair{
			Key: ResourceKey{
				Kind: "GlobalNetworkSet",
				Name: "gns",
			},
			Value: apiv3.GlobalNetworkSet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "gns",
					Labels: map[string]string{
						model.KindLabel: apiv3.KindGlobalNetworkSet,
					},
				},
				Spec: apiv3.GlobalNetworkSetSpec{},
			},
		},
	),
	Entry(
		"GlobalNetworkSet even as a pointer should have the label deleted",
		&KVPair{
			Key: ResourceKey{
				Kind: "GlobalNetworkSet",
				Name: "gns",
			},
			Value: &apiv3.GlobalNetworkSet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "gns",
					Labels: map[string]string{
						model.KindLabel: apiv3.KindGlobalNetworkSet,
					},
				},
				Spec: apiv3.GlobalNetworkSetSpec{},
			},
		},
	),
	Entry(
		"NetworkSet should have the label deleted",
		&KVPair{
			Key: ResourceKey{
				Kind: "NetworkSet",
				Name: "ns",
			},
			Value: apiv3.NetworkSet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ns",
					Labels: map[string]string{
						"x":             "y",
						model.KindLabel: apiv3.KindNetworkSet,
					},
				},
				Spec: apiv3.NetworkSetSpec{},
			},
		},
	),
	Entry(
		"NetworkSet even as a pointer should have the label deleted",
		&KVPair{
			Key: ResourceKey{
				Kind: "NetworkSet",
				Name: "ns",
			},
			Value: &apiv3.NetworkSet{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ns",
					Labels: map[string]string{
						"x":             "y",
						model.KindLabel: apiv3.KindNetworkSet,
					},
				},
				Spec: apiv3.NetworkSetSpec{},
			},
		},
	),
	Entry(
		"HostEndpoints should have the label deleted",
		&KVPair{
			Key: ResourceKey{
				Kind: "HostEndpoint",
				Name: "ns",
			},
			Value: apiv3.HostEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hep",
					Labels: map[string]string{
						"x":             "y",
						"a":             "b",
						model.KindLabel: apiv3.KindHostEndpoint,
					},
				},
				Spec: apiv3.HostEndpointSpec{},
			},
		},
	),
	Entry(
		"HostEndpoint even as a pointer should have the label deleted",
		&KVPair{
			Key: ResourceKey{
				Kind: "HostEndpoint",
				Name: "ns",
			},
			Value: &apiv3.HostEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hep",
					Labels: map[string]string{
						"x":             "y",
						"a":             "b",
						model.KindLabel: apiv3.KindHostEndpoint,
					},
				},
				Spec: apiv3.HostEndpointSpec{},
			},
		},
	),

	Entry(
		"WorkloadEndpoints should have the label deleted",
		&KVPair{
			Key: ResourceKey{
				Kind: "WorkloadEndpoint",
				Name: "wep",
			},
			Value: libapiv3.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name: "wep",
					Labels: map[string]string{
						"x":             "y",
						"a":             "b",
						model.KindLabel: libapiv3.KindWorkloadEndpoint,
					},
				},
				Spec: libapiv3.WorkloadEndpointSpec{},
			},
		},
	),
	Entry(
		"WorkloadEndpoints even as a pointer should have the label deleted",
		&KVPair{
			Key: ResourceKey{
				Kind: "WorkloadEndpoint",
				Name: "wep",
			},
			Value: &libapiv3.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name: "wep",
					Labels: map[string]string{
						"x":             "y",
						"a":             "b",
						model.KindLabel: libapiv3.KindWorkloadEndpoint,
					},
				},
				Spec: libapiv3.WorkloadEndpointSpec{},
			},
		},
	),
	Entry(
		"An intended resource (WorkloadEndpoint in this case) without the label should not behave abnormally",
		&KVPair{
			Key: ResourceKey{
				Kind: "WorkloadEndpoint",
				Name: "wep",
			},
			Value: &libapiv3.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name: "wep",
					Labels: map[string]string{
						"x": "y",
						"a": "b",
					},
				},
				Spec: libapiv3.WorkloadEndpointSpec{},
			},
		},
	),
)

var _ = DescribeTable(
	"attempting to add kind label to unintended resources (IPPool in this case)",
	func(kvp *KVPair) {
		// resource := kvp.Value.(metav1.ObjectMetaAccessor)
		oldLabels := getLabels(kvp)
		AddKindLabel(kvp)
		newLabels := getLabels(kvp)

		Expect(newLabels).To(Equal(oldLabels))
	},
	Entry(
		"IPPool should not have the label added",
		&KVPair{
			Key: ResourceKey{
				Kind: "IPPool",
				Name: "ippool-1",
			},
			Value: &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ippool-1",
					Labels: map[string]string{
						"x": "y",
					},
				},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.3.0/24",
				},
			},
		},
	),
)

var _ = DescribeTable(
	"attempting to delete kind label from unintended resources (IPPool in this case)",
	func(kvp *KVPair) {
		// resource := kvp.Value.(metav1.ObjectMetaAccessor)
		oldLabels := getLabels(kvp)
		AddKindLabel(kvp)
		newLabels := getLabels(kvp)

		Expect(newLabels).To(Equal(oldLabels))
	},
	Entry(
		"IPPool does not have the label, so deletion must not misbehave",
		&KVPair{
			Key: ResourceKey{
				Kind: "IPPool",
				Name: "ippool-1",
			},
			Value: &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ippool-1",
					Labels: map[string]string{
						"x": "y",
					},
				},
				Spec: apiv3.IPPoolSpec{
					CIDR: "1.2.3.0/24",
				},
			},
		},
	),
)

func getLabels(kvp *KVPair) map[string]string {
	var meta metav1.ObjectMetaAccessor

	switch resource := kvp.Value.(type) {
	case apiv3.GlobalNetworkSet, *apiv3.GlobalNetworkSet:
		meta = valueToPtr[apiv3.GlobalNetworkSet](resource)
	case *apiv3.NetworkSet, apiv3.NetworkSet:
		meta = valueToPtr[apiv3.NetworkSet](resource)
	case *apiv3.HostEndpoint, apiv3.HostEndpoint:
		meta = valueToPtr[apiv3.HostEndpoint](resource)
	case *libapiv3.WorkloadEndpoint, libapiv3.WorkloadEndpoint:
		meta = valueToPtr[libapiv3.WorkloadEndpoint](resource)

	case *apiv3.IPPool:
		meta = resource
	}
	return maps.Clone(meta.GetObjectMeta().GetLabels())
}

func valueToPtr[T interface{}](value interface{}) *T {
	switch r := value.(type) {
	case *T:
		return r
	case T:
		return &r
	default:
		return nil
	}
}
