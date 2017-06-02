package thirdparty

import (
	"encoding/json"

	"github.com/projectcalico/libcalico-go/lib/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// SystemNetworkPolicy is the ThirdPartyResource definition of a Calico Policy resource in
// the Kubernetes API.
type SystemNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ObjectMeta `json:"metadata"`
	Spec            api.PolicySpec    `json:"spec"`
}

// SystemNetworkPolicyList is a list of SystemNetworkPolicy resources.
type SystemNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ListMeta       `json:"metadata"`
	Items           []SystemNetworkPolicy `json:"items"`
}

// GetObjectKind returns the kind of this object.  Required to satisfy Object interface
func (e *SystemNetworkPolicy) GetObjectKind() schema.ObjectKind {
	return &e.TypeMeta
}

// GetOjbectMeta returns the object metadata of this object. Required to satisfy ObjectMetaAccessor interface
func (e *SystemNetworkPolicy) GetObjectMeta() metav1.Object {
	return &e.Metadata
}

// GetObjectKind returns the kind of this object. Required to satisfy Object interface
func (el *SystemNetworkPolicyList) GetObjectKind() schema.ObjectKind {
	return &el.TypeMeta
}

// GetListMeta returns the list metadata of this object. Required to satisfy ListMetaAccessor interface
func (el *SystemNetworkPolicyList) GetListMeta() metav1.List {
	return &el.Metadata
}

// The code below is used only to work around a known problem with third-party
// resources and ugorji. If/when these issues are resolved, the code below
// should no longer be required.

type SystemNetworkPolicyListCopy SystemNetworkPolicyList
type SystemNetworkPolicyCopy SystemNetworkPolicy

func (g *SystemNetworkPolicy) UnmarshalJSON(data []byte) error {
	tmp := SystemNetworkPolicyCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := SystemNetworkPolicy(tmp)
	*g = tmp2
	return nil
}

func (l *SystemNetworkPolicyList) UnmarshalJSON(data []byte) error {
	tmp := SystemNetworkPolicyListCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := SystemNetworkPolicyList(tmp)
	*l = tmp2
	return nil
}
