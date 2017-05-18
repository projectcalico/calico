package thirdparty

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// IpPoolSpec is the specification of an IP Pool as represented in the Kubernetes
// ThirdPartyResource API.
type IpPoolSpec struct {
	// Value is a json encoded string which can be unmarshalled into a model.IPPool struct.
	Value string `json:"value"`
}

// IpPool is the ThirdPartyResource definition of an IPPool in the Kubernetes API.
type IpPool struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ObjectMeta `json:"metadata"`

	Spec IpPoolSpec `json:"spec"`
}

// IpPoolList is a list of IpPool resources.
type IpPoolList struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ListMeta `json:"metadata"`

	Items []IpPool `json:"items"`
}

// GetObjectKind returns the kind of this object.  Required to satisfy Object interface
func (e *IpPool) GetObjectKind() schema.ObjectKind {
	return &e.TypeMeta
}

// GetOjbectMeta returns the object metadata of this object. Required to satisfy ObjectMetaAccessor interface
func (e *IpPool) GetObjectMeta() metav1.Object {
	return &e.Metadata
}

// GetObjectKind returns the kind of this object. Required to satisfy Object interface
func (el *IpPoolList) GetObjectKind() schema.ObjectKind {
	return &el.TypeMeta
}

// GetListMeta returns the list metadata of this object. Required to satisfy ListMetaAccessor interface
func (el *IpPoolList) GetListMeta() metav1.List {
	return &el.Metadata
}

// The code below is used only to work around a known problem with third-party
// resources and ugorji. If/when these issues are resolved, the code below
// should no longer be required.

type IpPoolListCopy IpPoolList
type IpPoolCopy IpPool

func (g *IpPool) UnmarshalJSON(data []byte) error {
	tmp := IpPoolCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := IpPool(tmp)
	*g = tmp2
	return nil
}

func (l *IpPoolList) UnmarshalJSON(data []byte) error {
	tmp := IpPoolListCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := IpPoolList(tmp)
	*l = tmp2
	return nil
}
