package thirdparty

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type GlobalConfigSpec struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type GlobalConfig struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ObjectMeta `json:"metadata"`

	Spec GlobalConfigSpec `json:"spec"`
}

type GlobalConfigList struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ListMeta `json:"metadata"`

	Items []GlobalConfig `json:"items"`
}

// Required to satisfy Object interface
func (e *GlobalConfig) GetObjectKind() schema.ObjectKind {
	return &e.TypeMeta
}

// Required to satisfy ObjectMetaAccessor interface
func (e *GlobalConfig) GetObjectMeta() metav1.Object {
	return &e.Metadata
}

// Required to satisfy Object interface
func (el *GlobalConfigList) GetObjectKind() schema.ObjectKind {
	return &el.TypeMeta
}

// Required to satisfy ListMetaAccessor interface
func (el *GlobalConfigList) GetListMeta() metav1.List {
	return &el.Metadata
}

// The code below is used only to work around a known problem with third-party
// resources and ugorji. If/when these issues are resolved, the code below
// should no longer be required.

type GlobalConfigListCopy GlobalConfigList
type GlobalConfigCopy GlobalConfig

func (g *GlobalConfig) UnmarshalJSON(data []byte) error {
	tmp := GlobalConfigCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := GlobalConfig(tmp)
	*g = tmp2
	return nil
}

func (l *GlobalConfigList) UnmarshalJSON(data []byte) error {
	tmp := GlobalConfigListCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := GlobalConfigList(tmp)
	*l = tmp2
	return nil
}
