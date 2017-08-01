package converter

import (
	"fmt"
	"github.com/projectcalico/libcalico-go/lib/api"
	log "github.com/sirupsen/logrus"
	k8sApiV1 "k8s.io/client-go/pkg/api/v1"
	"reflect"
)

// ProfileNameFormat Format used by policy controller to name Calico profiles
const ProfileNameFormat = "ns.projectcalico.org/"

// profileLabelFormat Format used by policy controller to label Calico profiles
const profileLabelFormat = "k8s_ns/label/"

type namespaceConverter struct {
}

// NewNamespaceConverter Constructor for namespaceConverter
func NewNamespaceConverter() Converter {
	return &namespaceConverter{}
}
func (p *namespaceConverter) Convert(k8sObj interface{}) (interface{}, error) {
	if reflect.TypeOf(k8sObj).String() != "*v1.Namespace" {
		log.Fatalf("can not convert object %#v to calico profile. Object is not of type *v1.Namespace", k8sObj)
	}

	namespace := k8sObj.(*k8sApiV1.Namespace)
	profile := api.NewProfile()

	name := fmt.Sprintf(ProfileNameFormat+"%s", namespace.ObjectMeta.Name)
	
	// Generate the labels to apply to the profile, using a special prefix
	// to indicate that these are the labels from the parent Kubernetes Namespace.
	labels := map[string]string{}

	for k, v := range namespace.ObjectMeta.Labels {
		labels[fmt.Sprintf(profileLabelFormat+"%s", k)] = v
	}

	profile.Metadata.Name = name
	profile.Metadata.Labels = labels
	profile.Spec = api.ProfileSpec{
		IngressRules: []api.Rule{api.Rule{Action: "allow"}},
		EgressRules:  []api.Rule{api.Rule{Action: "allow"}},
	}

	return *profile, nil
}

// GetKey returns name of the namespace as key.
func (p *namespaceConverter) GetKey(obj interface{}) string {

	if reflect.TypeOf(obj) != reflect.TypeOf(api.Profile{}) {
		log.Fatalf("can not construct key for object %#v. Object is not of type api.WorkloadEndpoint", obj)
	}
	profile := obj.(api.Profile)
	return profile.Metadata.Name
}
