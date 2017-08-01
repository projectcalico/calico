package converter

import (
	"fmt"
	"github.com/projectcalico/libcalico-go/lib/api"
	log "github.com/sirupsen/logrus"
	k8sApiV1 "k8s.io/client-go/pkg/api/v1"
	"reflect"
)

// Label which represents the namespace a given pod belongs to.
const k8sNamespaceLabel = "calico/k8s_ns"

type podConverter struct {
}

// NewPodConverter Constructor for podConverter
func NewPodConverter() Converter {
	return &podConverter{}
}
func (p *podConverter) Convert(k8sObj interface{}) (interface{}, error) {
	if reflect.TypeOf(k8sObj) != reflect.TypeOf(&k8sApiV1.Pod{}) {
		log.Fatalf("can not convert object %#v to workloadEndpoint. Object is not of type *v1.Pod", k8sObj)
	}

	pod := k8sObj.(*k8sApiV1.Pod)
	endpoint := api.NewWorkloadEndpoint()

	endpoint.Metadata.Workload = fmt.Sprintf("%s.%s", pod.Namespace, pod.Name)
	endpoint.Metadata.Labels = pod.ObjectMeta.Labels

	// Add a special label for the Kubernetes namespace.  This is used
	// by selector-based policies to select all pods in a given namespace.
	endpoint.Metadata.Labels[k8sNamespaceLabel] = pod.Namespace

	return *endpoint, nil
}

// GetKey returns workloadID of the object as key.
// workloadID is namespace.name for kubernetes pod.
func (p *podConverter) GetKey(obj interface{}) string {
	if reflect.TypeOf(obj) != reflect.TypeOf(api.WorkloadEndpoint{}) {
		log.Fatalf("can not construct key for object %#v. Object is not of type api.WorkloadEndpoint", obj)
	}
	endpoint := obj.(api.WorkloadEndpoint)
	return endpoint.Metadata.Workload
}
