package testutils

import (
	"fmt"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/etcd"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s"

	. "github.com/onsi/ginkgo"
)

const (
	DatastoreEtcdV2 = 1 << iota
	DatastoreK8s
)

// E2eDatastoreDescribe is a replacement for ginkgo.Describe which invokes Describe
// multiple times for one or more different datastore drivers - passing in the
// Calico API configuration as a parameter to the test function.  This allows
// easy construction of end-to-end tests covering multiple different datastore
// drivers.
//
// The *datastores* parameter is a bit-wise OR of the required datastore drivers
// that will be tested.
func E2eDatastoreDescribe(description string, datastores int, body func(config api.CalicoAPIConfig)) bool {

	if datastores & DatastoreEtcdV2 != 0 {
		Describe(fmt.Sprintf("%s (etcdv2 backend)", description),
			func() {
				body(api.CalicoAPIConfig{
					Spec: api.CalicoAPIConfigSpec{
						DatastoreType: api.EtcdV2,
						EtcdConfig: etcd.EtcdConfig{
							EtcdEndpoints: "http://127.0.0.1:2379",
						},
					},
				})
			})
	}

	if datastores & DatastoreK8s != 0 {
		Describe(fmt.Sprintf("%s (kubernetes backend)", description),
			func() {
				body(api.CalicoAPIConfig{
					Spec: api.CalicoAPIConfigSpec{
						DatastoreType: api.Kubernetes,
						KubeConfig: k8s.KubeConfig{
							K8sAPIEndpoint: "http://localhost:8080",
						},
					},
				})
			})
	}

	return true
}
