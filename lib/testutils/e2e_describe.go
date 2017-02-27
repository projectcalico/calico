package testutils

import (
	"fmt"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/etcd"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s"

	. "github.com/onsi/ginkgo"
)

const (
	ClientEtcdV2 = 1 << iota
	ClientK8s
)

// E2eDescribe is a replacement for ginkgo.Describe which invoke Describe
// multiple times for one or more different backend clients - passing in the
// Calico API configuration as a parameter to the test function.  This allows
// easy construction of end-to-end tests covering multiple different backends.
//
// The *clients* parameter is a bit-wise OR of the required client/backend
// types that will be tested.
func E2eDescribe(description string, clients int, body func(config api.CalicoAPIConfig)) bool {

	if clients&ClientEtcdV2 != 0 {
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

	if clients&ClientK8s != 0 {
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
