// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package client_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"errors"
	"os"

	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/client"
)

var _ = Describe("Client config tests", func() {

	// Data to test ETCD parameters
	data1 := `
apiVersion: v1
kind: calicoApiConfig
spec:
  etcdEndpoints: https://1.2.3.4:1234,https://10.20.30.40:1234
  etcdUsername: bar
  etcdPassword: baz
  etcdKeyFile: foo
  etcdCertFile: foobar
  etcdCACertFile: foobarbaz
`
	cfg1data := api.NewCalicoAPIConfig()
	cfg1data.Spec = api.CalicoAPIConfigSpec{
		DatastoreType: api.EtcdV2,
		EtcdConfig: api.EtcdConfig{
			EtcdEndpoints:  "https://1.2.3.4:1234,https://10.20.30.40:1234",
			EtcdUsername:   "bar",
			EtcdPassword:   "baz",
			EtcdKeyFile:    "foo",
			EtcdCertFile:   "foobar",
			EtcdCACertFile: "foobarbaz",
		},
	}

	// Data to test ETCD SRV parameter
	data2 := `
apiVersion: v1
kind: calicoApiConfig
spec:
  etcdDiscoverySrv: example.com
`
	cfg2data := api.NewCalicoAPIConfig()
	cfg2data.Spec = api.CalicoAPIConfigSpec{
		DatastoreType: api.EtcdV2,
		EtcdConfig:    api.EtcdConfig{EtcdDiscoverySrv: "example.com"},
	}

	// Data to test k8s parameters
	data3 := `
apiVersion: v1
kind: calicoApiConfig
metadata:
spec:
  kubeconfig: filename
  k8sAPIEndpoint: bar
  k8sCertFile: baz
  k8sKeyFile: foo
  k8sCAFile: foobar
  k8sAPIToken: foobarbaz
`
	cfg3data := api.NewCalicoAPIConfig()
	cfg3data.Spec = api.CalicoAPIConfigSpec{
		DatastoreType: api.EtcdV2,
		KubeConfig: api.KubeConfig{
			Kubeconfig:     "filename",
			K8sAPIEndpoint: "bar",
			K8sCertFile:    "baz",
			K8sKeyFile:     "foo",
			K8sCAFile:      "foobar",
			K8sAPIToken:    "foobarbaz",
		},
	}

	// Bad data samples.
	data4 := `
apiVersion: v2
kind: calicoApiConfig
`
	data5 := `
apiVersion: v1
kind: notCalicoApiConfig
`

	// Environments to test ETCD parameters
	env1 := map[string]string{
		"APIV1_ETCD_ENDPOINTS":    "https://1.2.3.4:1234,https://10.20.30.40:1234",
		"APIV1_ETCD_USERNAME":     "bar",
		"APIV1_ETCD_PASSWORD":     "baz",
		"APIV1_ETCD_KEY_FILE":     "foo",
		"APIV1_ETCD_CERT_FILE":    "foobar",
		"APIV1_ETCD_CA_CERT_FILE": "foobarbaz",
	}
	cfg1env := api.NewCalicoAPIConfig()
	cfg1env.Spec = api.CalicoAPIConfigSpec{
		DatastoreType: api.EtcdV2,
		EtcdConfig: api.EtcdConfig{
			EtcdScheme:     "",
			EtcdAuthority:  "",
			EtcdEndpoints:  "https://1.2.3.4:1234,https://10.20.30.40:1234",
			EtcdUsername:   "bar",
			EtcdPassword:   "baz",
			EtcdKeyFile:    "foo",
			EtcdCertFile:   "foobar",
			EtcdCACertFile: "foobarbaz",
		},
	}

	// Environments to test k8s parameters
	env2 := map[string]string{
		"APIV1_DATASTORE_TYPE":   string(api.Kubernetes),
		"APIV1_KUBECONFIG":       "filename",
		"APIV1_K8S_API_ENDPOINT": "bar1",
		"APIV1_K8S_CERT_FILE":    "baz1",
		"APIV1_K8S_KEY_FILE":     "foo1",
		"APIV1_K8S_CA_FILE":      "foobar1",
		"APIV1_K8S_API_TOKEN":    "foobarbaz1", // Ignored due to security reasons
	}
	cfg2env := api.NewCalicoAPIConfig()
	cfg2env.Spec = api.CalicoAPIConfigSpec{
		DatastoreType: api.Kubernetes,
		EtcdConfig: api.EtcdConfig{
			EtcdScheme:    "",
			EtcdAuthority: "",
		},
		KubeConfig: api.KubeConfig{
			Kubeconfig:     "filename",
			K8sAPIEndpoint: "bar1",
			K8sCertFile:    "baz1",
			K8sKeyFile:     "foo1",
			K8sCAFile:      "foobar1",
			K8sAPIToken:    "",
		},
	}

	// Environments should work with CALICO_ prefix too.
	env3 := map[string]string{
		"CALICO_APIV1_ETCD_AUTHORITY": "123.123.123.123:2344",
		"CALICO_APIV1_ETCD_USERNAME":  "userbar",
		"CALICO_APIV1_ETCD_PASSWORD":  "passbaz",
	}
	cfg3env := api.NewCalicoAPIConfig()
	cfg3env.Spec = api.CalicoAPIConfigSpec{
		DatastoreType: api.EtcdV2,
		EtcdConfig: api.EtcdConfig{
			EtcdScheme:    "",
			EtcdAuthority: "123.123.123.123:2344",
			EtcdUsername:  "userbar",
			EtcdPassword:  "passbaz",
		},
	}

	// Environments to test k8s parameters (preferential naming)
	env4 := map[string]string{
		"APIV1_DATASTORE_TYPE":    string(api.Kubernetes),
		"APIV1_KUBECONFIG":        "filename",
		"CALICO_APIV1_KUBECONFIG": "filename-preferred",
	}
	cfg4env := api.NewCalicoAPIConfig()
	cfg4env.Spec = api.CalicoAPIConfigSpec{
		DatastoreType: api.Kubernetes,
		EtcdConfig: api.EtcdConfig{
			EtcdScheme:    "",
			EtcdAuthority: "",
		},
		KubeConfig: api.KubeConfig{
			Kubeconfig: "filename-preferred",
		},
	}

	// Environments to test ETCD SRV parameter
	env5 := map[string]string{
		"APIV1_ETCD_DISCOVERY_SRV": "example.com",
	}
	cfg5env := api.NewCalicoAPIConfig()
	cfg5env.Spec = api.CalicoAPIConfigSpec{
		DatastoreType: api.EtcdV2,
		EtcdConfig: api.EtcdConfig{
			EtcdScheme:       "",
			EtcdAuthority:    "",
			EtcdEndpoints:    "",
			EtcdDiscoverySrv: "example.com",
		},
	}

	DescribeTable("Load client config",
		func(data string, expected *api.CalicoAPIConfig, expectedErr error) {
			By("Loading client config and checking results")
			loaded, err := client.LoadClientConfigFromBytes([]byte(data))
			if expectedErr == nil {
				Expect(*loaded).To(Equal(*expected))
				Expect(err).To(BeNil())
			} else {
				Expect(loaded).To(BeNil())
				Expect(err).To(Equal(expectedErr))
			}
		},

		Entry("valid etcd configuration", data1, cfg1data, nil),
		Entry("valid etcd SRV configuration", data2, cfg2data, nil),
		Entry("valid k8s configuration", data3, cfg3data, nil),
		Entry("invalid version", data4, nil, errors.New("invalid config file: unknown APIVersion 'v2'")),
		Entry("invalid kind", data5, nil, errors.New("invalid config file: expected kind 'calicoApiConfig', got 'notCalicoApiConfig'")),
	)

	DescribeTable("Load client config by environment",
		func(envs map[string]string, expected *api.CalicoAPIConfig, expectedErr error) {
			By("Loading client config and checking results")
			// Set environments, load the config and then unset the environments.
			for k, v := range envs {
				os.Setenv(k, v)
			}
			loaded, err := client.LoadClientConfig("")
			for k := range envs {
				os.Unsetenv(k)
			}

			// Note that the environment vars always initialize the
			// etcd scheme and authority, so set these if they are
			// not already set.
			if expectedErr == nil {
				Expect(*loaded).To(Equal(*expected))
				Expect(err).To(BeNil())
			} else {
				Expect(loaded).To(BeNil())
				Expect(err).To(Equal(expectedErr))
			}
		},

		Entry("valid etcd configuration", env1, cfg1env, nil),
		Entry("valid k8s configuration", env2, cfg2env, nil),
		Entry("valid etcd configuration with CALICO_ prefix", env3, cfg3env, nil),
		Entry("valid k8s configuration (preferential naming)", env4, cfg4env, nil),
		Entry("valid etcd SRV configuration", env5, cfg5env, nil),
	)
})
