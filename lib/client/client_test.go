// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

// Test operations involving node resources.  These tests test a variety of
// operations to check that each operation returns the expected data.  By
// writing and reading sets of node data we can check that the data is stored
// and round trips correctly.  Note that these tests do not actually test the
// format of the data as it is stored in the underlying datastore.
//
// The tests are designed to test standard, Update, Create, Apply, Get, List,
// and Delete operations in standard operational and failure scenarios -
// creating and modifying field values and checking that the values hold in
// subsequent queries.
//
// Read the test code for full details of the test.

package client_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/backend/etcd"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s"
	"errors"
	"os"
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
		EtcdConfig: etcd.EtcdConfig{
			EtcdEndpoints: "https://1.2.3.4:1234,https://10.20.30.40:1234",
			EtcdUsername: "bar",
			EtcdPassword: "baz",
			EtcdKeyFile: "foo",
			EtcdCertFile: "foobar",
			EtcdCACertFile: "foobarbaz",
		},
	}

	// Data to test k8s parameters
	data2 := `
apiVersion: v1
kind: calicoApiConfig
metadata:
spec:
  k8sKubeconfig: filename
  k8sServer: bar
  k8sClientCertificate: baz
  k8sClientKey: foo
  k8sCertificateAuthority: foobar
  k8sToken: foobarbaz
`
	cfg2data := api.NewCalicoAPIConfig()
	cfg2data.Spec = api.CalicoAPIConfigSpec{
		DatastoreType: api.EtcdV2,
		KubeConfig: k8s.KubeConfig{
			K8sKubeconfigFile: "filename",
			K8sServer: "bar",
			K8sClientCertificate: "baz",
			K8sClientKey: "foo",
			K8sCertificateAuthority: "foobar",
			K8sToken: "foobarbaz",
		},
	}

	// Bad data samples.
	data3 := `
apiVersion: v2
kind: calicoApiConfig
`
	data4 := `
apiVersion: v1
kind: notCalicoApiConfig
`

	// Environments to test ETCD parameters
	env1 := map[string]string {
		"ETCD_ENDPOINTS": "https://1.2.3.4:1234,https://10.20.30.40:1234",
		"ETCD_USERNAME": "bar",
		"ETCD_PASSWORD": "baz",
		"ETCD_KEY_FILE": "foo",
		"ETCD_CERT_FILE": "foobar",
		"ETCD_CA_CERT_FILE": "foobarbaz",
	}
	cfg1env := api.NewCalicoAPIConfig()
	cfg1env.Spec = api.CalicoAPIConfigSpec{
		DatastoreType: api.EtcdV2,
		EtcdConfig: etcd.EtcdConfig{
			EtcdScheme: "http",
			EtcdAuthority: "127.0.0.1:2379",
			EtcdEndpoints: "https://1.2.3.4:1234,https://10.20.30.40:1234",
			EtcdUsername: "bar",
			EtcdPassword: "baz",
			EtcdKeyFile: "foo",
			EtcdCertFile: "foobar",
			EtcdCACertFile: "foobarbaz",
		},
	}

	// Environments to test k8s parameters
	env2 := map[string]string {
		"DATASTORE_TYPE": string(api.Kubernetes),
		"KUBECONFIG": "filename",
		"K8S_API_ENDPOINT": "bar",
		"K8S_CERT_FILE": "baz",
		"K8S_KEY_FILE": "foo",
		"K8S_CA_FILE": "foobar",
		"K8S_API_TOKEN": "foobarbaz",
	}
	cfg2env := api.NewCalicoAPIConfig()
	cfg2env.Spec = api.CalicoAPIConfigSpec{
		DatastoreType: api.Kubernetes,
		EtcdConfig: etcd.EtcdConfig{
			EtcdScheme: "http",
			EtcdAuthority: "127.0.0.1:2379",
		},
		KubeConfig: k8s.KubeConfig{
			K8sKubeconfigFile: "filename",
			K8sServer: "bar",
			K8sClientCertificate: "baz",
			K8sClientKey: "foo",
			K8sCertificateAuthority: "foobar",
			K8sToken: "foobarbaz",
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
		Entry("valid k8s configuration", data2, cfg2data, nil),
		Entry("invalid version", data3, nil, errors.New("unknown APIVersion 'v2'")),
		Entry("invalid kind", data4, nil, errors.New("expected kind 'calicoApiConfig', got 'notCalicoApiConfig'")),
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
	)
})
