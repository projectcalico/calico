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

package api

import "github.com/projectcalico/libcalico-go/lib/api/unversioned"

type DatastoreType string

const (
	EtcdV2     DatastoreType = "etcdv2"
	Kubernetes DatastoreType = "kubernetes"
)

// CalicoAPIConfig contains the connection information for a Calico CalicoAPIConfig resource
type CalicoAPIConfig struct {
	unversioned.TypeMetadata
	Metadata CalicoAPIConfigMetadata `json:"metadata,omitempty"`
	Spec     CalicoAPIConfigSpec     `json:"spec,omitempty"`
}

// CalicoAPIConfigMetadata contains the metadata for a Calico CalicoAPIConfig resource.
type CalicoAPIConfigMetadata struct {
	unversioned.ObjectMetadata
}

// CalicoAPIConfigSpec contains the specification for a Calico CalicoAPIConfig resource.
type CalicoAPIConfigSpec struct {
	DatastoreType DatastoreType `json:"datastoreType" envconfig:"DATASTORE_TYPE" default:"etcdv2"`

	// Inline the ectd config fields
	EtcdConfig

	// Inline the k8s config fields.
	KubeConfig
}

type EtcdConfig struct {
	EtcdScheme     string `json:"etcdScheme" envconfig:"ETCD_SCHEME" default:"http"`
	EtcdAuthority  string `json:"etcdAuthority" envconfig:"ETCD_AUTHORITY" default:"127.0.0.1:2379"`
	EtcdEndpoints  string `json:"etcdEndpoints" envconfig:"ETCD_ENDPOINTS"`
	EtcdUsername   string `json:"etcdUsername" envconfig:"ETCD_USERNAME"`
	EtcdPassword   string `json:"etcdPassword" envconfig:"ETCD_PASSWORD"`
	EtcdKeyFile    string `json:"etcdKeyFile" envconfig:"ETCD_KEY_FILE"`
	EtcdCertFile   string `json:"etcdCertFile" envconfig:"ETCD_CERT_FILE"`
	EtcdCACertFile string `json:"etcdCACertFile" envconfig:"ETCD_CA_CERT_FILE"`
}

type KubeConfig struct {
	Kubeconfig               string `json:"kubeconfig" envconfig:"KUBECONFIG" default:""`
	K8sAPIEndpoint           string `json:"k8sAPIEndpoint" envconfig:"K8S_API_ENDPOINT" default:""`
	K8sKeyFile               string `json:"k8sKeyFile" envconfig:"K8S_KEY_FILE" default:""`
	K8sCertFile              string `json:"k8sCertFile" envconfig:"K8S_CERT_FILE" default:""`
	K8sCAFile                string `json:"k8sCAFile" envconfig:"K8S_CA_FILE" default:""`
	K8sAPIToken              string `json:"k8sAPIToken" envconfig:"K8S_API_TOKEN" default:""`
	K8sInsecureSkipTLSVerify bool   `json:"k8sInsecureSkipTLSVerify" envconfig:"K8S_INSECURE_SKIP_TLS_VERIFY" default:""`
	K8sDisableNodePoll       bool   `json:"k8sDisableNodePoll" envconfig:"K8S_DISABLE_NODE_POLL" default:""`
}

// NewCalicoAPIConfig creates a new (zeroed) CalicoAPIConfig struct with the
// TypeMetadata initialised to the current version.
func NewCalicoAPIConfig() *CalicoAPIConfig {
	return &CalicoAPIConfig{
		TypeMetadata: unversioned.TypeMetadata{
			Kind:       "calicoApiConfig",
			APIVersion: unversioned.VersionCurrent,
		},
	}
}
