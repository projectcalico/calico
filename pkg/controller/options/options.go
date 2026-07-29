// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package options

import (
	"context"

	v1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/common/discovery"
	"k8s.io/client-go/kubernetes"
)

// ControllerOptions are passed to controllers when added to the controller manager. They
// detail options detected by the daemon at startup that some controllers may either
// use to determine if they should run at all, or store them and influence their
// reconciliation loops.
type ControllerOptions struct {
	DetectedProvider    v1.Provider
	EnterpriseCRDExists bool
	ClusterDomain       string
	KubernetesVersion   *common.VersionInfo
	ManageCRDs          bool
	ShutdownContext     context.Context

	// Kubernetes clientset used by controllers to create watchers and informers.
	K8sClientset *kubernetes.Clientset

	// Whether or not the operator is running in multi-tenant mode.
	// When true, this means some CRDs are installed as namespace scoped
	// instead of cluster scoped.
	MultiTenant bool

	// Whether or not the operator is running in a management cluster configured to
	// use external elasticsearch. When set, the operator will not install Elasticsearch
	// and instead will configure the cluster to use an external Elasticsearch.
	ElasticExternal bool

	// Cloud indicates the operator is running in a Calico Cloud management cluster. When set,
	// controllers activate cloud-specific behavior (cloud render decorations, cloud config maps,
	// etc.). When false the operator behaves as a regular Calico/Calico Enterprise install.
	Cloud bool

	// ESMigration is enabled in the last phase of an ES migration, when we need to keep both an
	// LSS configuration and internal elasticsearch running. Only meaningful when Cloud is set.
	ESMigration bool

	// Whether or not to use crd.projectcalico.org/v1 or projectcalico.org/v3 for Calico CRDs.
	UseV3CRDs bool

	// APIDiscovery is a snapshot of which Kubernetes API versions the cluster serves for the kinds
	// the operator cares about. Populated once at startup so controllers can branch on API
	// availability without issuing further discovery requests at reconcile time.
	APIDiscovery *discovery.APIDiscovery
}
