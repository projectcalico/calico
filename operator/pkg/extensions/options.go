// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.
//
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

package extensions

import (
	"context"
	"fmt"

	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"

	v1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/common/discovery"
)

// ControllerOptions are passed to controllers when added to the controller manager. They
// detail options detected by the daemon at startup that some controllers may either
// use to determine if they should run at all, or store them and influence their
// reconciliation loops.
type ControllerOptions struct {
	DetectedProvider v1.Provider

	// Variant is the product variant resolved from the Installation before any controller
	// started. The process runs as this variant for its lifetime; a change restarts it.
	Variant v1.ProductVariant

	ClusterDomain     string
	KubernetesVersion *common.VersionInfo
	ManageCRDs        bool
	ShutdownContext   context.Context

	// Kubernetes clientset used by controllers to create watchers and informers.
	K8sClientset *kubernetes.Clientset

	// Whether or not to use crd.projectcalico.org/v1 or projectcalico.org/v3 for Calico CRDs.
	UseV3CRDs bool

	// APIDiscovery is a snapshot of which Kubernetes API versions the cluster serves for the kinds
	// the operator cares about. Populated once at startup so controllers can branch on API
	// availability without issuing further discovery requests at reconcile time.
	APIDiscovery *discovery.APIDiscovery

	// Extensions are the variant extensions the operator runs with, for the Variant
	// above. The core operator leaves them unset and runs the base behavior.
	Extensions Extensions
}

// AddControllers adds the reconcilers the running variant contributes.
func (o ControllerOptions) AddControllers(mgr ctrl.Manager) error {
	for _, c := range o.Extensions.Startup().Controllers() {
		if err := c.Add(mgr, o); err != nil {
			return fmt.Errorf("failed to create controller %s: %v", c.Name, err)
		}
	}
	return nil
}

// Controller is a reconciler a variant contributes, so that the core controller
// manager can add it without naming the type.
type Controller struct {
	// Name identifies the controller when its setup fails.
	Name string

	Add func(mgr ctrl.Manager, opts ControllerOptions) error
}
