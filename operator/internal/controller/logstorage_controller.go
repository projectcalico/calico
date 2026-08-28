// Copyright (c) 2020,2024-2026 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"github.com/go-logr/logr"
	"github.com/tigera/operator/pkg/controller/logstorage/dashboards"
	"github.com/tigera/operator/pkg/controller/logstorage/esmetrics"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/controller/logstorage/elastic"
	"github.com/tigera/operator/pkg/controller/logstorage/initializer"
	"github.com/tigera/operator/pkg/controller/logstorage/kubecontrollers"
	"github.com/tigera/operator/pkg/controller/logstorage/linseed"
	"github.com/tigera/operator/pkg/controller/logstorage/managedcluster"
	"github.com/tigera/operator/pkg/controller/logstorage/secrets"
	"github.com/tigera/operator/pkg/controller/logstorage/users"
	"github.com/tigera/operator/pkg/controller/options"
)

// LogStorageReconciler reconciles a LogStorage object
type LogStorageReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=operator.tigera.io,resources=logstorages,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=operator.tigera.io,resources=logstorages/status,verbs=get;update;patch

// SetupWithManager adds all of the relevant log storage sub-controllers to the controller manager.
// Each of these controllers reconciles independently, but they work together in order to implement log storage
// capabilities. These controllers do not communicate directly with each other, but instead communicate through
// the Kubernetes API.
func (r *LogStorageReconciler) SetupWithManager(mgr ctrl.Manager, opts options.ControllerOptions) error {
	// The initializer controller is responsible for performing validation and defaulting on the LogStorage object,
	// and creating the base namespaces for other controllers to deploy into. It updates the status of the LogStorage
	// object to indicate that it has completed its work to other controllers.
	if err := initializer.Add(mgr, opts); err != nil {
		return err
	}

	// The conditions controller is responsible for updating the status of the log-storage TigeraStatus object with conditions
	// based on an aggregation of all the sub-controllers statuses.
	if err := initializer.AddConditionsController(mgr, opts); err != nil {
		return err
	}

	// The secrets controller provisions all the necessary key pairs and trusted bundles required for log storage components to operate.
	if err := secrets.Add(mgr, opts); err != nil {
		return err
	}

	// The Linseed controller installs Linseed and related resources into the cluster. It waits for elasticsearch to be
	// ready before doing so.
	if err := linseed.Add(mgr, opts); err != nil {
		return err
	}

	// The elastic controller is responsible for installing the ECK operator an Elasticsearch CR into the cluster.
	// It will also install Kibana if configured to do so. This controller only runs on management and standalone clusters.
	if err := elastic.Add(mgr, opts); err != nil {
		return err
	}

	// The ES metrics controller installs ES metrics into the cluster. It will only install ES metrics in a single-tenant
	// management cluster.
	if err := esmetrics.Add(mgr, opts); err != nil {
		return err
	}

	// The dashboards controller installs Kibana dashboards and Kibana index-patterns
	if err := dashboards.Add(mgr, opts); err != nil {
		return err
	}

	// The managed cluster controller runs on managed clusters only, and installs the necessary services for managed cluster components
	// to talk to the management cluster, as well as the necessary RBAC for management cluster components to talk
	// to the managed cluster.
	if err := managedcluster.Add(mgr, opts); err != nil {
		return err
	}

	// The users controller runs in multi-tenant mode only, and is responsible for generating unique credentials for each Linseed instance
	// and provisioning users into Elasticsearch for them to use.
	if err := users.Add(mgr, opts); err != nil {
		return err
	}

	// The kubecontrollers controller runs on single-tenant management clusters and standalone clusters, and installs es-gateway and
	// es-kube-controllers.
	if err := kubecontrollers.Add(mgr, opts); err != nil {
		return err
	}

	// This controller runs only on management clusters configured to use an external Elasticsearch cluster.
	if err := elastic.AddExternalES(mgr, opts); err != nil {
		return err
	}

	return nil
}
