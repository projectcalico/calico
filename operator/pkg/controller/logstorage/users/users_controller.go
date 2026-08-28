// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package users

import (
	"context"
	"fmt"

	"github.com/projectcalico/calico/operator/pkg/controller/logstorage/initializer"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	"github.com/elastic/cloud-on-k8s/v2/pkg/utils/stringsutil"
	"github.com/go-logr/logr"
	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	"github.com/projectcalico/calico/operator/pkg/render/logstorage/dashboards"
	corev1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/logstorage/esutils"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/crypto"
	"github.com/projectcalico/calico/operator/pkg/enterprise/cloudconfig"
	eutils "github.com/projectcalico/calico/operator/pkg/enterprise/utils"
	"github.com/projectcalico/calico/operator/pkg/render"
	relasticsearch "github.com/projectcalico/calico/operator/pkg/render/common/elasticsearch"
	"github.com/projectcalico/calico/operator/pkg/render/common/secret"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var log = logf.Log.WithName("controller_logstorage_users")

const (
	userCleanupFinalizer = "tigera.io/es-user-cleanup"
)

type UserController struct {
	client          client.Client
	scheme          *runtime.Scheme
	status          status.StatusManager
	esClientFn      esutils.ElasticsearchClientCreator
	multiTenant     bool
	elasticExternal bool

	// useSingleIndex indicates that this single-tenant cluster stores its data in single-index format,
	// in which case the users provisioned here are granted access to the single-index names rather than
	// to the per-cluster multi-index ones.
	useSingleIndex bool
}

type UsersCleanupController struct {
	client          client.Client
	scheme          *runtime.Scheme
	esClientFn      esutils.ElasticsearchClientCreator
	elasticExternal bool
}

func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.Variant.IsEnterprise() {
		return nil
	}
	if !opts.Cloud {
		// The operator creates users for cloud clusters. Anywhere
		// else, user creation is handled by es-kube-controllers instead.
		return nil
	}

	// Create the reconciler
	r := &UserController{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		multiTenant:     opts.MultiTenant,
		useSingleIndex:  opts.UseSingleIndex,
		status:          status.New(mgr.GetClient(), initializer.TigeraStatusLogStorageUsers, opts.KubernetesVersion),
		esClientFn:      esutils.NewElasticClient,
		elasticExternal: opts.ElasticExternal,
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := ctrlruntime.NewController("log-storage-user-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Determine how to handle watch events for cluster-scoped resources. For multi-tenant clusters,
	// we should update all tenants whenever one changes. For single-tenatn clusters, we can just queue the object.
	var eventHandler handler.EventHandler = &handler.EnqueueRequestForObject{}
	if opts.MultiTenant {
		eventHandler = eutils.EnqueueAllTenants(mgr.GetClient())
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.WatchObject(&operatorv1.LogStorage{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-user-controller failed to watch LogStorage resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementCluster{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-user-controller failed to watch ManagementCluster resource: %w", err)
	}
	if err = c.WatchObject(&operatorv1.ManagementClusterConnection{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-user-controller failed to watch ManagementClusterConnection resource: %w", err)
	}
	if err = utils.AddTigeraStatusWatch(c, initializer.TigeraStatusLogStorageUsers); err != nil {
		return fmt.Errorf("logstorage-controller failed to watch logstorage Tigerastatus: %w", err)
	}
	if opts.MultiTenant {
		if err = c.WatchObject(&operatorv1.Tenant{}, &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("log-storage-user-controller failed to watch Tenant resource: %w", err)
		}
	} else {
		// In single-tenant mode the tenant configuration comes from a ConfigMap rather than a Tenant
		// resource, and which one depends on where Elasticsearch lives. See singleTenant.
		configMap := eutils.CloudAuthConfig
		if opts.ElasticExternal {
			configMap = cloudconfig.CloudConfigConfigMapName
		}
		if err = utils.AddConfigMapWatch(c, configMap, common.OperatorNamespace(), &handler.EnqueueRequestForObject{}); err != nil {
			return fmt.Errorf("log-storage-user-controller failed to watch the ConfigMap resource: %w", err)
		}
	}

	// Watch for Elasticsearch.
	if err = c.WatchObject(&esv1.Elasticsearch{}, eventHandler); err != nil {
		return fmt.Errorf("log-storage-user-controller failed to watch Elasticsearch resource: %w", err)
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, eventHandler)
	if err != nil {
		return fmt.Errorf("log-storage-user-controller failed to create periodic reconcile watch: %w", err)
	}

	if !opts.MultiTenant {
		// The cleanup controller reconciles Tenant resources, which only exist in multi-tenant mode.
		return nil
	}

	// Now that the users controller is set up, we can also set up the controller that cleans up stale users
	usersCleanupReconciler := &UsersCleanupController{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		esClientFn:      esutils.NewElasticClient,
		elasticExternal: opts.ElasticExternal,
	}

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	usersCleanupController, err := ctrlruntime.NewController("log-storage-cleanup-controller", mgr, controller.Options{Reconciler: usersCleanupReconciler})
	if err != nil {
		return err
	}

	if err = usersCleanupController.WatchObject(&operatorv1.Tenant{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-cleanup-controller failed to watch Tenant resource: %w", err)
	}

	err = utils.AddPeriodicReconcile(usersCleanupController, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("log-storage-cleanup-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

// singleTenant builds the tenant configuration for a single-tenant cluster, which has no Tenant
// resource, and returns the ConfigMap it was read from so the caller can name it when waiting.
// Clusters sharing an external Elasticsearch are described by the cloud config; clusters on their own
// Elasticsearch by the cloud auth config, which carries the tenant ID alone.
func (r *UserController) singleTenant(ctx context.Context) (*operatorv1.Tenant, string, error) {
	if !r.elasticExternal {
		tenant, err := eutils.GetTenantFromCloudAuthConfig(ctx, r.client)
		return tenant, eutils.CloudAuthConfig, err
	}

	cloudConfig, err := eutils.GetCloudConfig(ctx, r.client)
	if err != nil {
		return nil, cloudconfig.CloudConfigConfigMapName, err
	}
	return eutils.TenantFromCloudConfig(cloudConfig, eutils.WithStandardIndicesIf(r.useSingleIndex)), cloudconfig.CloudConfigConfigMapName, nil
}

func (r *UserController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	helper := eutils.NewNamespaceHelper(r.multiTenant, render.ElasticsearchNamespace, request.Namespace)
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace())
	reqLogger.Info("Reconciling LogStorage - Users")

	// We skip requests without a namespace specified in multi-tenant setups.
	if r.multiTenant && request.Namespace == "" {
		return reconcile.Result{}, nil
	}

	// Check if this is a tenant-scoped request.
	tenant, tenantID, err := eutils.GetTenant(ctx, r.multiTenant, r.client, request.Namespace)
	if errors.IsNotFound(err) {
		reqLogger.Info("No Tenant in this Namespace, skip")
		return reconcile.Result{}, nil
	} else if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, reqLogger)
		return reconcile.Result{}, err
	}

	if !r.multiTenant {
		// Single-tenant clusters have no Tenant resource. Build the equivalent tenant configuration
		// from the ConfigMap describing this cluster, so that we provision the users against the right
		// Elasticsearch.
		var configMap string
		tenant, configMap, err = r.singleTenant(ctx)
		if errors.IsNotFound(err) {
			// The ConfigMap is written out of band, and may not exist yet. Wait for it rather than
			// retrying with backoff - we watch it, so we reconcile again once it appears.
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for ConfigMap %s to be available", configMap), nil, reqLogger)
			return reconcile.Result{}, nil
		} else if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to read the tenant configuration", err, reqLogger)
			return reconcile.Result{}, err
		}
		tenantID = tenant.Spec.ID
	}

	// Get LogStorage resource.
	logStorage := &operatorv1.LogStorage{}
	err = r.client.Get(ctx, utils.DefaultEnterpriseInstanceKey, logStorage)
	if err != nil {
		// Not finding the LogStorage CR is not an error, as a Managed cluster will not have this CR available but
		// there are still "LogStorage" related items that need to be set up
		if !errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	// We found the LogStorage instance (and Tenant instance if in multi-tenant mode).
	r.status.OnCRFound()

	// Wait for the initializing controller to indicate that the LogStorage object is actionable.
	if logStorage.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LogStorage defaulting to occur", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	if !r.elasticExternal {
		// Wait for Elasticsearch to be installed and available.
		elasticsearch, err := esutils.GetElasticsearch(ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Elasticsearch", err, reqLogger)
			return reconcile.Result{}, err
		}
		if elasticsearch == nil || elasticsearch.Status.Phase != esv1.ElasticsearchReadyPhase {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", nil, reqLogger)
			return reconcile.Result{}, nil
		}
	}

	// Determine the names of the users to provision. In multi-tenant clusters the cluster ID forms part
	// of the user names, and is read from the cluster-info ConfigMap written at install time.
	// Single-tenant clusters have no such ConfigMap - their user names are derived from the tenant ID
	// alone, matching the names es-kube-controllers used before the operator took over provisioning.
	var linseedUser, dashboardUser *esutils.User
	if r.multiTenant {
		clusterID, err := eutils.GetClusterID(ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Waiting for the cluster ID to be available", err, reqLogger)
			return reconcile.Result{}, err
		}
		linseedUser = esutils.LinseedUser(clusterID, tenant)
		dashboardUser = esutils.DashboardUser(clusterID, tenantID)
	} else {
		linseedUser = esutils.LinseedUserSingleTenant(tenant, r.elasticExternal)
		dashboardUser = esutils.DashboardUserSingleTenant(tenantID, r.elasticExternal)
	}

	// Query any existing username and password for this Linseed instance. If one already exists, we'll simply
	// use that. Otherwise, generate a new one.
	linseedUserSecret := corev1.Secret{}
	var credentialSecrets []client.Object
	key := types.NamespacedName{Name: render.ElasticsearchLinseedUserSecret, Namespace: helper.TruthNamespace()}
	if err = r.client.Get(ctx, key, &linseedUserSecret); err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error getting Secret %s", key), err, reqLogger)
		return reconcile.Result{}, err
	} else if errors.IsNotFound(err) {
		// Create the secret to provision into the cluster.
		linseedUserSecret.Name = render.ElasticsearchLinseedUserSecret
		linseedUserSecret.Namespace = helper.TruthNamespace()
		linseedUserSecret.StringData = map[string]string{"username": linseedUser.Username, "password": crypto.GeneratePassword(16)}

		// Make sure we install the generated credentials into the truth namespace.
		credentialSecrets = append(credentialSecrets, &linseedUserSecret)
	} else if string(linseedUserSecret.Data["username"]) != linseedUser.Username {
		// The credentials exist, but reference a different Elasticsearch user than the one we provision -
		// e.g. because they were created by es-kube-controllers before the operator took over user
		// provisioning. Point them at our user, keeping the existing password.
		linseedUserSecret.StringData = map[string]string{"username": linseedUser.Username}
		credentialSecrets = append(credentialSecrets, &linseedUserSecret)
	}

	// Query any existing username and password for this Dashboards instance. If one already exists, we'll simply
	// use that. Otherwise, generate a new one.
	keyDashboardCred := types.NamespacedName{Name: dashboards.ElasticCredentialsSecret, Namespace: helper.TruthNamespace()}
	dashboardUserSecret := corev1.Secret{}
	if err = r.client.Get(ctx, keyDashboardCred, &dashboardUserSecret); err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error getting Secret %s", keyDashboardCred), err, reqLogger)
		return reconcile.Result{}, err
	} else if errors.IsNotFound(err) {
		// Create the secret to provision into the cluster.
		dashboardUserSecret.Name = dashboards.ElasticCredentialsSecret
		dashboardUserSecret.Namespace = helper.TruthNamespace()
		dashboardUserSecret.StringData = map[string]string{"username": dashboardUser.Username, "password": crypto.GeneratePassword(16)}

		// Make sure we install the generated credentials into the truth namespace.
		credentialSecrets = append(credentialSecrets, &dashboardUserSecret)
	} else if string(dashboardUserSecret.Data["username"]) != dashboardUser.Username {
		// As above - point the existing credentials at the user we provision.
		dashboardUserSecret.StringData = map[string]string{"username": dashboardUser.Username}
		credentialSecrets = append(credentialSecrets, &dashboardUserSecret)
	}

	if helper.TruthNamespace() != helper.InstallNamespace() {
		// Copy the credentials into the install namespace.
		credentialSecrets = append(credentialSecrets, secret.CopyToNamespace(helper.InstallNamespace(), &linseedUserSecret)[0])
		credentialSecrets = append(credentialSecrets, secret.CopyToNamespace(helper.InstallNamespace(), &dashboardUserSecret)[0])
	}
	credentialComponent := render.NewCreationPassthrough(credentialSecrets...)

	// In standard installs, the LogStorage owns the secret. For multi-tenant, it's owned by the tenant.
	var hdler utils.ComponentHandler
	if r.multiTenant {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, tenant)
	} else {
		hdler = utils.NewComponentHandler(reqLogger, r.client, r.scheme, logStorage)
	}
	if err = hdler.CreateOrUpdateOrDelete(ctx, credentialComponent, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating Linseed user secret", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Add a finalizer to the Tenant instance if it exists so that we can clean up the Linseed user when the Tenant
	// is deleted. The finalizer will be removed by the user cleanup controller when the user is deleted from ES.
	if r.multiTenant && tenant != nil && tenant.GetDeletionTimestamp().IsZero() && !stringsutil.StringInSlice(userCleanupFinalizer, tenant.GetFinalizers()) {
		tenant.SetFinalizers(append(tenant.GetFinalizers(), userCleanupFinalizer))
		if err = r.client.Update(ctx, tenant); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error adding finalizer to Tenant", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Now that the secret has been created, also provision the user in ES.
	elasticEndpoint := relasticsearch.ECKElasticEndpoint()
	if tenant.Spec.Elastic != nil && tenant.Spec.Elastic.URL != "" {
		elasticEndpoint = tenant.Spec.Elastic.URL
	}
	if err = r.createUserLogin(ctx, elasticEndpoint, &linseedUserSecret, linseedUser, reqLogger); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to create Linseed user in ES", err, reqLogger)
		return reconcile.Result{}, err
	}

	if err = r.createUserLogin(ctx, elasticEndpoint, &dashboardUserSecret, dashboardUser, reqLogger); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to create Dashboards user in ES", err, reqLogger)
		return reconcile.Result{}, err
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}

func (r *UserController) createUserLogin(ctx context.Context, elasticEndpoint string, secret *corev1.Secret, user *esutils.User, reqLogger logr.Logger) error {
	esClient, err := r.esClientFn(r.client, ctx, elasticEndpoint, r.elasticExternal)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Failed to connect to Elasticsearch - failed to create the Elasticsearch client", err, reqLogger)
		return err
	}

	// Determine the password from the secret.
	password := secret.StringData["password"]
	if password == "" {
		password = string(secret.Data["password"])
	}
	if password == "" {
		return fmt.Errorf("unable to find password in secret")
	}

	// Create the user in ES.
	user.Password = password
	if err = esClient.CreateUser(ctx, user); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to create or update Elasticsearch user", err, reqLogger)
		return err
	}

	return nil
}

func (r *UsersCleanupController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	helper := eutils.NewNamespaceHelper(true, render.ElasticsearchNamespace, request.Namespace)
	reqLogger := logf.Log.WithName("controller_logstorage_users_cleanup").WithValues("Request.Namespace",
		request.Namespace, "Request.Name", request.Name, "installNS", helper.InstallNamespace(), "truthNS", helper.TruthNamespace())
	reqLogger.Info("Reconciling LogStorage - Cleanup")

	if !r.elasticExternal {
		// Wait for Elasticsearch to be installed and available.
		elasticsearch, err := esutils.GetElasticsearch(ctx, r.client)
		if err != nil {
			return reconcile.Result{}, err
		}
		if elasticsearch == nil || elasticsearch.Status.Phase != esv1.ElasticsearchReadyPhase {
			reqLogger.Info("Elasticsearch is not ready")
			return reconcile.Result{}, nil
		}
	}

	// Clean up any stale users that may have been left behind by a previous tenant
	if err := r.cleanupStaleUsers(ctx, reqLogger); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (r *UsersCleanupController) cleanupStaleUsers(ctx context.Context, logger logr.Logger) error {
	tenants := operatorv1.TenantList{}
	err := r.client.List(ctx, &tenants)
	if err != nil {
		return fmt.Errorf("failed to fetch TenantList")
	}

	clusterID, err := eutils.GetClusterID(ctx, r.client)
	if err != nil {
		return err
	}

	var t operatorv1.Tenant
	for _, t = range tenants.Items {
		// Skip tenants that aren't being deleted.
		if t.GetDeletionTimestamp().IsZero() {
			continue
		}

		// This tenant is terminating - clean up its Linseed user, if it exists.
		esClient, err := r.esClientFn(r.client, ctx, t.Spec.Elastic.URL, r.elasticExternal)
		if err != nil {
			return fmt.Errorf("failed to connect to Elasticsearch - failed to create the Elasticsearch client")
		}

		allESUsers, err := esClient.GetUsers(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch users from Elasticsearch")
		}

		lu := esutils.LinseedUser(clusterID, &t)
		dashboardsUser := esutils.DashboardUser(clusterID, t.Spec.ID)
		for _, user := range allESUsers {
			if user.Username == lu.Username || user.Username == dashboardsUser.Username {
				err = esClient.DeleteUser(ctx, &user)
				if err != nil {
					logger.Error(err, "Failed to delete elastic user")
				}

				// Remove the finalizer from the tenant to allow it to be deleted.
				if stringsutil.StringInSlice(userCleanupFinalizer, t.GetFinalizers()) {
					t.SetFinalizers(stringsutil.RemoveStringInSlice(userCleanupFinalizer, t.GetFinalizers()))
					if err = r.client.Update(ctx, &t); err != nil {
						logger.Error(err, "Failed to remove user cleanup finalizer from tenant")
					}
				}
				break
			}
		}
	}
	return nil
}
