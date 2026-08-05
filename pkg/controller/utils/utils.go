// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	"github.com/elastic/cloud-on-k8s/v2/pkg/utils/stringsutil"
	csiv1 "sigs.k8s.io/secrets-store-csi-driver/apis/v1"

	"github.com/go-logr/logr"

	appsv1 "k8s.io/api/apps/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/rbacmanagement"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
)

const (
	// If this annotation is set on an object, the operator will ignore it, allowing user modifications.
	// This is for development and testing purposes only. Do not use this annotation
	// for production, as this will cause problems with upgrade.
	unsupportedIgnoreAnnotation = "unsupported.operator.tigera.io/ignore"
)

var log = logf.Log.WithName("utils")

var (
	DefaultInstanceKey           = client.ObjectKey{Name: "default"}
	DefaultEnterpriseInstanceKey = client.ObjectKey{Name: "tigera-secure"}
	OverlayInstanceKey           = client.ObjectKey{Name: "overlay"}
	KubeProxyInstanceKey         = client.ObjectKey{Name: "kube-proxy", Namespace: "kube-system"}

	PeriodicReconcileTime = 5 * time.Minute

	// StandardRetry is the amount of time to wait beofre retrying a request in
	// most scenarios. Retries should be used sparingly, and only in extraordinary
	// circumstances. Use this as a default when retries are needed.
	StandardRetry = 30 * time.Second
	// FinalizerRemovalRetry is the amount of time to wait before retrying a request
	// when waiting for the removal of a finalizer from the Installation by a non-core controller.
	FinalizerRemovalRetry = 10 * time.Second

	// AllowedSysctlKeys controls the allowed Sysctl keys can be set in Tuning plugin
	AllowedSysctlKeys = map[string]bool{
		"net.ipv4.tcp_keepalive_intvl":  true,
		"net.ipv4.tcp_keepalive_probes": true,
		"net.ipv4.tcp_keepalive_time":   true,
	}
)

// ContextLoggerForResource provides a logger instance with context set for the provided object.
func ContextLoggerForResource(log logr.Logger, obj client.Object) logr.Logger {
	gvk := obj.GetObjectKind().GroupVersionKind()
	name := obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
	namespace := obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace()
	return log.WithValues("name", name, "namespace", namespace, "kind", gvk.Kind)
}

// IgnoreObject returns true if the object has been marked as ignored by the user,
// and returns false otherwise.
func IgnoreObject(obj runtime.Object) bool {
	a := obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetAnnotations()
	if val, ok := a[unsupportedIgnoreAnnotation]; ok && val == "true" {
		return true
	}
	return false
}

// V3Client creates a new controller-runtime client that can be used to interact with projectcalico.org/v3 resources.
// In some cases it is necessary to use a separate client from the default provisioned by the manager, as we interact with two different
// API groups (crd.projectcalico.org and projectcalico.org/v3) that may use the same underlying Go types.
func V3Client(config *rest.Config) (client.Client, error) {
	scheme := runtime.NewScheme()
	if err := v3.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add projectcalico.org/v3 to scheme: %w", err)
	}

	// The component handler reads the Installation regardless of which client writes the rendered
	// objects, so this client needs to be able to resolve operator.tigera.io types as well.
	if err := operatorv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add operator.tigera.io to scheme: %w", err)
	}

	c, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}
	return c, nil
}

func AddInstallationWatch(c ctrlruntime.Controller) error {
	return c.WatchObject(&operatorv1.Installation{}, &handler.EnqueueRequestForObject{})
}

func AddAPIServerWatch(c ctrlruntime.Controller) error {
	return c.WatchObject(&operatorv1.APIServer{}, &handler.EnqueueRequestForObject{})
}

func AddNamespaceWatch(c ctrlruntime.Controller, name string) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	return c.WatchObject(ns, &handler.EnqueueRequestForObject{})
}

type MetaMatch func(metav1.ObjectMeta) bool

func AddSecretsWatch(c ctrlruntime.Controller, name, namespace string) error {
	return AddSecretsWatchWithHandler(c, name, namespace, &handler.EnqueueRequestForObject{})
}

func AddSecretsWatchWithHandler(c ctrlruntime.Controller, name, namespace string, h handler.EventHandler) error {
	s := &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	return AddNamespacedWatch(c, s, h)
}

func AddSecretProviderClassWatch(c ctrlruntime.Controller, name, namespace string) error {
	return AddSecretProviderClassWatchWithHandler(c, name, namespace, &handler.EnqueueRequestForObject{})
}

func AddSecretProviderClassWatchWithHandler(c ctrlruntime.Controller, name, namespace string, h handler.EventHandler) error {
	s := &csiv1.SecretProviderClass{
		TypeMeta:   metav1.TypeMeta{Kind: "SecretProviderClass", APIVersion: "secrets-store.csi.x-k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	return AddNamespacedWatch(c, s, h)
}

func AddConfigMapWatch(c ctrlruntime.Controller, name, namespace string, h handler.EventHandler) error {
	cm := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	return AddNamespacedWatch(c, cm, h)
}

func AddServiceWatch(c ctrlruntime.Controller, name, namespace string) error {
	return AddServiceWatchWithHandler(c, name, namespace, &handler.EnqueueRequestForObject{})
}

func AddServiceWatchWithHandler(c ctrlruntime.Controller, name, namespace string, h handler.EventHandler) error {
	return AddNamespacedWatch(c, &corev1.Service{
		TypeMeta:   metav1.TypeMeta{Kind: "Service", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}, h)
}

func AddDeploymentWatch(c ctrlruntime.Controller, name, namespace string) error {
	return AddNamespacedWatch(c, &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}, &handler.EnqueueRequestForObject{})
}

func AddDaemonsetWatch(c ctrlruntime.Controller, name, namespace string) error {
	return AddNamespacedWatch(c, &appsv1.DaemonSet{
		TypeMeta:   metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}, &handler.EnqueueRequestForObject{})
}

func AddPeriodicReconcile(c ctrlruntime.Controller, period time.Duration, handler handler.EventHandler) error {
	return c.Watch(source.Channel(createPeriodicReconcileChannel(period), handler))
}

// AddSecretWatchWithLabel adds a secret watch for secrets with the given label in the given namespace.
// If no namespace is provided, it watches cluster-wide.
func AddSecretWatchWithLabel(c ctrlruntime.Controller, ns, label string) error {
	return c.WatchObject(&corev1.Secret{}, &handler.EnqueueRequestForObject{}, &predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			_, hasLabel := e.Object.GetLabels()[label]
			return (ns == "" || e.Object.GetNamespace() == ns) && hasLabel
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			_, hasLabel := e.ObjectNew.GetLabels()[label]
			return (ns == "" || e.ObjectNew.GetNamespace() == ns) && hasLabel
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			_, hasLabel := e.Object.GetLabels()[label]
			return (ns == "" || e.Object.GetNamespace() == ns) && hasLabel
		},
	})
}

// AddCSRWatchWithRelevancyFn adds a watch for CSRs with the given label. isRelevantFn is a function that returns true for
// items that are relevant to the caller.
func AddCSRWatchWithRelevancyFn(c ctrlruntime.Controller, isRelevantFn func(*certificatesv1.CertificateSigningRequest) bool) error {
	return c.WatchObject(&certificatesv1.CertificateSigningRequest{}, &handler.EnqueueRequestForObject{}, &predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			csr, ok := e.Object.(*certificatesv1.CertificateSigningRequest)
			return ok && isRelevantFn(csr)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			csr, ok := e.ObjectNew.(*certificatesv1.CertificateSigningRequest)
			return ok && isRelevantFn(csr)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			// If a CSR is deleted, then the need for a certificate is no longer there and there is no need to sign anything.
			// Therefore, we discard this event. It is up to the issuer to re-issue a new CSR if needed.
			return false
		},
	})
}

func createPeriodicReconcileChannel(period time.Duration) chan event.GenericEvent {
	periodicReconcileEvents := make(chan event.GenericEvent)
	eventObject := &unstructured.Unstructured{}
	eventObject.SetName(fmt.Sprintf("periodic-%s-reconcile-event", period.String()))

	go func() {
		for range time.Tick(period) {
			periodicReconcileEvents <- event.GenericEvent{Object: eventObject}
		}
	}()

	return periodicReconcileEvents
}

func WaitToAddClusterInformationWatch(controller ctrlruntime.Controller, c kubernetes.Interface, log logr.Logger, flag *ReadyFlag) {
	WaitToAddResourceWatch(controller, c, log, flag, []client.Object{&v3.ClusterInformation{TypeMeta: metav1.TypeMeta{Kind: v3.KindClusterInformation}}})
}

func WaitToAddPolicyRecommendationScopeWatch(controller ctrlruntime.Controller, c kubernetes.Interface, log logr.Logger, flag *ReadyFlag) {
	WaitToAddResourceWatch(controller, c, log, flag, []client.Object{&v3.PolicyRecommendationScope{TypeMeta: metav1.TypeMeta{Kind: v3.KindPolicyRecommendationScope}}})
}

func WaitToAddNetworkPolicyWatches(controller ctrlruntime.Controller, c kubernetes.Interface, log logr.Logger, policies []types.NamespacedName) {
	objs := []client.Object{}
	for _, policy := range policies {
		objs = append(objs, &v3.NetworkPolicy{
			TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
			ObjectMeta: metav1.ObjectMeta{Name: policy.Name, Namespace: policy.Namespace},
		})
	}

	// The success of a NetworkPolicy watch is not a dependency for resources to be installed or function correctly.
	// Therefore, no ready flag is accepted or created for the watch.
	WaitToAddResourceWatch(controller, c, log, nil, objs)
}

func WaitToAddTierWatch(tierName string, controller ctrlruntime.Controller, c kubernetes.Interface, log logr.Logger, flag *ReadyFlag) {
	obj := &v3.Tier{
		TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: tierName},
	}

	// The success of a Tier watch can be used as a signal that Tier queries will be resolved using the cache.
	WaitToAddResourceWatch(controller, c, log, flag, []client.Object{obj})
}

// AddNamespacedWatch creates a watch on the given object. If a name and namespace are provided, then it will
// use predicates to only return matching objects. If they are not, then all events of the provided kind
// will be generated. Updates that do not modify the object's generation (e.g., status and metadata) will be ignored.
func AddNamespacedWatch(c ctrlruntime.Controller, obj client.Object, h handler.EventHandler) error {
	pred := createPredicateForObject(obj)
	return c.WatchObject(obj, h, pred)
}

// AddClusterWatch creates a watch on the given Cluster scoped object. If a name is provided, then it will
// use predicates to only return matching objects. If it is not, then all events of the provided kind
// will be generated. Updates that do not modify the object's generation (e.g., status and metadata) will be ignored.
// If a namespace is set on the obj passed in, the namespace will be set to the empty string.
func AddClusterWatch(c ctrlruntime.Controller, obj client.Object, h handler.EventHandler) error {
	obj.SetNamespace("")
	return AddNamespacedWatch(c, obj, h)
}

// IsProjectCalicoV3Available checks if projectcalico.org/v3 APIs are available. If the v3 parameter is true, it will skip the check and return true.
func IsProjectCalicoV3Available(client client.Client, opts options.ControllerOptions, l logr.Logger) bool {
	if opts.UseV3CRDs {
		return true
	}

	instance, msg, err := GetAPIServer(context.Background(), client)
	if err != nil {
		if errors.IsNotFound(err) {
			l.V(3).Info("APIServer resource does not exist")
			return false
		}
		l.Error(err, "Unable to retrieve APIServer resource", "msg", msg)
		return false
	}

	if instance.Status.State != operatorv1.TigeraStatusReady {
		l.V(3).Info("APIServer resource not ready")
		return false
	}
	return true
}

func LogStorageExists(ctx context.Context, cli client.Client) (bool, error) {
	instance := &operatorv1.LogStorage{}
	err := cli.Get(ctx, DefaultEnterpriseInstanceKey, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func GetLogCollector(ctx context.Context, cli client.Client) (*operatorv1.LogCollector, error) {
	logCollector := &operatorv1.LogCollector{}
	err := cli.Get(ctx, DefaultEnterpriseInstanceKey, logCollector)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return logCollector, nil
}

// FetchClusterInformation fetches and returns the clusterinformation.
func FetchClusterInformation(ctx context.Context, cli client.Client) (v3.ClusterInformation, error) {
	instance := &v3.ClusterInformation{}
	err := cli.Get(ctx, DefaultInstanceKey, instance)
	return *instance, err
}

// ValidateCertPair checks if the given secret exists in the given
// namespace and if so that it contains key and cert fields. If an
// empty string is passed for the keyName argument it is skipped.
// If a secret exists then it is returned. If there is an error
// accessing the secret (except NotFound) or the cert does not have
// both a key and cert field then an appropriate error is returned.
// If no secret exists then nil, nil is returned to represent that no
// cert is valid.
func ValidateCertPair(client client.Client, namespace, certPairSecretName, keyName, certName string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Name:      certPairSecretName,
		Namespace: namespace,
	}
	err := client.Get(context.Background(), secretNamespacedName, secret)
	if err != nil {
		// If the reason for the error is not found then that is acceptable
		// so return valid in that case.
		statErr, ok := err.(*errors.StatusError)
		if ok && statErr.ErrStatus.Reason == metav1.StatusReasonNotFound {
			return nil, nil
		} else {
			return nil, fmt.Errorf("failed to read cert %q from datastore: %s", certPairSecretName, err)
		}
	}

	if keyName != "" {
		if val, ok := secret.Data[keyName]; !ok || len(val) == 0 {
			return secret, fmt.Errorf("secret %q does not have a field named %q", certPairSecretName, keyName)
		}
	}

	if val, ok := secret.Data[certName]; !ok || len(val) == 0 {
		return secret, fmt.Errorf("secret %q does not have a field named %q", certPairSecretName, certName)
	}

	return secret, nil
}

// GetK8sServiceEndPoint returns the kubernetes-service-endpoint configmap
func GetK8sServiceEndPoint(client client.Client) (*corev1.ConfigMap, error) {
	cmName := render.K8sSvcEndpointConfigMapName
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      cmName,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), cmNamespacedName, cm); err != nil {
		return nil, err
	}
	return cm, nil
}

// PopulateK8sServiceEndPoint reads the kubernetes-service-endpoint configmap and pushes
// KUBERNETES_SERVICE_HOST, KUBERNETES_SERVICE_PORT to calico-node daemonset, typha
// apiserver deployments
func PopulateK8sServiceEndPoint(client client.Client) error {
	cm, err := GetK8sServiceEndPoint(client)
	if err != nil {
		if !errors.IsNotFound(err) {
			// If the configmap is unavailable, do not return an error
			return fmt.Errorf("failed to read ConfigMap %q: %s", render.K8sSvcEndpointConfigMapName, err)
		}
	} else {
		k8sapi.Endpoint.Host = cm.Data["KUBERNETES_SERVICE_HOST"]
		k8sapi.Endpoint.Port = cm.Data["KUBERNETES_SERVICE_PORT"]
		k8sapi.PodNetworkEndpoint.Host = cm.Data["KUBERNETES_SERVICE_HOST_POD_NETWORK"]
		k8sapi.PodNetworkEndpoint.Port = cm.Data["KUBERNETES_SERVICE_PORT_POD_NETWORK"]
	}
	return nil
}

func GetInstallationPullSecrets(i *operatorv1.InstallationSpec, c client.Client) ([]*corev1.Secret, error) {
	secrets := []*corev1.Secret{}
	for _, ps := range i.ImagePullSecrets {
		s := &corev1.Secret{}
		err := c.Get(context.Background(), client.ObjectKey{Name: ps.Name, Namespace: common.OperatorNamespace()}, s)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, s)
	}

	return secrets, nil
}

// Return the AplicationLayer CR if present. No error is returned if it was not
// found.
func GetApplicationLayer(ctx context.Context, c client.Client) (*operatorv1.ApplicationLayer, error) {
	applicationLayer := &operatorv1.ApplicationLayer{}

	err := c.Get(ctx, DefaultEnterpriseInstanceKey, applicationLayer)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return applicationLayer, nil
}

// Return the Istio CR if present. No error is returned if it was not found.
func GetIstio(ctx context.Context, c client.Client) (*operatorv1.Istio, error) {
	istio := &operatorv1.Istio{}

	err := c.Get(ctx, DefaultInstanceKey, istio)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return istio, nil
}

// GetManager returns the Manager CR, or nil if it is not found. When
// multiTenant is true the tenant-scoped instance is read from ns; otherwise the
// cluster-scoped instance is read and ns is ignored. A NoMatchError (the
// Manager CRD is not registered) is returned to the caller rather than treated
// as not-found: absence of the CRD is distinct from the user not having created
// a Manager, and the caller decides how to handle it.
func GetManager(ctx context.Context, cli client.Client, multiTenant bool, ns string) (*operatorv1.Manager, error) {
	key := DefaultEnterpriseInstanceKey
	if multiTenant {
		key.Namespace = ns
	}
	instance := &operatorv1.Manager{}
	if err := cli.Get(ctx, key, instance); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return instance, nil
}

// Return the ManagementCluster CR if present. No error is returned if it was not found.
func GetManagementCluster(ctx context.Context, c client.Client) (*operatorv1.ManagementCluster, error) {
	managementCluster := &operatorv1.ManagementCluster{}

	err := c.Get(ctx, DefaultEnterpriseInstanceKey, managementCluster)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return managementCluster, nil
}

// Return the ManagementClusterConnection CR if present. No error is returned if it was not found.
func GetManagementClusterConnection(ctx context.Context, c client.Client) (*operatorv1.ManagementClusterConnection, error) {
	managementClusterConnection := &operatorv1.ManagementClusterConnection{}

	err := c.Get(ctx, DefaultEnterpriseInstanceKey, managementClusterConnection)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return managementClusterConnection, nil
}

type ClientObjType[E any] interface {
	*E
	client.Object
}

func GetIfExists[E any, ClientObj ClientObjType[E]](ctx context.Context, key client.ObjectKey, c client.Client) (*E, error) {
	obj := new(E)

	err := c.Get(ctx, key, ClientObj(obj))
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return obj, nil
}

// RBACManagementEnabled reports whether the RBAC management UI should be rendered.
// The feature is Enterprise-only, and multi-tenant force-disables it on the ui-apis
// side. Otherwise the admin's switch decides; an absent ConfigMap reads as disabled.
func RBACManagementEnabled(ctx context.Context, c client.Client, variant operatorv1.ProductVariant, multiTenant bool) (bool, error) {
	if !variant.IsEnterprise() || multiTenant {
		return false, nil
	}
	gate, err := GetIfExists[corev1.ConfigMap](ctx, client.ObjectKey{
		Name: rbacmanagement.ConfigMapName, Namespace: common.CalicoNamespace,
	}, c)
	if err != nil {
		return false, err
	}
	return rbacmanagement.Enabled(gate), nil
}

// GetNonClusterHost finds the NonClusterHost CR in your cluster.
func GetNonClusterHost(ctx context.Context, cli client.Client) (*operatorv1.NonClusterHost, error) {
	nonclusterhost := &operatorv1.NonClusterHost{}

	err := cli.Get(ctx, DefaultEnterpriseInstanceKey, nonclusterhost)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return nonclusterhost, nil
}

// GetAuthentication finds the authentication CR in your cluster.
func GetAuthentication(ctx context.Context, cli client.Client) (*operatorv1.Authentication, error) {
	authentication := &operatorv1.Authentication{}
	err := cli.Get(ctx, DefaultEnterpriseInstanceKey, authentication)
	if err != nil {
		return nil, err
	}

	return authentication, nil
}

// GetTenant returns the Tenant instance in the given namespace.
func GetTenant(ctx context.Context, mt bool, cli client.Client, ns string) (*operatorv1.Tenant, string, error) {
	if !mt {
		// Multi-tenancy isn't enabled. Return nil.
		return nil, "", nil
	}

	key := client.ObjectKey{Name: "default", Namespace: ns}
	instance := &operatorv1.Tenant{}
	err := cli.Get(ctx, key, instance)
	if err != nil {
		return nil, "", err
	}

	if instance.Spec.ID == "" {
		return nil, "", fmt.Errorf("tenant %s/%s has no ID specified", ns, instance.Name)
	}
	return instance, instance.Spec.ID, nil
}

// TenantNamespaces returns all namespaces that contain a tenant.
// include is an optional filter function that returns true if the tenant should be included, false otherwise.
func TenantNamespaces(ctx context.Context, cli client.Client, include TenantFilter) ([]string, error) {
	namespaces := []string{}
	tenants := operatorv1.TenantList{}
	err := cli.List(ctx, &tenants)
	if err != nil {
		return nil, err
	}
	for _, t := range tenants.Items {
		if include == nil || include(&t) {
			namespaces = append(namespaces, t.Namespace)
		}
	}

	// Sort the namespaces, so that the output is deterministic.
	sort.Strings(namespaces)
	return namespaces, nil
}

// GetInstallationStatus returns the current installation status, for use by other controllers.
func GetInstallationStatus(ctx context.Context, client client.Client) (*operatorv1.InstallationStatus, error) {
	// Fetch the Installation instance. We only support a single instance named "default".
	instance := &operatorv1.Installation{}
	if err := client.Get(ctx, DefaultInstanceKey, instance); err != nil {
		return nil, err
	}
	return &instance.Status, nil
}

// GetInstallationSpec returns the current installation, accounting for overlays. Controllers take
// the variant from their ControllerOptions instead, so that the whole process agrees on one value.
func GetInstallationSpec(ctx context.Context, client client.Client) (*operatorv1.InstallationSpec, error) {
	// Fetch the Installation instance. We only support a single instance named "default".
	instance := &operatorv1.Installation{}
	if err := client.Get(ctx, DefaultInstanceKey, instance); err != nil {
		return nil, err
	}

	spec := instance.Spec

	// update Installation with 'overlay'
	overlay := operatorv1.Installation{}
	if err := client.Get(ctx, OverlayInstanceKey, &overlay); err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}
	} else {
		spec = OverrideInstallationSpec(spec, overlay.Spec)
	}

	return &spec, nil
}

// GetAPIServer finds the correct API server instance and returns a message and error in the case of an error.
func GetAPIServer(ctx context.Context, client client.Client) (*operatorv1.APIServer, string, error) {
	// Fetch the APIServer instance. Look for the "default" instance first.
	instance := &operatorv1.APIServer{}
	err := client.Get(ctx, DefaultInstanceKey, instance)
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, "failed to get apiserver 'default'", err
		}

		// Default instance doesn't exist. Check for the legacy (enterprise only) CR.
		err = client.Get(ctx, DefaultEnterpriseInstanceKey, instance)
		if err != nil {
			return nil, "failed to get apiserver 'tigera-secure'", err
		}
	} else {
		// Assert there is no legacy "tigera-secure" instance present.
		err = client.Get(ctx, DefaultEnterpriseInstanceKey, instance)
		if err == nil {
			return nil,
				"Duplicate configuration detected",
				fmt.Errorf("multiple APIServer CRs provided. To fix, run \"kubectl delete apiserver tigera-secure\"")
		}
	}
	return instance, "", nil
}

// GetPacketCapture finds the PacketCapture CR in your cluster.
func GetPacketCaptureAPI(ctx context.Context, cli client.Client) (*operatorv1.PacketCaptureAPI, error) {
	pc := &operatorv1.PacketCaptureAPI{}
	err := cli.Get(ctx, DefaultEnterpriseInstanceKey, pc)
	if err != nil {
		return nil, err
	}

	return pc, nil
}

// GetElasticLicenseType returns the license type from elastic-licensing ConfigMap that ECK operator keeps updated.
func GetElasticLicenseType(ctx context.Context, cli client.Client, logger logr.Logger) (render.ElasticsearchLicenseType, error) {
	cm := &corev1.ConfigMap{}
	err := cli.Get(ctx, client.ObjectKey{Name: eck.LicenseConfigMapName, Namespace: eck.OperatorNamespace}, cm)
	if err != nil {
		return render.ElasticsearchLicenseTypeUnknown, err
	}
	license, ok := cm.Data["eck_license_level"]
	if !ok {
		return render.ElasticsearchLicenseTypeUnknown, fmt.Errorf("eck_license_level not available")
	}

	return StrToElasticLicenseType(license, logger), nil
}

// StrToElasticLicenseType maps Elasticsearch license to one of the known and expected value.
func StrToElasticLicenseType(license string, logger logr.Logger) render.ElasticsearchLicenseType {
	if license == string(render.ElasticsearchLicenseTypeEnterprise) ||
		license == string(render.ElasticsearchLicenseTypeBasic) ||
		license == string(render.ElasticsearchLicenseTypeEnterpriseTrial) {
		return render.ElasticsearchLicenseType(license)
	}
	logger.V(3).Info("Elasticsearch license %s is unexpected", license)
	return render.ElasticsearchLicenseTypeUnknown
}

type resourceWatchContext struct {
	predicate predicate.Predicate
	logger    logr.Logger
}

// WaitToAddResourceWatch will check if the required CRD APIs are available and if so, it will add a watch for the
// resource. The completion of this operation will be signaled on a ready channel.
// An optional predicate can be provided to override the default generation-based predicate for all
// watched objects. This is useful for resources whose meaningful changes are status-only updates
// that don't bump generation (e.g., DatastoreMigration phase transitions).
func WaitToAddResourceWatch(controller ctrlruntime.Controller, c kubernetes.Interface, log logr.Logger, flag *ReadyFlag, objs []client.Object, predicates ...predicate.Predicate) {
	// Track resources left to watch and establish their watch context.
	resourcesToWatch := map[client.Object]resourceWatchContext{}
	for _, obj := range objs {
		pred := createPredicateForObject(obj)
		if len(predicates) > 0 {
			pred = predicate.And(predicates...)
		}
		resourcesToWatch[obj] = resourceWatchContext{
			predicate: pred,
			logger:    ContextLoggerForResource(log, obj),
		}
	}

	maxDuration := 30 * time.Second
	duration := 1 * time.Second
	ticker := time.NewTicker(duration)
	defer ticker.Stop()
	for range ticker.C {
		duration = duration * 2
		if duration >= maxDuration {
			duration = maxDuration
		}
		ticker.Reset(duration)

		for obj := range resourcesToWatch {
			objLog := resourcesToWatch[obj].logger
			predicateFn := resourcesToWatch[obj].predicate
			gvk := obj.GetObjectKind().GroupVersionKind()
			if ok, err := isResourceReady(c, gvk); err != nil {
				msg := "Failed to check if resource is ready - will retry"
				if errors.IsNotFound(err) {
					objLog.WithValues("Error", err).V(2).Info(msg)
				} else {
					objLog.WithValues("Error", err).Info(msg)
				}
			} else if !ok {
				objLog.Info("Waiting for resource to be ready to watch - will retry watch attempt")
			} else if err := controller.WatchObject(obj, &handler.EnqueueRequestForObject{}, predicateFn); err != nil {
				objLog.WithValues("Error", err).Info("Failed to watch resource - will retry")
			} else {
				objLog.V(2).Info("Successfully watching resource")
				delete(resourcesToWatch, obj)
			}
		}

		if len(resourcesToWatch) == 0 {
			if flag != nil {
				flag.MarkAsReady()
			}
			return
		}
	}
}

// isResourceReady checks if the specified resource is available.
func isResourceReady(client kubernetes.Interface, gvk schema.GroupVersionKind) (bool, error) {
	gv := gvk.GroupVersion()
	if gv.Empty() {
		// Default to the Calico group and version if not specified so existing callers that only
		// provide the Kind continue to function.
		var err error
		gv, err = schema.ParseGroupVersion(v3.GroupVersionCurrent)
		if err != nil {
			return false, err
		}
	}

	// Only get the resources for the groupVersion we care about so that we are resilient to other
	// apiservices being down.
	res, err := client.Discovery().ServerResourcesForGroupVersion(gv.String())
	if err != nil {
		return false, err
	}
	for _, r := range res.APIResources {
		if gvk.Kind == r.Kind {
			return true, nil
		}
	}
	return false, nil
}

// Creates a predicate for CRUD operations that matches the object's namespace, and name if provided.
// If neither name nor namespace is provided, all objects will be matched.
func createPredicateForObject(objMeta metav1.Object) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			if objMeta.GetName() == "" && objMeta.GetNamespace() == "" {
				// No name or namespace match was specified. Match everything.
				return true
			}
			if objMeta.GetName() != "" && e.Object.GetName() != objMeta.GetName() {
				// A name match was specified, and the object doesn't match.
				return false
			}

			// A name match was specified and the name matches, or this is just a namespace match.
			// Return a match if the namespaces match, or if no namespace match was given.
			return e.Object.GetNamespace() == objMeta.GetNamespace() || objMeta.GetNamespace() == ""
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Not all objects use/have a generation, so we can't always rely on that to determine if the
			// object has changed. The generation will be 0 if it's not set.
			generationChanged := e.ObjectOld.GetGeneration() == 0 || e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()

			if objMeta.GetName() == "" && objMeta.GetNamespace() == "" {
				// No name or namespace match was specified. Match everything, assuming the generation has changed.
				return generationChanged
			}

			if objMeta.GetName() != "" && e.ObjectNew.GetName() != objMeta.GetName() {
				// A name match was specified, and the object doesn't match it.
				return false
			}
			// A name match was specified and the name matches, or this is just a namespace match.
			// Assuming the generation has changed, return a match if the namespaces also match,
			// or if no namespace was given to match against.
			return generationChanged && (e.ObjectNew.GetNamespace() == objMeta.GetNamespace() || objMeta.GetNamespace() == "")
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			if objMeta.GetName() == "" && objMeta.GetNamespace() == "" {
				return true
			}
			if objMeta.GetName() != "" && e.Object.GetName() != objMeta.GetName() {
				return false
			}
			return e.Object.GetNamespace() == objMeta.GetNamespace() || objMeta.GetNamespace() == ""
		},
	}
}

// ValidateResourceNameIsQualified returns a compiled list of errors which states which rule the name
// did not respect. Returns nil if it's a valid name.
func ValidateResourceNameIsQualified(name string) error {
	errors := validation.IsDNS1123Subdomain(name)

	if len(errors) > 0 {
		return fmt.Errorf("%s is not a qualified resource name with errors: %s", name, strings.Join(errors[:], ", "))
	}

	return nil
}

// AddTigeraStatusWatch creates a watch on the given object. It uses predicates to only return matching objects.
func AddTigeraStatusWatch(c ctrlruntime.Controller, name string) error {
	return c.WatchObject(&operatorv1.TigeraStatus{ObjectMeta: metav1.ObjectMeta{Name: name}}, &handler.EnqueueRequestForObject{}, predicate.NewPredicateFuncs(func(object client.Object) bool {
		return object.GetName() == name
	}))
}

// GetKubeControllerMetricsPort fetches kube controller metrics port.
func GetKubeControllerMetricsPort(ctx context.Context, client client.Client) (int, error) {
	kubeControllersConfig := &v3.KubeControllersConfiguration{}
	kubeControllersMetricsPort := 0

	// Query the KubeControllersConfiguration object. We'll use this to help configure kube-controllers metric port.
	err := client.Get(ctx, types.NamespacedName{Name: "default"}, kubeControllersConfig)
	if err != nil && !errors.IsNotFound(err) {
		return 0, err
	}

	if kubeControllersConfig.Spec.PrometheusMetricsPort != nil {
		kubeControllersMetricsPort = *kubeControllersConfig.Spec.PrometheusMetricsPort
	}
	return kubeControllersMetricsPort, nil
}

func GetElasticsearch(ctx context.Context, c client.Client) (*esv1.Elasticsearch, error) {
	es := esv1.Elasticsearch{}
	err := c.Get(ctx, client.ObjectKey{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}, &es)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &es, nil
}

// AddKubeProxyWatch creates a watch on the kube-proxy DaemonSet.
func AddKubeProxyWatch(c ctrlruntime.Controller) error {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: KubeProxyInstanceKey.Namespace,
			Name:      KubeProxyInstanceKey.Name,
		},
	}
	return c.WatchObject(&appsv1.DaemonSet{}, &handler.EnqueueRequestForObject{}, createPredicateForObject(ds))
}

func IsNodeLocalDNSAvailable(ctx context.Context, cli client.Client) (bool, error) {
	ds := &appsv1.DaemonSet{}

	err := cli.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: "node-local-dns"}, ds)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		} else {
			return false, err
		}
	}

	return true, nil
}

// AddNodeLocalDNSWatch creates a watch on the node-local-dns pods.
func AddNodeLocalDNSWatch(c ctrlruntime.Controller) error {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "node-local-dns",
		},
	}
	return c.WatchObject(&appsv1.DaemonSet{}, &handler.EnqueueRequestForObject{}, createPredicateForObject(ds))
}

func GetDNSServiceIPs(ctx context.Context, client client.Client, provider operatorv1.Provider) ([]string, error) {
	// Discover the DNS Service's cluster IP address:
	// Default kubernetes dns service is named "kube-dns", but RKE2 is using a different name for the default
	// dns service i.e. "rke2-coredns-rke2-coredns".
	dnsServiceName := "kube-dns"
	if provider.IsRKE2() {
		dnsServiceName = "rke2-coredns-rke2-coredns"
	}

	kubeDNSService := &corev1.Service{}

	err := client.Get(ctx, types.NamespacedName{Name: dnsServiceName, Namespace: "kube-system"}, kubeDNSService)
	if err != nil {
		return nil, err
	}

	return kubeDNSService.Spec.ClusterIPs, nil
}

// GetDNSServiceName returns the name and namespace for the DNS service based on the given provider.
// This is "kube-dns" for most providers, but varies on OpenShift and RKE2.
func GetDNSServiceName(provider operatorv1.Provider) types.NamespacedName {
	kubeDNSServiceName := types.NamespacedName{Name: "kube-dns", Namespace: "kube-system"}
	if provider.IsOpenShift() {
		kubeDNSServiceName = types.NamespacedName{Name: "dns-default", Namespace: "openshift-dns"}
	} else if provider.IsRKE2() {
		kubeDNSServiceName = types.NamespacedName{Name: "rke2-coredns-rke2-coredns", Namespace: "kube-system"}
	}
	return kubeDNSServiceName
}

// MonitorConfigMap exits the operator if the given ConfigMap's data is changed.
func MonitorConfigMap(ctx context.Context, ca ctrlcache.Cache, name string, data map[string]string) error {
	// The cache isn't running yet, so don't wait on a sync that can't happen.
	informer, err := ca.GetInformer(ctx, &corev1.ConfigMap{}, ctrlcache.BlockUntilSynced(false))
	if err != nil {
		return err
	}

	// The shared cache isn't filtered to this ConfigMap, so match on it here.
	namespace := common.OperatorNamespace()
	check := func(obj interface{}) {
		cm, ok := obj.(*corev1.ConfigMap)
		if !ok || cm.Name != name || cm.Namespace != namespace {
			return
		}

		if compareMap(data, cm.Data) {
			log.Info("ignoring configmap event as data was not modified")
			return
		}

		log.Info("detected config change. rebooting")
		os.Exit(0)
	}

	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    check,
		UpdateFunc: func(_, newObj interface{}) { check(newObj) },
	})
	return err
}

func compareMap(m1, m2 map[string]string) bool {
	if len(m1) != len(m2) {
		return false
	}
	for k, v := range m1 {
		if m2[k] != v {
			return false
		}
	}
	return true
}

func DexEnabled(authentication *operatorv1.Authentication) bool {
	enableDex := authentication != nil
	if enableDex && authentication.Spec.OIDC != nil && authentication.Spec.OIDC.Type == operatorv1.OIDCTypeTigera {
		enableDex = false
	}
	return enableDex
}

func VerifySysctl(pluginData []operatorv1.Sysctl) error {
	for _, setting := range pluginData {
		if _, ok := AllowedSysctlKeys[setting.Key]; !ok {
			return fmt.Errorf("key %s is not allowed in spec.calicoNetwork.sysctl", setting.Key)
		}
	}
	return nil
}

func GetPodEnvVar(spec corev1.PodSpec, name, key string) *string {
	c := getContainer(spec, name)
	for _, e := range c.Env {
		if e.Name == key {
			if e.ValueFrom == nil {
				return &e.Value
			}
		}
	}
	return nil
}

func getContainer(spec corev1.PodSpec, name string) *corev1.Container {
	for _, container := range spec.Containers {
		if container.Name == name {
			return &container
		}
	}
	for _, container := range spec.InitContainers {
		if container.Name == name {
			return &container
		}
	}
	return nil
}

func SetInstallationFinalizer(i *operatorv1.Installation, finalizer string) {
	if !stringsutil.StringInSlice(finalizer, i.GetFinalizers()) {
		i.SetFinalizers(append(i.GetFinalizers(), finalizer))
	}
}

func RemoveInstallationFinalizer(i *operatorv1.Installation, finalizer string) {
	if stringsutil.StringInSlice(finalizer, i.GetFinalizers()) {
		i.SetFinalizers(stringsutil.RemoveStringInSlice(finalizer, i.GetFinalizers()))
	}
}

// MaintainInstallationFinalizer manages a controller's finalizer on the Installation resource.
// We add a finalizer to the Installation when the mainResource has been installed, and only remove that finalizer when
// the resource has been deleted and its secondary resources have stopped running. This allows for a graceful cleanup of any resources
// prior to the CNI plugin being removed.
// The bool return value indicates if the finalizer is Set
func MaintainInstallationFinalizer(
	ctx context.Context,
	c client.Client,
	mainResource client.Object,
	finalizer string,
	secondaryResources ...client.Object,
) (bool, error) {
	finalizerSet := false
	// Get the Installation.
	installation := &operatorv1.Installation{}
	if err := c.Get(ctx, DefaultInstanceKey, installation); err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Installation config not found")
			return finalizerSet, nil
		}
		log.Error(err, "An error occurred when querying the Installation resource")
		return finalizerSet, err
	}
	// Use optimistic locking so that concurrent finalizer patches from different controllers
	// (e.g., whisker and goldmane) produce a conflict error instead of silently overwriting
	// each other. JSON merge patch replaces the entire finalizers array, so without the lock
	// the second writer wins and the first controller's finalizer is lost until re-reconciliation.
	patchFrom := client.MergeFromWithOptions(installation.DeepCopy(), client.MergeFromWithOptimisticLock{})

	// Determine the correct finalizers to apply to the Installation.
	if mainResource != nil {
		// Add a finalizer indicating that the mainResource is still available.
		SetInstallationFinalizer(installation, finalizer)
		finalizerSet = true
	} else {
		// Remove the finalizer. We can skip this check if the finalizer is already not present.
		if !stringsutil.StringInSlice(finalizer, installation.GetFinalizers()) {
			log.V(2).Info("Finalizer not present, skipping removal", "finalizer", finalizer)
			return finalizerSet, nil
		}
		finalizerSet = true

		// Check if the namespaced secondaryResources are still present.
		// Keep track of all the secondary resources that the main resource creates.
		// Only delete the finalizer if all of the secondary resources are deleted and there are no lingering Pods.
		for _, secondaryResource := range secondaryResources {
			err := c.Get(ctx, types.NamespacedName{Namespace: secondaryResource.GetNamespace(), Name: secondaryResource.GetName()}, secondaryResource)
			if err != nil && !errors.IsNotFound(err) {
				return finalizerSet, err
			} else if errors.IsNotFound(err) {
				log.Info("Object no longer exists.", "object", secondaryResource)
			} else {
				log.Info("Object is still present, waiting for termination", "object", secondaryResource)
				return finalizerSet, nil
			}

			// If the secondary resource itself is gone, ensure there are no Pods left over from this resource.
			terminated, err := AllPodsTerminated(ctx, c, secondaryResource)
			if err != nil {
				return finalizerSet, err
			}
			if !terminated {
				log.Info("Pods for object are still present, waiting for termination", "object", secondaryResource)
				return finalizerSet, nil
			}
		}
		log.Info("All objects no longer exist. Removing finalizer", "finalizer", finalizer)
		RemoveInstallationFinalizer(installation, finalizer)
		finalizerSet = false
	}

	// Update the installation with any finalizer changes.
	return finalizerSet, c.Patch(ctx, installation, patchFrom)
}

func AllPodsTerminated(ctx context.Context, c client.Client, obj client.Object) (bool, error) {
	// Find the selector to use for listing Pods owned by obj.
	matchLabels := getMatchLabels(obj)
	if matchLabels == nil {
		// This resource doesn't have a selector, so it can't own Pods.
		return true, nil
	}

	// List the Pods in the same namespace as obj, matching the selector.
	podList := &corev1.PodList{}
	if err := c.List(ctx, podList, client.InNamespace(obj.GetNamespace()), client.MatchingLabels(matchLabels)); err != nil {
		return false, err
	}
	return len(podList.Items) == 0, nil
}

func RestoreV3Metadata(obj client.Object) error {
	if v3metaJSON, ok := obj.GetAnnotations()["projectcalico.org/metadata"]; ok {
		v3meta := metav1.ObjectMeta{}
		err := json.Unmarshal([]byte(v3metaJSON), &v3meta)
		if err != nil {
			return err
		}

		// Restore the v3 metadata we care about.
		obj.SetLabels(v3meta.Labels)
		obj.SetAnnotations(v3meta.Annotations)
		log.V(1).Info("Restored v3 resource metadata", "labels", v3meta.Labels, "annotations", v3meta.Annotations)
	}
	return nil
}

// getMatchLabels extracts the matchLabels from the given workload object.
// Returns nil if the object is not a supported workload type or if it has no matchLabels.
// TODO: This should be extended with full label selector support if we ever need to support more complex matching.
func getMatchLabels(obj client.Object) map[string]string {
	switch o := obj.(type) {
	case *appsv1.Deployment:
		if o.Spec.Selector != nil && o.Spec.Selector.MatchLabels != nil {
			return o.Spec.Selector.MatchLabels
		}
		// If the Selector or MatchLabels is nil then assume it isn't populated and return the operator default
		if o.Spec.Selector == nil || o.Spec.Selector.MatchLabels == nil {
			return map[string]string{"k8s-app": o.Name}
		}
	case *appsv1.DaemonSet:
		if o.Spec.Selector != nil && o.Spec.Selector.MatchLabels != nil {
			return o.Spec.Selector.MatchLabels
		}
		// If the Selector or MatchLabels is nil then assume it isn't populated and return the operator default
		if o.Spec.Selector == nil || o.Spec.Selector.MatchLabels == nil {
			return map[string]string{"k8s-app": o.Name}
		}
	case *appsv1.StatefulSet:
		if o.Spec.Selector != nil && o.Spec.Selector.MatchLabels != nil {
			return o.Spec.Selector.MatchLabels
		}
	}
	return nil
}
