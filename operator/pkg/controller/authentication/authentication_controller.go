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

package authentication

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"golang.org/x/net/http/httpproxy"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	csiv1 "sigs.k8s.io/secrets-store-csi-driver/apis/v1"

	oprv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/controller/utils/imageset"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	"github.com/projectcalico/calico/operator/pkg/dns"
	eutils "github.com/projectcalico/calico/operator/pkg/enterprise/utils"
	"github.com/projectcalico/calico/operator/pkg/render"
	rcertificatemanagement "github.com/projectcalico/calico/operator/pkg/render/certificatemanagement"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

var log = logf.Log.WithName("controller_authentication")

const (
	controllerName = "authentication-controller"

	defaultNameAttribute string = "uid"

	ResourceName = "authentication"
)

// Add creates a new authentication Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.Variant.IsEnterprise() {
		// No need to start this controller.
		return nil
	}

	// Create the reconciler
	tierWatchReady := &utils.ReadyFlag{}
	reconciler := newReconciler(mgr, opts, tierWatchReady)

	// Create a new controller
	c, err := ctrlruntime.NewController(controllerName, mgr, controller.Options{Reconciler: reconcile.Reconciler(reconciler)})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	go utils.WaitToAddTierWatch(networkpolicy.CalicoTierName, c, opts.K8sClientset, log, tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(c, opts.K8sClientset, log, []types.NamespacedName{
		{Name: render.DexPolicyName, Namespace: render.DexNamespace},
		{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: render.DexNamespace},
	})

	var secretProviderClasses []client.Object
	for _, namespace := range []string{render.DexNamespace, common.OperatorNamespace()} {
		secretProviderClasses = append(secretProviderClasses, &csiv1.SecretProviderClass{
			TypeMeta:   metav1.TypeMeta{Kind: "SecretProviderClass", APIVersion: "secrets-store.csi.x-k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: render.OIDCSecretProviderClassName, Namespace: namespace},
		})
	}
	go utils.WaitToAddResourceWatch(c, opts.K8sClientset, log, nil, secretProviderClasses)

	// Watch for changes to the dex namespace.
	if err = c.WatchObject(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch dex namespace: %w", controllerName, err)
	}

	return add(mgr, c)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.ControllerOptions, tierWatchReady *utils.ReadyFlag) *ReconcileAuthentication {
	r := &ReconcileAuthentication{
		client:         mgr.GetClient(),
		scheme:         mgr.GetScheme(),
		provider:       opts.DetectedProvider,
		status:         status.New(mgr.GetClient(), "authentication", opts.KubernetesVersion),
		clusterDomain:  opts.ClusterDomain,
		variant:        opts.Variant,
		tierWatchReady: tierWatchReady,
		multiTenant:    opts.MultiTenant,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// add adds watches for resources that are available at startup
func add(mgr manager.Manager, c ctrlruntime.Controller) error {
	err := c.WatchObject(&oprv1.Authentication{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch resource: %w", controllerName, err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch installation resource: %w", controllerName, err)
	}

	err = c.WatchObject(&oprv1.ManagementClusterConnection{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch resource: %w", controllerName, err)
	}

	for _, namespace := range []string{common.OperatorNamespace(), render.DexNamespace} {
		for _, secretName := range []string{
			render.DexTLSSecretName, render.OIDCSecretName, render.OpenshiftSecretName,
			render.DexObjectName, certificatemanagement.CASecretName,
		} {
			if err = utils.AddSecretsWatch(c, secretName, namespace); err != nil {
				return fmt.Errorf("%s failed to watch the secret '%s' in '%s' namespace: %w", controllerName, secretName, namespace, err)
			}
		}
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch ImageSet: %w", controllerName, err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("authentication-controller failed to watch authentication Tigerastatus: %w", err)
	}

	return nil
}

// blank assignment to verify that ReconcileAuthentication implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileAuthentication{}

// ReconcileAuthentication reconciles an Authentication object
type ReconcileAuthentication struct {
	client                     client.Client
	scheme                     *runtime.Scheme
	provider                   oprv1.Provider
	status                     status.StatusManager
	clusterDomain              string
	variant                    oprv1.ProductVariant
	tierWatchReady             *utils.ReadyFlag
	multiTenant                bool
	resolvedPodProxies         []*httpproxy.Config
	lastAvailabilityTransition metav1.Time
}

// Reconcile the cluster state with the Authentication object that is found in the cluster.
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileAuthentication) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling ", "controller", controllerName)

	// Fetch the Authentication spec. If present, we deploy dex in the cluster.
	authentication, err := eutils.GetAuthentication(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	r.status.OnCRFound()

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&authentication.ObjectMeta)

	// Changes for updating application layer status conditions
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &oprv1.TigeraStatus{}
		err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		authentication.Status.Conditions = status.UpdateStatusCondition(authentication.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, authentication); err != nil {
			log.WithValues("reason", err).Info("Failed to create authentication status conditions.")
			return reconcile.Result{}, err
		}
	}

	reqLogger.V(2).Info("Loaded config", "config", authentication)
	preDefaultPatchFrom := client.MergeFrom(authentication.DeepCopy())

	// Set defaults for backwards compatibility.
	updateAuthenticationWithDefaults(authentication)

	// Validate the configuration
	if err := validateAuthentication(authentication, r.multiTenant); err != nil {
		r.status.SetDegraded(oprv1.ResourceValidationError, "Invalid Authentication provided", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Write the authentication back to the datastore, so the controllers depending on this can reconcile.
	if err = r.client.Patch(ctx, authentication, preDefaultPatchFrom); err != nil {
		r.status.SetDegraded(oprv1.ResourcePatchError, "Failed to write defaults", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Query for the installation object.
	installationSpec, err := utils.GetComputedInstallationSpec(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(oprv1.ResourceNotFound, "Installation not found", err, reqLogger)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(oprv1.ResourceReadError, "Error querying installation", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(oprv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Ensure the calico-system tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.CalicoTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(oprv1.ResourceNotReady, "Waiting for calico-system tier to be created, see the 'tiers' TigeraStatus for more information", err, reqLogger)
			return reconcile.Result{}, nil
		} else {
			r.status.SetDegraded(oprv1.ResourceReadError, "Error querying calico-system tier", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Make sure Authentication and ManagementClusterConnection are not present at the same time.
	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if managementClusterConnection != nil {
		log.Error(fmt.Errorf("only one of Authentication and ManagementClusterConnection may be specified"), "")
		r.status.SetDegraded(oprv1.ResourceValidationError, "Only one of Authentication and ManagementClusterConnection may be specified", nil, reqLogger)
		return reconcile.Result{}, err
	} else if err != nil {
		r.status.SetDegraded(oprv1.ResourceReadError, "Error querying ManagementClusterConnection", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Secret used for TLS between dex and other components.
	certificateManager, err := certificatemanager.Create(r.client, installationSpec, r.clusterDomain, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(oprv1.ResourceCreateError, "Unable to create the Tigera CA", err, reqLogger)
		return reconcile.Result{}, err
	}

	dnsNames := dns.GetServiceDNSNames(render.DexObjectName, render.DexNamespace, r.clusterDomain)
	tlsKeyPair, err := certificateManager.GetOrCreateKeyPair(r.client, render.DexTLSSecretName, common.OperatorNamespace(), dnsNames)
	if err != nil {
		r.status.SetDegraded(oprv1.ResourceReadError, "Unable to get or create tls key pair", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Dex needs to trust a public CA, so we mount all the system certificates.
	trustedBundle, err := certificateManager.CreateTrustedBundleWithSystemRootCertificates()
	if err != nil {
		r.status.SetDegraded(oprv1.ResourceCreateError, "Unable to create tigera-ca-bundle configmap", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Dex will be configured with the contents of this secret, such as clientID and clientSecret.
	secretProviderClass, idpSecret, err := eutils.GetSecretOrProviderClass(ctx, r.client, authentication)
	if err != nil {
		r.status.SetDegraded(oprv1.ResourceValidationError, "Invalid or missing IDP secret or IDP secret provider", err, reqLogger)
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.client)
	if err != nil {
		r.status.SetDegraded(oprv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Determine the current deployment availability.
	var currentAvailabilityTransition metav1.Time
	var currentlyAvailable bool
	dexDeployment := v1.Deployment{}
	err = r.client.Get(ctx, client.ObjectKey{Name: render.DexObjectName, Namespace: render.DexNamespace}, &dexDeployment)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(oprv1.ResourceReadError, "Failed to read the deployment status of Dex", err, reqLogger)
		return reconcile.Result{}, nil
	} else if err == nil {
		for _, condition := range dexDeployment.Status.Conditions {
			if condition.Type == v1.DeploymentAvailable {
				currentAvailabilityTransition = condition.LastTransitionTime
				if condition.Status == corev1.ConditionTrue {
					currentlyAvailable = true
				}
				break
			}
		}
	}

	// Resolve the proxies used by each Dex pod. We only update the resolved proxies if the availability of the
	// Dex deployment has changed since our last reconcile and the deployment is currently available. We restrict
	// the resolution of pod proxies in this way to limit the number of pod queries we make.
	if !currentAvailabilityTransition.Equal(&r.lastAvailabilityTransition) && currentlyAvailable {
		// Query dex pods.
		labelSelector := labels.SelectorFromSet(map[string]string{
			"app.kubernetes.io/name": render.DexObjectName,
		})
		pods := corev1.PodList{}
		err := r.client.List(ctx, &pods, &client.ListOptions{
			LabelSelector: labelSelector,
			Namespace:     render.DexNamespace,
		})
		if err != nil {
			r.status.SetDegraded(oprv1.ResourceReadError, "Failed to list the pods of the Dex deployment", err, reqLogger)
			return reconcile.Result{}, nil
		}

		// Resolve the proxy config for each pod. Pods without a proxy will have a nil proxy config value.
		var podProxies []*httpproxy.Config
		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				if container.Name == render.DexObjectName {
					var podProxyConfig *httpproxy.Config
					var httpProxy, httpsProxy, noProxy string
					for _, env := range container.Env {
						switch env.Name {
						case "http_proxy", "HTTP_PROXY":
							httpProxy = env.Value
						case "https_proxy", "HTTPS_PROXY":
							httpsProxy = env.Value
						case "no_proxy", "NO_PROXY":
							noProxy = env.Value
						}
					}
					if httpProxy != "" || httpsProxy != "" || noProxy != "" {
						podProxyConfig = &httpproxy.Config{
							HTTPProxy:  httpProxy,
							HTTPSProxy: httpsProxy,
							NoProxy:    noProxy,
						}
					}

					podProxies = append(podProxies, podProxyConfig)
				}
			}
		}

		r.resolvedPodProxies = podProxies
	}
	r.lastAvailabilityTransition = currentAvailabilityTransition

	enableDex := eutils.DexEnabled(authentication)

	// DexConfig adds convenience methods around dex related objects in k8s and can be used to configure Dex.
	dexCfg := render.NewDexConfig(installationSpec.CertificateManagement, authentication, idpSecret, secretProviderClass, r.clusterDomain)

	// Create a component handler to manage the rendered component.
	hlr := utils.NewComponentHandler(log, r.client, r.scheme, authentication)

	dexComponentCfg := &render.DexComponentConfiguration{
		PullSecrets:     pullSecrets,
		OpenShift:       r.provider.IsOpenShift(),
		Installation:    installationSpec,
		DexConfig:       dexCfg,
		ClusterDomain:   r.clusterDomain,
		DeleteDex:       !enableDex,
		TLSKeyPair:      tlsKeyPair,
		TrustedBundle:   trustedBundle,
		TigeraCAKeyPair: certificateManager.KeyPair(),
		Authentication:  authentication,
		PodProxies:      r.resolvedPodProxies,
	}

	// Render the desired objects from the CRD and create or update them.
	reqLogger.V(3).Info("rendering components")
	component := render.Dex(dexComponentCfg)

	if err = imageset.ApplyImageSet(ctx, r.client, r.variant, component); err != nil {
		r.status.SetDegraded(oprv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		return reconcile.Result{}, err
	}

	components := []render.Component{component}

	if enableDex {
		components = append(components,
			rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
				Namespace:       render.DexNamespace,
				ServiceAccounts: []string{render.DexObjectName},
				KeyPairOptions: []rcertificatemanagement.KeyPairOption{
					rcertificatemanagement.NewKeyPairOption(tlsKeyPair, true, true),
				},
				TrustedBundle: trustedBundle,
			}),
		)
	}

	for _, comp := range components {
		if err = hlr.CreateOrUpdateOrDelete(context.Background(), comp, r.status); err != nil {
			r.status.SetDegraded(oprv1.ResourceUpdateError, "Error creating / updating resource", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	// Check BYO certificate expiry warnings.
	certificatemanagement.CheckKeyPairWarnings(map[string]certificatemanagement.KeyPairInterface{
		render.DexTLSSecretName: tlsKeyPair,
	}, r.status)

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future.
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	// Everything is available - update the CRD status.
	authentication.Status.State = oprv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, authentication); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

// updateAuthenticationWithDefaults sets values for backwards compatibility.
func updateAuthenticationWithDefaults(authentication *oprv1.Authentication) {
	if authentication.Spec.OIDC != nil {
		if authentication.Spec.OIDC.UsernamePrefix != "" && authentication.Spec.UsernamePrefix == "" {
			authentication.Spec.UsernamePrefix = authentication.Spec.OIDC.UsernamePrefix
		}
		if authentication.Spec.OIDC.GroupsPrefix != "" && authentication.Spec.GroupsPrefix == "" {
			authentication.Spec.GroupsPrefix = authentication.Spec.OIDC.GroupsPrefix
		}
		if authentication.Spec.OIDC.EmailVerification == nil {
			defaultVerification := oprv1.EmailVerificationTypeVerify
			authentication.Spec.OIDC.EmailVerification = &defaultVerification
		}
	}
	ldap := authentication.Spec.LDAP
	if ldap != nil {
		if ldap.UserSearch.NameAttribute == "" {
			ldap.UserSearch.NameAttribute = defaultNameAttribute
		}
	}
}

// validateAuthentication makes sure that the authentication spec is ready for use.
func validateAuthentication(authentication *oprv1.Authentication, multiTenant bool) error {
	oidc := authentication.Spec.OIDC
	ldp := authentication.Spec.LDAP
	// We support using only one connector at once.
	var numConnectors int8 = 0
	if oidc != nil {
		numConnectors++
	}
	if ldp != nil {
		numConnectors++
	}
	if authentication.Spec.Openshift != nil {
		numConnectors++
	}

	if numConnectors == 0 {
		return fmt.Errorf("no identity provider connector was specified, please add a connector to the Authentication spec")
	} else if numConnectors > 1 {
		return fmt.Errorf("multiple identity provider connectors were specified, but only 1 is allowed in the Authentication spec")
	}

	// If the user has specified the deprecated and the new prefix field, but with different values, we cannot proceed.
	if oidc != nil {
		if multiTenant && authentication.Spec.OIDC.Type != oprv1.OIDCTypeTigera {
			return fmt.Errorf("you set an unsupported authentication for multi-tenant, please set Authentication.Spec.OIDC.Type to Tigera")
		}
		if authentication.Spec.OIDC.UsernamePrefix != "" && authentication.Spec.UsernamePrefix != "" && authentication.Spec.OIDC.UsernamePrefix != authentication.Spec.UsernamePrefix {
			return fmt.Errorf("you set username prefix twice, but with different values, please remove Authentication.Spec.OIDC.UsernamePrefix")
		}

		if authentication.Spec.OIDC.GroupsPrefix != "" && authentication.Spec.GroupsPrefix != "" && authentication.Spec.OIDC.GroupsPrefix != authentication.Spec.GroupsPrefix {
			return fmt.Errorf("you set groups prefix twice, but with different values, please remove Authentication.Spec.OIDC.GroupsPrefix")
		}

		promptTypes := authentication.Spec.OIDC.PromptTypes
		if promptTypes != nil && len(authentication.Spec.OIDC.PromptTypes) > 1 {
			for _, pt := range promptTypes {
				if pt == oprv1.PromptTypeNone {
					return fmt.Errorf("you cannot combine PromptType None with other prompt types, please modify Authentication.Spec.OIDC.PromptType")
				}
			}
		}

	}

	if ldp != nil {
		if _, err := ldap.ParseDN(ldp.UserSearch.BaseDN); err != nil {
			return fmt.Errorf("invalid dn for LDAP user search: %w", err)
		}
		if ldp.GroupSearch != nil {
			if _, err := ldap.ParseDN(ldp.GroupSearch.BaseDN); err != nil {
				return fmt.Errorf("invalid dn for LDAP group search: %w", err)
			}
			if ldp.GroupSearch.Filter != "" {
				if _, err := ldap.CompileFilter(ldp.GroupSearch.Filter); err != nil {
					return fmt.Errorf("invalid filter for LDAP group search: %w", err)
				}
			}
		}
		if ldp.UserSearch.Filter != "" {
			if _, err := ldap.CompileFilter(ldp.UserSearch.Filter); err != nil {
				return fmt.Errorf("invalid filter for LDAP user search: %w", err)
			}
		}
	}

	return nil
}
