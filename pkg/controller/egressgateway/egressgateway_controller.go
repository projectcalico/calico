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

package egressgateway

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	ocsv1 "github.com/openshift/api/security/v1"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"

	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/egressgateway"
)

const (
	reconcileErr = "Error_reconciling_Egress_Gateway"
)

var log = logf.Log.WithName("controller_egressgateway")

// Add creates a new EgressGateway Controller and adds it to the Manager.
// The Manager will set fields on the Controller and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	if !opts.Variant.IsEnterprise() {
		// No need to start this controller.
		return nil
	}
	licenseAPIReady := &utils.ReadyFlag{}

	reconciler := newReconciler(mgr, opts, licenseAPIReady)

	c, err := ctrlruntime.NewController("egressgateway-controller", mgr, controller.Options{Reconciler: reconcile.Reconciler(reconciler)})
	if err != nil {
		return err
	}

	go utils.WaitToAddLicenseKeyWatch(c, opts.K8sClientset, log, licenseAPIReady)

	return add(mgr, c)
}

// newReconciler returns a new *reconcile.Reconciler.
func newReconciler(mgr manager.Manager, opts options.ControllerOptions, licenseAPIReady *utils.ReadyFlag) reconcile.Reconciler {
	r := &ReconcileEgressGateway{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        opts.DetectedProvider,
		status:          status.New(mgr.GetClient(), "egressgateway", opts.KubernetesVersion),
		clusterDomain:   opts.ClusterDomain,
		variant:         opts.Variant,
		licenseAPIReady: licenseAPIReady,
	}
	r.status.Run(opts.ShutdownContext)
	return r
}

// add adds watches for resources that are available at startup.
// Watching namespaced resources must be avoided as the controller
// can't differentiate if the request namespaced resource is an
// Egress Gateway resource or not.
func add(_ manager.Manager, c ctrlruntime.Controller) error {
	var err error

	// Watch for changes to primary resource Egress Gateway.
	err = c.WatchObject(&operatorv1.EgressGateway{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("egressgateway-controller failed to watch ImageSet: %w", err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("egressgateway-controller failed to watch Installation resource: %v", err)
	}

	// Watch for changes to FelixConfiguration.
	err = c.WatchObject(&v3.FelixConfiguration{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("egressGateway-controller failed to watch FelixConfiguration resource: %w", err)
	}

	return nil
}

// Blank assignment to verify that ReconcileEgressGateway implements reconcile.Reconciler.
var _ reconcile.Reconciler = &ReconcileEgressGateway{}

// ReconcileEgressGatewayLayer reconciles a EgressGatewayLayer object.
type ReconcileEgressGateway struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver.
	client          client.Client
	scheme          *runtime.Scheme
	provider        operatorv1.Provider
	status          status.StatusManager
	clusterDomain   string
	variant         operatorv1.ProductVariant
	licenseAPIReady *utils.ReadyFlag
}

// Reconcile reads that state of the cluster for an EgressGateway object and makes changes
// based on the state read and what is in the EgressGateway.Spec.
func (r *ReconcileEgressGateway) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling EgressGateway")

	// Get all the Egress Gateway resources available.
	egws, err := getEgressGateways(ctx, r.client)
	if err != nil {
		reqLogger.Error(err, "Error querying for Egress Gateway")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying for Egress Gateway", err, reqLogger)
		return reconcile.Result{}, err
	}

	// If there are no Egress Gateway resources, return.
	ch := utils.NewComponentHandler(log, r.client, r.scheme, nil)
	if len(egws) == 0 {
		var objects []client.Object
		if r.provider.IsOpenShift() {
			objects = append(objects, egressgateway.SecurityContextConstraints())
		}
		err := ch.CreateOrUpdateOrDelete(ctx, render.NewDeletionPassthrough(objects...), r.status)
		if err != nil {
			reqLogger.Error(err, "error deleting cluster scoped resources")
			return reconcile.Result{}, nil
		}
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	/* Reconcile is done as follows.
	1. At the start, assume all the EGW resources need to be reconciled.
	2. If the request is to a particular EGW resource, find the requested EGW from the list of EGWs.
	3. If the requested EGW resource is not present, it could have been deleted.
	   'egws' is now the list of all EGW resources present. Get the cumulative status and update
	   TigeraStatus object.
	4. If the requested EGW resource is present, then it is the only resource to reconcile. Remove this
	   EGW resource from the list and get the status of all the other EGW resources present and update
	   TigeraStatus accordingly.
	5. If the request is not to a particular EGW resource, reconcile all the resources.
	*/

	// egwsToReconcile is the list of Egress Gateway resources that needs to be reconciled.
	// To start with all EGW resources must be reconciled.
	egwsToReconcile := egws
	namespaceAndNames := getEGWNamespaceAndNames(egws)
	if request.Namespace != "" {
		requestedEGW, idx := getRequestedEgressGateway(egws, request)
		if requestedEGW == nil {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			reqLogger.Info("EgressGateway object not found")
			// Since the EGW resource is not found, remove the deployment.
			r.status.RemoveDeployments(types.NamespacedName{Name: request.Name, Namespace: request.Namespace})
			// In the case of OpenShift, we are using a single SCC.
			// Whenever a EGW resource is deleted, remove the corresponding user from the SCC
			// and update the resource.
			if r.provider.IsOpenShift() {
				scc, err := getOpenShiftSCC(ctx, r.client)
				if err != nil {
					reqLogger.Error(err, "Error querying SecurityContextConstraints")
					return reconcile.Result{}, err
				}
				userString := fmt.Sprintf("system:serviceaccount:%s:%s", request.Namespace, request.Name)
				for index, user := range scc.Users {
					if user == userString {
						scc.Users = append(scc.Users[:index], scc.Users[index+1:]...)
						err := ch.CreateOrUpdateOrDelete(ctx, render.NewCreationPassthrough(scc), r.status)
						if err != nil {
							reqLogger.Error(err, "error updating security context constraints")
						}
						break
					}
				}

			}
			// Get the unready EGW. Let's say we have 2 EGW resources red and blue.
			// Red has already degraded. When the user deletes Red, TigeraStatus should go back to available
			// as Blue is healthy. If all the EGWs are ready, clear the degraded TigeraStatus.
			// If at least one of the EGWs is unhealthy, get the degraded msg from the conditions and
			// update the TigeraStatus.
			unreadyEGW := getUnreadyEgressGateway(egws)
			if unreadyEGW != nil {
				r.status.SetDegraded(operatorv1.ResourceNotReady,
					fmt.Sprintf("Error reconciling Egress Gateway resource. Name=%s Namespace=%s", unreadyEGW.Name, unreadyEGW.Namespace),
					fmt.Errorf("%s", getDegradedMsg(unreadyEGW)), reqLogger)
				return reconcile.Result{}, nil
			}
			r.status.ClearDegraded()
			return reconcile.Result{}, nil
		}
		// If the EGW resource is present, reconcile only that resource.
		// Remove this from the list of EGWs before computing status.
		egwsToReconcile = []operatorv1.EgressGateway{*requestedEGW}
		egws = append(egws[:idx], egws[idx+1:]...)
	}
	r.status.OnCRFound()

	// Get the unready EGW.
	unreadyEGW := getUnreadyEgressGateway(egws)

	if !r.licenseAPIReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", nil, reqLogger)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	installationSpec, err := utils.GetInstallationSpec(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Error(err, "Installation not found")
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
			// Set the EGW resource's condition to Degraded.
			for _, egw := range egwsToReconcile {
				setDegraded(r.client, ctx, &egw, reconcileErr, fmt.Sprintf("Installation not found err = %s", err.Error()))
			}
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "Error querying installation")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, reqLogger)
		for _, egw := range egwsToReconcile {
			setDegraded(r.client, ctx, &egw, reconcileErr, fmt.Sprintf("Error querying installation err = %s", err.Error()))
		}
		return reconcile.Result{}, err
	}

	installStatus, err := utils.GetInstallationStatus(ctx, r.client)
	if err != nil {
		reqLogger.Error(err, "Error querying installation status")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation status", err, reqLogger)
		for _, egw := range egwsToReconcile {
			setDegraded(r.client, ctx, &egw, reconcileErr, fmt.Sprintf("Error querying installation status err = %s", err.Error()))
		}
		return reconcile.Result{}, err
	}

	if installStatus.CalicoVersion != components.EnterpriseRelease {
		reqLogger.WithValues("version", components.EnterpriseRelease).Info("Waiting for expected version of Calico to be installed")
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	pullSecrets, err := utils.GetInstallationPullSecrets(installationSpec, r.client)
	if err != nil {
		reqLogger.Error(err, "Error retrieving pull secrets")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, reqLogger)
		for _, egw := range egwsToReconcile {
			setDegraded(r.client, ctx, &egw, reconcileErr, fmt.Sprintf("Error retrieving pull secrets err = %s", err.Error()))
		}
		return reconcile.Result{}, err
	}

	// patch and get the felix configuration
	fc, err := utils.PatchFelixConfiguration(ctx, r.client, func(fc *v3.FelixConfiguration) (bool, error) {
		if fc.Spec.PolicySyncPathPrefix != "" {
			return false, nil // don't proceed with the patch
		}
		fc.Spec.PolicySyncPathPrefix = "/var/run/nodeagent"
		return true, nil // proceed with this patch
	})
	if err != nil {
		reqLogger.Error(err, "Error patching felix configuration")
		r.status.SetDegraded(operatorv1.ResourcePatchError, "Error patching felix configuration", err, reqLogger)
		for _, egw := range egwsToReconcile {
			setDegraded(r.client, ctx, &egw, reconcileErr, fmt.Sprintf("Error patching felix configuration err = %s", err.Error()))
		}
		return reconcile.Result{}, err
	}

	// Reconcile all the EGWs
	var errMsgs []string
	for _, egw := range egwsToReconcile {
		err = r.reconcileEgressGateway(ctx, &egw, reqLogger, r.variant, fc, pullSecrets, installationSpec, namespaceAndNames)
		if err != nil {
			reqLogger.Error(err, "Error reconciling egress gateway")
			errMsgs = append(errMsgs, err.Error())
		}
	}
	if len(errMsgs) != 0 {
		return reconcile.Result{}, fmt.Errorf("%s", strings.Join(errMsgs, ";"))
	}

	if unreadyEGW != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError,
			fmt.Sprintf("Error reconciling Egress Gateway resource. Name=%s Namespace=%s", unreadyEGW.Name, unreadyEGW.Namespace),
			fmt.Errorf("%s", getDegradedMsg(unreadyEGW)), reqLogger)
		return reconcile.Result{}, nil
	}

	r.status.ClearDegraded()
	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future, hopefully by then things will be available.
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileEgressGateway) reconcileEgressGateway(ctx context.Context, egw *operatorv1.EgressGateway, reqLogger logr.Logger,
	variant operatorv1.ProductVariant, fc *v3.FelixConfiguration, pullSecrets []*v1.Secret,
	installationSpec *operatorv1.InstallationSpec, namespaceAndNames []string,
) error {
	preDefaultPatchFrom := client.MergeFrom(egw.DeepCopy())
	// update the EGW resource with default values.
	fillDefaults(egw, installationSpec)
	// Validate the EGW resource.
	err := validateEgressGateway(ctx, r.client, egw)
	if err != nil {
		reqLogger.Error(err, fmt.Sprintf("Error validating Egress Gateway Name = %s, Namespace = %s", egw.Name, egw.Namespace))
		r.status.SetDegraded(operatorv1.ResourceValidationError,
			fmt.Sprintf("Error validating egress gateway Name = %s, Namespace = %s", egw.Name, egw.Namespace), err, reqLogger)
		setDegraded(r.client, ctx, egw, reconcileErr, fmt.Sprintf("Error validating egress gateway err = %s", err.Error()))
		return err
	}

	if err = r.client.Patch(ctx, egw, preDefaultPatchFrom); err != nil {
		reqLogger.Error(err, fmt.Sprintf("Failed to write defaults to egress gateway Name = %s, Namespace = %s", egw.Name, egw.Namespace))
		r.status.SetDegraded(operatorv1.ResourceUpdateError,
			fmt.Sprintf("Failed to write defaults to egress gateway Name = %s, Namespace = %s", egw.Name, egw.Namespace), err, reqLogger)
		setDegraded(r.client, ctx, egw, reconcileErr, fmt.Sprintf("Failed to write defaults to egress gateway err = %s", err.Error()))
		return err
	}

	egwVXLANPort := egressgateway.DefaultVXLANPort
	egwVXLANVNI := egressgateway.DefaultVXLANVNI
	if fc.Spec.EgressIPVXLANPort != nil {
		egwVXLANPort = *fc.Spec.EgressIPVXLANPort
	}
	if fc.Spec.EgressIPVXLANVNI != nil {
		egwVXLANVNI = *fc.Spec.EgressIPVXLANVNI
	}

	ipTablesBackend := ""
	if fc.Spec.IptablesBackend != nil {
		backend := strings.ToLower(string(*fc.Spec.IptablesBackend))
		if backend != "auto" {
			ipTablesBackend = backend
		}
	}

	config := &egressgateway.Config{
		PullSecrets:       pullSecrets,
		Installation:      installationSpec,
		OSType:            rmeta.OSTypeLinux,
		EgressGW:          egw,
		VXLANPort:         egwVXLANPort,
		VXLANVNI:          egwVXLANVNI,
		IptablesBackend:   ipTablesBackend,
		OpenShift:         r.provider.IsOpenShift(),
		NamespaceAndNames: namespaceAndNames,
	}

	component := egressgateway.EgressGateway(config)
	ch := utils.NewComponentHandler(log, r.client, r.scheme, egw)

	if err = imageset.ApplyImageSet(ctx, r.client, variant, component); err != nil {
		reqLogger.Error(err, "Error with images from ImageSet")
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, reqLogger)
		setDegraded(r.client, ctx, egw, reconcileErr, fmt.Sprintf("Error with images from ImageSet err = %s", err.Error()))
		return err
	}

	if err = ch.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		reqLogger.Error(err, fmt.Sprintf("Error creating / updating resource: Name = %s, Namespace = %s", egw.Name, egw.Namespace))
		r.status.SetDegraded(operatorv1.ResourceUpdateError,
			fmt.Sprintf("Error creating / updating resource: Name = %s, Namespace = %s", egw.Name, egw.Namespace), err, reqLogger)
		setDegraded(r.client, ctx, egw, reconcileErr, fmt.Sprintf("Error creating / updating resource err = %s", err.Error()))
		return err
	}

	// Update the status of this CR.
	egw.Status.State = operatorv1.TigeraStatusReady
	setAvailable(r.client, ctx, egw, string(operatorv1.AllObjectsAvailable), "All objects available")
	return nil
}

// getRequestedEgressGateway returns the namespaced EgressGateway instance.
func getRequestedEgressGateway(egws []operatorv1.EgressGateway, request reconcile.Request) (*operatorv1.EgressGateway, int) {
	for index, egw := range egws {
		if request.Name == egw.Name && request.Namespace == egw.Namespace {
			return &egw, index
		}
	}
	return nil, -1
}

// validateEgressGateway checks if the ippools specified are already present.
func validateEgressGateway(ctx context.Context, cli client.Client, egw *operatorv1.EgressGateway) error {
	nativeIP := operatorv1.NativeIPDisabled
	if egw.Spec.AWS != nil && egw.Spec.AWS.NativeIP != nil {
		nativeIP = *egw.Spec.AWS.NativeIP
	}

	// Validate IPPools specified.
	// If name is specified, check IPPool exists.
	// If CIDR is specified, check if CIDR matches with any IPPool.
	// If Aws.NativeIP is enabled, check if the IPPool is backed by aws-subnet ID.
	if len(egw.Spec.IPPools) == 0 {
		return fmt.Errorf("at least one IPPool must be specified")
	}

	for _, ippool := range egw.Spec.IPPools {
		err := validateIPPool(ctx, cli, ippool, nativeIP)
		if err != nil {
			return err
		}
	}

	for _, externalNetwork := range egw.Spec.ExternalNetworks {
		err := validateExternalNetwork(ctx, cli, externalNetwork)
		if err != nil {
			return err
		}
	}

	// Check if ElasticIPs are specified only if NativeIP is enabled.
	if egw.Spec.AWS != nil {
		if len(egw.Spec.AWS.ElasticIPs) > 0 && (*egw.Spec.AWS.NativeIP == operatorv1.NativeIPDisabled) {
			return fmt.Errorf("NativeIP must be enabled when elastic IPs are used")
		}
	}

	// Check if neither ICMPProbe nor HTTPProbe is configured.
	if egw.Spec.EgressGatewayFailureDetection != nil {
		if egw.Spec.EgressGatewayFailureDetection.ICMPProbe == nil &&
			egw.Spec.EgressGatewayFailureDetection.HTTPProbe == nil {
			return fmt.Errorf("either ICMP or HTTP probe must be configured")
		}
		// Check if ICMP and HTTP probe timeout is greater than interval.
		if egw.Spec.EgressGatewayFailureDetection.ICMPProbe != nil {
			if *egw.Spec.EgressGatewayFailureDetection.ICMPProbe.TimeoutSeconds <
				*egw.Spec.EgressGatewayFailureDetection.ICMPProbe.IntervalSeconds {
				return fmt.Errorf("ICMP probe timeout must be greater than interval")
			}
		}
		if egw.Spec.EgressGatewayFailureDetection.HTTPProbe != nil {
			if *egw.Spec.EgressGatewayFailureDetection.HTTPProbe.TimeoutSeconds <
				*egw.Spec.EgressGatewayFailureDetection.HTTPProbe.IntervalSeconds {
				return fmt.Errorf("HTTP probe timeout must be greater than interval")
			}
		}
	}
	return nil
}

// getEgressGateways returns the egress gateways in all namespaces or in the request's namespace.
func getEgressGateways(ctx context.Context, cli client.Client) ([]operatorv1.EgressGateway, error) {
	// Get all the Egress Gateways in all the namespaces.
	instance := &operatorv1.EgressGatewayList{}
	err := cli.List(ctx, instance)
	if err != nil {
		return []operatorv1.EgressGateway{}, err
	}
	return instance.Items, nil
}

func getOpenShiftSCC(ctx context.Context, cli client.Client) (*ocsv1.SecurityContextConstraints, error) {
	scc := &ocsv1.SecurityContextConstraints{
		TypeMeta:   metav1.TypeMeta{Kind: "SecurityContextConstraints", APIVersion: "security.openshift.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: egressgateway.OpenShiftSCCName},
	}
	err := cli.Get(ctx, client.ObjectKey{Name: egressgateway.OpenShiftSCCName}, scc)
	if err != nil {
		return nil, err
	}
	return scc, nil
}

// fillDefaults sets the default values of the EGW resource.
func fillDefaults(egw *operatorv1.EgressGateway, installationSpec *operatorv1.InstallationSpec) {
	defaultAWSNativeIP := operatorv1.NativeIPDisabled

	// Default value of Native IP is Disabled.
	if egw.Spec.AWS != nil && egw.Spec.AWS.NativeIP == nil {
		egw.Spec.AWS.NativeIP = &defaultAWSNativeIP
	}

	// set the default label if not specified.
	defLabel := map[string]string{"projectcalico.org/egw": egw.Name}
	if egw.Spec.Template == nil {
		egw.Spec.Template = &operatorv1.EgressGatewayDeploymentPodTemplateSpec{}
		egw.Spec.Template.Metadata = &operatorv1.EgressGatewayMetadata{Labels: defLabel}
	} else {
		if egw.Spec.Template.Metadata == nil {
			egw.Spec.Template.Metadata = &operatorv1.EgressGatewayMetadata{Labels: defLabel}
		} else {
			if len(egw.Spec.Template.Metadata.Labels) == 0 {
				egw.Spec.Template.Metadata.Labels = defLabel
			}
		}
	}

	// If affinity isn't specified by the user, default pod anti affinity is added so that 2 EGW pods aren't scheduled in
	// the same node. If the provider is AKS, set the node affinity so that pods don't run on virutal-nodes.
	defAffinity := &v1.Affinity{}
	defAffinity.PodAntiAffinity = &v1.PodAntiAffinity{
		PreferredDuringSchedulingIgnoredDuringExecution: []v1.WeightedPodAffinityTerm{
			{
				Weight: 1,
				PodAffinityTerm: v1.PodAffinityTerm{
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: egw.Spec.Template.Metadata.Labels,
					},
					TopologyKey: "topology.kubernetes.io/zone",
				},
			},
		},
	}
	switch installationSpec.KubernetesProvider {
	case operatorv1.ProviderAKS:
		defAffinity.NodeAffinity = &v1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
				NodeSelectorTerms: []v1.NodeSelectorTerm{{
					MatchExpressions: []v1.NodeSelectorRequirement{
						{
							Key:      "type",
							Operator: v1.NodeSelectorOpNotIn,
							Values:   []string{"virtual-node"},
						},
						{
							Key:      "kubernetes.azure.com/cluster",
							Operator: v1.NodeSelectorOpExists,
						},
					},
				}},
			},
		}
	default:
		defAffinity.NodeAffinity = nil
	}

	if egw.Spec.Template.Spec == nil {
		egw.Spec.Template.Spec = &operatorv1.EgressGatewayDeploymentPodSpec{Affinity: defAffinity}
	} else if egw.Spec.Template.Spec.Affinity == nil {
		egw.Spec.Template.Spec.Affinity = defAffinity
	}
}

// validateExternalNetwork validates if the specified external network exists.
func validateExternalNetwork(ctx context.Context, cli client.Client, externalNetwork string) error {
	instance := &v3.ExternalNetwork{}
	key := types.NamespacedName{Name: externalNetwork}
	err := cli.Get(ctx, key, instance)
	if err != nil {
		return err
	}
	return nil
}

// validateIPPool validates if the specified IPPool either by name or cidr, exists. If name and CIDR are provider, the ippool is validated
// to see if they match.
func validateIPPool(ctx context.Context, cli client.Client, ipPool operatorv1.EgressGatewayIPPool, awsNativeIP operatorv1.NativeIP) error {
	if ipPool.Name != "" {
		instance := &v3.IPPool{}
		key := types.NamespacedName{Name: ipPool.Name}
		err := cli.Get(ctx, key, instance)
		if err != nil {
			return err
		}
		if ipPool.CIDR != "" {
			if instance.Spec.CIDR != ipPool.CIDR {
				return fmt.Errorf("IPPool CIDR does not match with name")
			}
		}
		if awsNativeIP == operatorv1.NativeIPEnabled && instance.Spec.AWSSubnetID == "" {
			return fmt.Errorf("AWS subnet ID must be set when NativeIP is enabled")
		}
		return nil
	}
	if ipPool.CIDR != "" {
		instance := &v3.IPPoolList{}
		err := cli.List(ctx, instance)
		if err != nil {
			return err
		}
		for _, item := range instance.Items {
			if item.Spec.CIDR == ipPool.CIDR {
				if awsNativeIP == operatorv1.NativeIPEnabled && item.Spec.AWSSubnetID == "" {
					return fmt.Errorf("AWS subnet ID must be set when NativeIP is enabled")
				}
				return nil
			}
		}
	}
	return fmt.Errorf("IPPool matching CIDR = %s not present", ipPool.CIDR)
}

// getUnreadyEgressGateway returns the first instance of the EGW resource which is unready.
func getUnreadyEgressGateway(egws []operatorv1.EgressGateway) *operatorv1.EgressGateway {
	for _, egw := range egws {
		if egw.Status.State != operatorv1.TigeraStatusReady {
			return &egw
		}
	}
	return nil
}

// setDegraded updates the degraded status condition of the EGW resource.
func setDegraded(cli client.Client, ctx context.Context, egw *operatorv1.EgressGateway, reason, msg string) {
	updateEGWStatusConditions(cli, ctx, egw, operatorv1.ComponentDegraded, metav1.ConditionTrue, reason, msg)
}

// setAvailable updates the ready status condition of the EGW resource.
func setAvailable(cli client.Client, ctx context.Context, egw *operatorv1.EgressGateway, reason, msg string) {
	updateEGWStatusConditions(cli, ctx, egw, operatorv1.ComponentAvailable, metav1.ConditionTrue, reason, msg)
}

// updateEGWStatusConditions sets the status conditions of the EGW resource and if updateStatus is True, status of the EGW resource
// is updated in the datastore.
func updateEGWStatusConditions(cli client.Client, ctx context.Context, egw *operatorv1.EgressGateway, ctype operatorv1.StatusConditionType, status metav1.ConditionStatus, reason, msg string) {
	found := false
	for idx, cond := range egw.Status.Conditions {
		if cond.Type == string(ctype) {
			if cond.Status == status &&
				cond.Reason == reason &&
				cond.Message == msg {
				return
			}
			cond.Status = status
			cond.Reason = reason
			cond.Message = msg
			found = true
		} else {
			cond.Status = metav1.ConditionFalse
			cond.Reason = string(operatorv1.Unknown)
			cond.Message = ""
		}
		cond.LastTransitionTime = metav1.NewTime(time.Now())
		egw.Status.Conditions[idx] = cond
	}
	if !found {
		condition := metav1.Condition{Type: string(ctype), Status: status, Reason: reason, Message: msg, LastTransitionTime: metav1.NewTime(time.Now())}
		egw.Status.Conditions = append(egw.Status.Conditions, condition)
	}
	if err := cli.Status().Update(ctx, egw); err != nil {
		log.WithValues("Name", egw.Name, "Namespace", egw.Namespace, "error", err).Info("Error updating status")
	}
}

func getDegradedMsg(egw *operatorv1.EgressGateway) string {
	for _, cond := range egw.Status.Conditions {
		if cond.Type == string(operatorv1.ComponentDegraded) {
			return cond.Message
		}
	}
	return ""
}

func getEGWNamespaceAndNames(egws []operatorv1.EgressGateway) []string {
	namespacedName := []string{}
	for _, egw := range egws {
		namespacedName = append(namespacedName, fmt.Sprintf("%s:%s", egw.Namespace, egw.Name))
	}
	return namespacedName
}
