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

package ippool

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	"github.com/projectcalico/calico/operator/pkg/render"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const tigeraStatusName string = "ippools"

var log = logf.Log.WithName("controller_ippool")

func Add(mgr manager.Manager, opts options.ControllerOptions) error {
	clientv3, err := utils.V3Client(mgr.GetConfig())
	if err != nil {
		return fmt.Errorf("failed to create projectcalico.org/v3 client: %w", err)
	}

	r := &Reconciler{
		config:               mgr.GetConfig(),
		client:               mgr.GetClient(),
		clientv3:             clientv3,
		scheme:               mgr.GetScheme(),
		watches:              make(map[runtime.Object]struct{}),
		autoDetectedProvider: opts.DetectedProvider,
		opts:                 opts,
		status:               status.New(mgr.GetClient(), tigeraStatusName, opts.KubernetesVersion),
	}
	r.status.Run(opts.ShutdownContext)

	c, err := ctrlruntime.NewController("tigera-ippool-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create tigera-ippool-controller: %w", err)
	}

	// Watch for changes to primary resource Installation
	err = c.WatchObject(&operatorv1.Installation{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-ippool-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to APIServer
	err = c.WatchObject(&operatorv1.APIServer{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		log.V(5).Info("Failed to create APIServer watch", "err", err)
		return fmt.Errorf("apiserver-controller failed to watch primary resource: %v", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, tigeraStatusName); err != nil {
		return fmt.Errorf("tigera-ippool-controller failed to watch calico Tigerastatus: %w", err)
	}

	// Watch for changes to IPPool.
	err = c.WatchObject(&v3.IPPool{}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("tigera-ippool-controller failed to watch IPPool resource: %w", err)
	}

	if r.autoDetectedProvider.IsOpenShift() {
		// Watch for openshift network configuration as well. If we're running in OpenShift, we need to
		// merge this configuration with our own and the write back the status object.
		err = c.WatchObject(&configv1.Network{}, &handler.EnqueueRequestForObject{})
		if err != nil {
			if !errors.IsNotFound(err) {
				return fmt.Errorf("tigera-installation-controller failed to watch openshift network config: %w", err)
			}
		}
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("tigera-ippool-controller failed to create periodic reconcile watch: %w", err)
	}
	return nil
}

var _ reconcile.Reconciler = &Reconciler{}

type Reconciler struct {
	config               *rest.Config
	client               client.Client
	clientv3             client.Client
	scheme               *runtime.Scheme
	watches              map[runtime.Object]struct{}
	autoDetectedProvider operatorv1.Provider
	status               status.StatusManager
	opts                 options.ControllerOptions
}

const (
	// This label is used to track which IP pools are managed by this controller. Any IP pool
	// with this label key/value pair is assumed to be solely managed and reconciled by this controller.
	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "tigera-operator"
)

// hasOwnerLabel returns true if the given IP pool is owned by the tigera/operator, and false otheriwse.
func hasOwnerLabel(pool *v3.IPPool) bool {
	if val, ok := pool.Labels[managedByLabel]; ok && val == managedByValue {
		return true
	}
	return false
}

// recordDefaults adds the pool defaults to the Installation status, leaving the spec untouched.
func (r *Reconciler) recordDefaults(ctx context.Context, installation *operatorv1.Installation, declared, computed operatorv1.InstallationSpec) error {
	recorded, err := utils.MergeRecordedDefaults(installation.Status.Defaults, declared, computed,
		utils.DefaultsScope{Owned: []string{utils.PoolDefaultsPath}})
	if err != nil {
		return err
	}
	if reflect.DeepEqual(installation.Status.Defaults, recorded) {
		return nil
	}

	// Write a copy, so the response can't replace the effective spec we're working from.
	written := installation.DeepCopy()
	written.Status.Defaults = recorded
	if err := r.client.Status().Update(ctx, written); err != nil {
		return err
	}
	installation.Status = written.Status
	return nil
}

// Reconcile reconciles IP pools in the cluster.
//
// - Query desired IP pools (from Installation)
// - Query existing IP pools owned by this controller
// - Reconcile the differences
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(1).Info("Reconciling IP pools")

	// Get the Installation object - this is the source of truth for IP pools managed by
	// this controller.
	installation := &operatorv1.Installation{}
	if err := r.client.Get(ctx, utils.DefaultInstanceKey, installation); err != nil {
		if errors.IsNotFound(err) {
			reqLogger.Info("Installation config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		reqLogger.Error(err, "An error occurred when querying the Installation resource")
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	defer r.status.SetMetaData(&installation.ObjectMeta)

	// If the installation is terminating, do nothing.
	if installation.DeletionTimestamp != nil {
		reqLogger.Info("Installation is terminating, skipping IP pool reconciliation")
		return reconcile.Result{}, nil
	}

	// The core controller signals that initial defaulting is done by publishing the computed spec.
	if installation.Status.Computed == nil {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Installation defaulting to occur", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Everything below works from the computed config, except the recorded defaults, which are
	// diffed against what the user declared.
	declared := *installation.Spec.DeepCopy()
	computed := installation.Status.Computed.DeepCopy()

	// The computed config has the overlay merged in, so count the overlay as declared. Recording
	// its pools as ours would leave them behind in status.defaults once the overlay is deleted.
	overlay, err := utils.GetOverlayInstallationSpec(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying the 'overlay' Installation resource", err, reqLogger)
		return reconcile.Result{}, err
	}
	if overlay != nil {
		declared = utils.OverrideInstallationSpec(declared, *overlay)
	}

	if computed.CNI == nil || computed.CNI.Type == "" {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for CNI type to be configured on Installation", nil, reqLogger)
		return reconcile.Result{}, nil
	}

	// Get all IP pools currently in the cluster.
	currentPools := &v3.IPPoolList{}
	if err := r.client.List(ctx, currentPools); err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "error querying IP pools", err, reqLogger)
		return reconcile.Result{}, err
	}
	for i := range currentPools.Items {
		if err := utils.RestoreV3Metadata(&currentPools.Items[i]); err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, "error obtaining v3 IPPool metadata", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	if err = fillDefaults(ctx, r.client, computed, currentPools); err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "error filling IP pool defaults", err, reqLogger)
		return reconcile.Result{}, err
	}
	if err = ValidatePools(computed); err != nil {
		r.status.SetDegraded(operatorv1.InvalidConfigurationError, "error validating IP pool configuration", err, reqLogger)
		return reconcile.Result{}, err
	}
	if err := r.recordDefaults(ctx, installation, declared, *computed); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Failed to write defaults", err, reqLogger)
		return reconcile.Result{}, err
	}
	reqLogger.V(1).Info("Reconciling IP pools for installation", "installation", computed)

	// Get the APIServer. If healthy, we'll use the projectcalico.org/v3 API for managing pools.
	// Otherwise, we'll use the internal v1 API for bootstrapping the cluster until the API server is available.
	// This controller will never delete pools using the v1 API, as deletion is a complex process and is only
	// properly handled when using the v3 API.
	apiserver, _, err := utils.GetAPIServer(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Error querying APIServer", err, reqLogger)
		return reconcile.Result{}, err
	}

	// Determine if the v3 API is available. This is true if either:
	// - The APIServer resource exists and is ready.
	// - We're using v3 CRDs directly (i.e., not via the Calico API server).
	apiAvailable := apiserver != nil && apiserver.Status.State == operatorv1.TigeraStatusReady || r.opts.UseV3CRDs

	// Create a lookup map of pools owned by this controller for easy access.
	// This controller will only modify IP pools if:
	// - The pool was created by or last updated by this controller (as indicated by the managed-by label).
	// - The IP pool is present in the cluster, present in the Installation, and both match exactly.
	// The latter case exists for upgrade scenarios, allowing the operator to assume control of existing IP pools gracefully.
	ourPools := map[string]v3.IPPool{}
	notOurs := map[string]bool{}
	for _, p := range currentPools.Items {
		if hasOwnerLabel(&p) {
			// This pool is owned by the Installation object, so consider it ours.
			reqLogger.V(1).Info("IP pool is owned by operator", "name", p.Name, "cidr", p.Spec.CIDR)
			ourPools[utils.NormalizeCIDR(p.Spec.CIDR)] = p
		} else {
			// The IP pool may have been created by the operator, but it may not have the managed-by label set if it was created
			// before the operator started setting the label. The following logic allows opt-in ownership of IP pools created prior to
			// this controller, or via external tools like calicoctl.
			//
			// Compare this pool to the pools in the Installation object and there is a match, consider it ours.
			// Without this logic, this controller would consider these pools as not owned by itself, resulting in errors
			// when it attempts to create overlappin IP pools.
			for _, cnp := range computed.CalicoNetwork.IPPools {
				v1p := operatorv1.IPPool{}
				FromProjectCalico(&v1p, p)
				reqLogger.V(1).Info("Comparing IP pool", "clusterPool", p, "installationPool", cnp)
				// Compare using normalized CIDRs so that an existing pool with a canonical CIDR is still
				// recognized as a match for an Installation pool that specifies the same CIDR in a
				// non-canonical form. Only the CIDR field can differ textually while being semantically
				// equal, so we normalize that field on copies before comparing the full structs.
				cnpNorm := cnp
				cnpNorm.CIDR = utils.NormalizeCIDR(cnp.CIDR)
				v1p.CIDR = utils.NormalizeCIDR(v1p.CIDR)
				if !reflect.DeepEqual(cnpNorm, v1p) {
					// The IP pool in the cluster doesn't match the IP pool in the Installation - ignore it.
					reqLogger.V(1).Info("IP pool doesn't match", "clusterPool", v1p, "installationPool", cnp)
					continue
				}

				// Consider this IP pool to be owned by the operator.
				reqLogger.V(1).Info("Assuming ownership of IP pool", "name", p.Name, "cidr", p.Spec.CIDR)
				ourPools[utils.NormalizeCIDR(p.Spec.CIDR)] = p
			}
			if _, ok := ourPools[utils.NormalizeCIDR(p.Spec.CIDR)]; !ok {
				// This IP pool exists in the cluster, but is not owned by us - mark it down so that
				// we can refuse to update any pool with this CIDR if it exists in the Installation.
				// This branch is only hit if the pool does not have the managed-by label, and does
				// not exactly match any pool in the Installation.
				notOurs[utils.NormalizeCIDR(p.Spec.CIDR)] = true
			}
		}
	}
	reqLogger.V(1).Info("Found IP pools owned by us", "count", len(ourPools))

	// For each pool that is desired, but doesn't exist, create it.
	// We will install pools at start-of-day using the CRD API, but otherwise
	// we require the v3 API to be running. This is so that we properly leverage the v3 API's validation.
	toCreateOrUpdate := []client.Object{}
	for _, p := range computed.CalicoNetwork.IPPools {
		// We need to check if updates are required, but the installation uses the operator API format and the queried
		// pools are in projectcalico.org/v3 format. Compare the pools using the projectcalico.org/v3 format.
		v1res, err := ToProjectCalico(p)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, "error handling IP pool", err, reqLogger)
			return reconcile.Result{}, err
		}
		v1res.Labels[managedByLabel] = managedByValue

		// If there is an existing IP pool in the cluster with the same CIDR, but it is not owned by us, then we cannot
		// take action on it.
		if _, ok := notOurs[utils.NormalizeCIDR(p.CIDR)]; ok {
			r.status.SetDegraded(operatorv1.ResourceValidationError, "Cannot update an IP pool not owned by the operator", nil, reqLogger)
			continue
		}

		// Consider sending an update if:
		//
		// - The API server is up and running.
		// - The desired IP pool doesn't exist.
		// - The desired IP pool exists, but doesn't match the desired state.
		//
		// We'll only actually send the update if the API server is available or there are no IP pools in the cluster. We
		// are careful here to only generate a degraded status if the API server is unavailable and we determine that an IP pool needs
		// to be updated after initial IP pool creation.
		if pool, ok := ourPools[utils.NormalizeCIDR(p.CIDR)]; apiAvailable || !ok || !reflect.DeepEqual(pool.Spec, v1res.Spec) {
			if len(currentPools.Items) == 0 {
				// There are no pools in the cluster. Create them using the v1 API, as they are needed for bootstrapping and the API server is non-functional
				// if there are no IP pools in the cluster!
				//
				// Once the v3 API is available, we'll use that instead. Note that this is an imperfect solution - it still bypasses apiserver validation for
				// the initial creation of IP pools (although we expect them to be valid due to operator validation). If the bootstrap pools
				// are invalid and do not enable the Calico apiserver to launch successfully, then manual intervention will be required.
				toCreateOrUpdate = append(toCreateOrUpdate, v1res)
			} else if apiAvailable {
				// There are IP pools in the cluster and the v3 API is available, so use it to create / update the pool.
				v3res, err := v1ToV3(v1res)
				if err != nil {
					r.status.SetDegraded(operatorv1.ResourceValidationError, "error handling IP pool", err, reqLogger)
					return reconcile.Result{}, err
				}
				toCreateOrUpdate = append(toCreateOrUpdate, v3res)
			} else {
				// The v3 API is not available, and there are existing pools in the cluster. We cannot create new pools until the v3 API is available.
				// The user may need to manually delete or update pools in order to allow the v3 API to launch successfully.
				r.status.SetDegraded(operatorv1.ResourceNotReady, "Unable to modify IP pools while Calico API server is unavailable", nil, reqLogger)
				return reconcile.Result{}, nil
			}
		}
	}

	// Check existing pools owned by this controller that are no longer in the Installation resource.
	toDelete := []client.Object{}
	for cidr, v1res := range ourPools {
		reqLogger.WithValues("cidr", cidr).V(1).Info("Checking if pool is still valid")
		found := false
		for _, p := range computed.CalicoNetwork.IPPools {
			// cidr is a normalized map key; normalize the Installation CIDR before comparing so that a
			// non-canonical CIDR in the Installation still matches the canonical CIDR stored on the pool.
			if utils.NormalizeCIDR(p.CIDR) == cidr {
				found = true
				break
			}
		}
		if !found {
			// This pool needs to be deleted. We only ever send deletes via the API server,
			// since deletion requires rather complex logic. If the API server isn't available,
			// we won't delete the pool and will mark the controller as degraded.
			reqLogger.WithValues("cidr", cidr, "valid", computed.CalicoNetwork.IPPools).Info("Pool needs to be deleted")
			if apiAvailable {
				// v3 API is available - send a delete request.
				v3res, err := v1ToV3(&v1res)
				if err != nil {
					r.status.SetDegraded(operatorv1.ResourceValidationError, "error handling IP pool", err, reqLogger)
					return reconcile.Result{}, err
				}
				toDelete = append(toDelete, v3res)
			} else {
				// The v3 API is not available, so we can't delete the pool. Mark degraded and return. We'll delete the pool
				// when the API server become available.
				r.status.SetDegraded(operatorv1.ResourceNotReady, "Unable to delete IP pools while Calico API server is unavailable", nil, reqLogger)
				return reconcile.Result{}, nil
			}
		}
	}

	// We don't apply an OwnerReference to IP pools created by this controller. This means that when the Installation is deleted, IP pools
	// will remain even though all other Calico resources will be deleted. This is intentional - deleting IP pools requires the Calico API server to be
	// running, and we don't want to block the deletion of the Installation on the API server being available, as it introduces too many ways for
	// things to go wrong upon deleting the Installation API. Users can manually delete the IP pools if they are no longer needed.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, nil)
	if apiAvailable {
		// Use the projectcalico.org/v3 client.
		handler = utils.NewComponentHandler(log, r.clientv3, r.scheme, nil)
	}

	passThru := render.NewCreationPassthroughWithLog(log, toCreateOrUpdate...)
	if err := handler.CreateOrUpdateOrDelete(ctx, passThru, nil); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating IPPools", err, log)
		return reconcile.Result{}, err
	}
	delPassThru := render.NewDeletionPassthrough(toDelete...)
	if err := handler.CreateOrUpdateOrDelete(ctx, delPassThru, nil); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error deleting IPPools", err, log)
		return reconcile.Result{}, err
	}

	// Tell the status manager that we're ready to monitor the resources we've told it about and receive statuses.
	r.status.ReadyToMonitor()

	// We can clear the degraded state now since as far as we know everything is in order.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	return reconcile.Result{}, nil
}

// ToProjectCalico converts an operator IPPool to a projectcalico.org/v3 IPPool resource.
func ToProjectCalico(p operatorv1.IPPool) (*v3.IPPool, error) {
	pool := v3.IPPool{
		TypeMeta: metav1.TypeMeta{Kind: "IPPool", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   p.Name,
			Labels: map[string]string{},
		},
		// Normalize the CIDR to its canonical form. The Calico API server stores pools with canonical
		// CIDRs, so emitting the canonical form here keeps the pool we create/update byte-for-byte
		// consistent with what is stored, avoiding needless updates and rejection by API server versions
		// that refuse to persist non-canonical CIDRs.
		Spec: v3.IPPoolSpec{CIDR: utils.NormalizeCIDR(p.CIDR)},
	}

	// Set encap.
	switch p.Encapsulation {
	case operatorv1.EncapsulationIPIP:
		pool.Spec.IPIPMode = v3.IPIPModeAlways
		pool.Spec.VXLANMode = v3.VXLANModeNever
	case operatorv1.EncapsulationIPIPCrossSubnet:
		pool.Spec.IPIPMode = v3.IPIPModeCrossSubnet
		pool.Spec.VXLANMode = v3.VXLANModeNever
	case operatorv1.EncapsulationVXLAN:
		pool.Spec.VXLANMode = v3.VXLANModeAlways
		pool.Spec.IPIPMode = v3.IPIPModeNever
	case operatorv1.EncapsulationVXLANCrossSubnet:
		pool.Spec.VXLANMode = v3.VXLANModeCrossSubnet
		pool.Spec.IPIPMode = v3.IPIPModeNever
	}

	// Set NAT
	switch p.NATOutgoing {
	case operatorv1.NATOutgoingEnabled:
		pool.Spec.NATOutgoing = true
	}

	if p.DisableNewAllocations != nil {
		pool.Spec.Disabled = *p.DisableNewAllocations
	}

	// Set BlockSize
	if p.BlockSize != nil {
		pool.Spec.BlockSize = int(*p.BlockSize)
	}

	// Set selector.
	pool.Spec.NodeSelector = p.NodeSelector

	// Set BGP export.
	if p.DisableBGPExport != nil {
		pool.Spec.DisableBGPExport = *p.DisableBGPExport
	}

	for _, use := range p.AllowedUses {
		pool.Spec.AllowedUses = append(pool.Spec.AllowedUses, v3.IPPoolAllowedUse(use))
	}

	m := v3.AssignmentMode(p.AssignmentMode)
	pool.Spec.AssignmentMode = &m

	return &pool, nil
}

// FromProjectCalico populates the IP pool with the data from the given
// projectcalico.org/v3 IP pool. It is the direct inverse of ToProjectCalicoV1,
// and should be updated with every new field added to the IP pool structure.
func FromProjectCalico(p *operatorv1.IPPool, crd v3.IPPool) {
	p.Name = crd.Name
	p.CIDR = crd.Spec.CIDR

	// Set encap.
	switch crd.Spec.IPIPMode {
	case v3.IPIPModeAlways:
		p.Encapsulation = operatorv1.EncapsulationIPIP
	case v3.IPIPModeCrossSubnet:
		p.Encapsulation = operatorv1.EncapsulationIPIPCrossSubnet
	}
	switch crd.Spec.VXLANMode {
	case v3.VXLANModeAlways:
		p.Encapsulation = operatorv1.EncapsulationVXLAN
	case v3.VXLANModeCrossSubnet:
		p.Encapsulation = operatorv1.EncapsulationVXLANCrossSubnet
	}

	// Set NAT
	if crd.Spec.NATOutgoing {
		p.NATOutgoing = operatorv1.NATOutgoingEnabled
	} else {
		p.NATOutgoing = operatorv1.NATOutgoingDisabled
	}

	// Configure DisableNewAllocations
	p.DisableNewAllocations = ptr.To(crd.Spec.Disabled)

	// Set BlockSize
	blockSize := int32(crd.Spec.BlockSize)
	p.BlockSize = &blockSize

	// Set selector.
	p.NodeSelector = crd.Spec.NodeSelector

	// Set BGP export.
	p.DisableBGPExport = ptr.To(crd.Spec.DisableBGPExport)

	for _, use := range crd.Spec.AllowedUses {
		p.AllowedUses = append(p.AllowedUses, operatorv1.IPPoolAllowedUse(use))
	}

	if crd.Spec.AssignmentMode != nil {
		m := operatorv1.AssignmentMode(*crd.Spec.AssignmentMode)
		p.AssignmentMode = m
	}
}

func CRDPoolsToOperator(crds []v3.IPPool) []operatorv1.IPPool {
	pools := []operatorv1.IPPool{}
	for _, p := range crds {
		op := operatorv1.IPPool{}
		FromProjectCalico(&op, p)
		pools = append(pools, op)
	}
	return pools
}

func v1ToV3(v1pool *v3.IPPool) (*v3.IPPool, error) {
	bs, err := json.Marshal(v1pool)
	if err != nil {
		return nil, err
	}

	v3pool := v3.IPPool{}
	err = json.Unmarshal(bs, &v3pool)
	if err != nil {
		return nil, err
	}

	// We need to clear the UID field, as the v1 UID is not valid in the v3 API.
	v3pool.UID = ""

	return &v3pool, nil
}
