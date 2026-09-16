// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package installation

import (
	"context"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/sharedconfig"
)

const (
	// installationFieldManager owns the shared config fields defaulted from the Installation.
	installationFieldManager = "installation"

	// bpfFieldManager owns spec.bpfEnabled, which both installation write sites declare.
	bpfFieldManager = "installation-bpf"
)

// declareFelixConfiguration declares the fields defaulted from the Installation spec, always
// declaring every one so the field set stays stable. A field the spec stops asking for is
// declared without a value, which clears whatever the operator wrote there.
func (r *ReconcileInstallation) declareFelixConfiguration(ctx context.Context, install *operatorv1.Installation, needNsMigration bool) sharedconfig.DeclareFelixConfiguration {
	return func(current *v3.FelixConfiguration) (*sharedconfig.FelixConfigurationDeclaration, error) {
		d := &sharedconfig.FelixConfigurationDeclaration{
			Manager: installationFieldManager,
			Owned:   &v3.FelixConfiguration{},
			Policies: map[string]sharedconfig.ConflictPolicy{
				"spec.routeTableRange":         sharedconfig.ConflictDefer,
				"spec.healthPort":              sharedconfig.ConflictDefer,
				"spec.vxlanVNI":                sharedconfig.ConflictDefer,
				"spec.vxlanPort":               sharedconfig.ConflictDefer,
				"spec.bpfHostConntrackBypass":  sharedconfig.ConflictDefer,
				"spec.bpfKubeProxyHealthzPort": sharedconfig.ConflictDefer,
				"spec.nftablesMode":            sharedconfig.ConflictOverride,
				"spec.programClusterRoutes":    sharedconfig.ConflictOverride,
			},
		}
		owned := &d.Owned.Spec

		// Keep calico-node's route tables clear of the ones the CNI plugin uses.
		switch install.Spec.CNI.Type {
		case operatorv1.PluginAmazonVPC:
			// AWS uses the ENI device number + 1, and the VLAN table ID + 100.
			owned.RouteTableRange = &v3.RouteTableRange{Min: 65, Max: 99}
		case operatorv1.PluginGKE:
			owned.RouteTableRange = &v3.RouteTableRange{Min: 10, Max: 250}
		}

		owned.HealthPort = ptr.To(defaultFelixHealthPort(install))

		vxlanVNI, vxlanPort := 4096, 4789
		if install.Spec.KubernetesProvider == operatorv1.ProviderDockerEE {
			// MKE's docker swarm VXLAN uses 4096/4789, and the clash deletes vxlan.calico.
			// MKE's docs recommend 10000.
			vxlanVNI = 10000
			if install.Spec.BPFEnabled() {
				// The eBPF dataplane's flow-based VXLAN device clashes with the host's VXLAN interface.
				vxlanPort = 8472

				// The eBPF dataplane only works with MKE when conntrack bypass is off.
				owned.BPFHostConntrackBypass = ptr.To(false)
			}
		}
		owned.VXLANVNI = &vxlanVNI
		owned.VXLANPort = &vxlanPort

		if install.Spec.BPFEnabled() && !install.Spec.KubeProxyManagementEnabled() {
			// The platform's kube-proxy holds 10256, so Felix's healthz server would fail to
			// bind. Port 0 only validates on newer nodes, so hold the first write until all of
			// them accept it.
			nodeDSExists, err := r.nodeDaemonSetExists(ctx)
			if err != nil {
				return nil, err
			}
			alreadySet := current.Spec.BPFKubeProxyHealthzPort != nil && *current.Spec.BPFKubeProxyHealthzPort == 0
			if alreadySet || allNodesRunTargetVersion(install, needNsMigration, nodeDSExists, r.ext.ProductVersion(&install.Spec)) {
				owned.BPFKubeProxyHealthzPort = ptr.To(0)
			}
		}

		if install.Spec.CalicoNetwork != nil && install.Spec.CalicoNetwork.LinuxDataplane != nil {
			owned.NFTablesMode = ptr.To(nftablesMode(install))
		}

		// Gated on the field being set, so leaving it unset keeps meaning "whatever Calico
		// defaults to" rather than pinning today's default into the datastore.
		if install.Spec.CalicoNetwork != nil && install.Spec.CalicoNetwork.ClusterRoutingMode != nil {
			mode := *install.Spec.CalicoNetwork.ClusterRoutingMode
			owned.ProgramClusterRoutes = ptr.To(felixProgramClusterRoutesValue(mode))
		}

		extPaths, err := r.ext.DeclareFelixConfiguration(&install.Spec, current, d.Owned)
		if err != nil {
			return nil, err
		}
		for _, path := range extPaths {
			d.Policies[path] = sharedconfig.ConflictOverride
		}

		return d, nil
	}
}

// declareBGPConfiguration declares the BIRD half of cluster route programming. It moves in
// lockstep with the FelixConfiguration half: whatever Felix is not programming, BIRD has to be.
func (r *ReconcileInstallation) declareBGPConfiguration(install *operatorv1.Installation) sharedconfig.DeclareBGPConfiguration {
	return func(current *v3.BGPConfiguration) (*sharedconfig.BGPConfigurationDeclaration, error) {
		d := &sharedconfig.BGPConfigurationDeclaration{
			Manager: installationFieldManager,
			Owned:   &v3.BGPConfiguration{},
			Policies: map[string]sharedconfig.ConflictPolicy{
				"spec.programClusterRoutes": sharedconfig.ConflictOverride,
			},
		}

		// Gated on the field being set, so leaving it unset keeps meaning "whatever Calico
		// defaults to" rather than pinning today's default into the datastore.
		if install.Spec.CalicoNetwork != nil && install.Spec.CalicoNetwork.ClusterRoutingMode != nil {
			mode := *install.Spec.CalicoNetwork.ClusterRoutingMode
			d.Owned.Spec.ProgramClusterRoutes = ptr.To(birdProgramClusterRoutesValue(mode))
		}
		return d, nil
	}
}

// nodeDaemonSetExists reports whether calico-node has been rendered yet.
func (r *ReconcileInstallation) nodeDaemonSetExists(ctx context.Context) (bool, error) {
	ds := &appsv1.DaemonSet{}
	err := r.client.Get(ctx, types.NamespacedName{Namespace: common.CalicoNamespace, Name: common.NodeDaemonSetName}, ds)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// defaultFelixHealthPort is the port the operator defaults Felix's health server to.
func defaultFelixHealthPort(install *operatorv1.Installation) int {
	if install.Spec.KubernetesProvider.IsOpenShift() {
		return 9199
	}
	return 9099
}

// nftablesMode is the dataplane mode Felix should run in. The operator has always owned it,
// so nothing older needs preserving.
func nftablesMode(install *operatorv1.Installation) v3.NFTablesMode {
	if !install.Spec.IsNftables() {
		return v3.NFTablesModeDisabled
	}
	if install.Spec.BPFEnabled() {
		// BPF mode replaces kube-proxy, so nftables needs no compatibility with its mode.
		return v3.NFTablesModeEnabled
	}
	// kube-proxy is running, so let Felix pick per node and keep upgrades smooth.
	return v3.NFTablesModeAuto
}

// declareBPFEnabled declares spec.bpfEnabled. Both installation write sites use it so the field
// stays under one manager with the same value.
func (r *ReconcileInstallation) declareBPFEnabled(ctx context.Context, install *operatorv1.Installation, needNsMigration bool) sharedconfig.DeclareFelixConfiguration {
	return func(current *v3.FelixConfiguration) (*sharedconfig.FelixConfigurationDeclaration, error) {
		enabled, err := r.bpfEnabledValue(ctx, install, current, needNsMigration)
		if err != nil {
			return nil, err
		}
		return &sharedconfig.FelixConfigurationDeclaration{
			Manager: bpfFieldManager,
			Owned: &v3.FelixConfiguration{
				Spec: v3.FelixConfigurationSpec{BPFEnabled: &enabled},
			},
			Policies: map[string]sharedconfig.ConflictPolicy{
				// A user who changed this by hand gets a degraded status, not an override.
				"spec.bpfEnabled": sharedconfig.ConflictError,
			},
		}, nil
	}
}

// bpfEnabledValue resolves the dataplane Felix should run. Turning eBPF on waits for the
// calico-node rollout to mount the BPF volumes.
func (r *ReconcileInstallation) bpfEnabledValue(ctx context.Context, install *operatorv1.Installation, current *v3.FelixConfiguration, needNsMigration bool) (bool, error) {
	if !install.Spec.BPFEnabled() {
		return false, nil
	}

	ds := &appsv1.DaemonSet{}
	err := r.client.Get(ctx, types.NamespacedName{Namespace: common.CalicoNamespace, Name: common.NodeDaemonSetName}, ds)
	if apierrors.IsNotFound(err) {
		// A fresh install in eBPF mode has no calico-node rollout to wait for.
		return !needNsMigration, nil
	}
	if err != nil {
		return false, err
	}

	// Operators before the FelixConfiguration field enabled eBPF through a calico-node env var.
	envVarEnabled, err := bpfEnabledOnDaemonsetWithEnvVar(ds)
	if err != nil {
		return false, err
	}
	if envVarEnabled || isRolloutCompleteWithBPFVolumes(ds) {
		return true, nil
	}
	return bpfEnabledOnFelixConfig(current), nil
}
