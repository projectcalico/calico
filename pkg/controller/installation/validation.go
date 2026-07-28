// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
	"errors"
	"fmt"
	"net"
	"path"
	"strings"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/common/validation"
	node "github.com/tigera/operator/pkg/common/validation/calico-node"
	csinodedriver "github.com/tigera/operator/pkg/common/validation/csi-node-driver"
	kubecontrollers "github.com/tigera/operator/pkg/common/validation/kube-controllers"
	typha "github.com/tigera/operator/pkg/common/validation/typha"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	rcc "github.com/tigera/operator/pkg/render/common/components"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// validateCustomResource validates that the given custom resource is correct. This
// should be called after populating defaults and before rendering objects.
func validateCustomResource(instance *operatorv1.Installation) error {
	if instance.Spec.CNI == nil {
		return fmt.Errorf("spec.cni must be defined")
	}

	// The CNI spec version only applies to the CNI config that the operator
	// generates, which only exists when using the Calico CNI plugin.
	if instance.Spec.CNI.SpecVersion != nil && instance.Spec.CNI.Type != operatorv1.PluginCalico {
		return fmt.Errorf("spec.cni.specVersion is only valid when spec.cni.type is Calico, not %s",
			instance.Spec.CNI.Type)
	}

	// Perform validation based on the chosen CNI plugin.
	// For example, make sure the plugin is supported on the specified k8s provider.
	switch instance.Spec.CNI.Type {
	case operatorv1.PluginCalico:
		switch instance.Spec.CNI.IPAM.Type {
		case operatorv1.IPAMPluginCalico:
		case operatorv1.IPAMPluginHostLocal:
		default:
			return fmt.Errorf(
				"spec.cni.ipam.type %s is not compatible with spec.cni.type %s, valid IPAM values %s",
				instance.Spec.CNI.IPAM.Type, instance.Spec.CNI.Type,
				strings.Join([]string{
					operatorv1.IPAMPluginCalico.String(),
					operatorv1.IPAMPluginHostLocal.String(),
				}, ",",
				),
			)
		}

		// validate logging config for calico-cni
		if instance.Spec.Logging != nil && instance.Spec.Logging.CNI != nil {
			if instance.Spec.Logging.CNI.LogFileMaxCount != nil &&
				*instance.Spec.Logging.CNI.LogFileMaxCount <= 0 {
				return fmt.Errorf("spec.loggingConfig.cni.logFileMaxCount value should be greater than zero")
			}

			if instance.Spec.Logging.CNI.LogFileMaxSize != nil &&
				(instance.Spec.Logging.CNI.LogFileMaxSize.Format != resource.BinarySI ||
					instance.Spec.Logging.CNI.LogFileMaxSize.Value() <= 0) {
				return fmt.Errorf("spec.Logging.cni.logFileMaxSize format is not corrent. Suffix should be Ki | Mi | Gi | Ti | Pi | Ei")
			}

			if instance.Spec.Logging.CNI.LogFileMaxAgeDays != nil &&
				*instance.Spec.Logging.CNI.LogFileMaxAgeDays <= 0 {
				return fmt.Errorf("spec.Logging.cni.logFileMaxAgeDays should be a positive non-zero integer")
			}
		}

	case operatorv1.PluginGKE:
		// The GKE CNI plugin is only supported on GKE or BYO.
		switch instance.Spec.KubernetesProvider {
		case operatorv1.ProviderGKE, "":
		default:
			return fmt.Errorf("spec.kubernetesProvider %s is not compatible with spec.cni.type %s",
				instance.Spec.KubernetesProvider, instance.Spec.CNI.Type)
		}

		switch instance.Spec.CNI.IPAM.Type {
		case operatorv1.IPAMPluginHostLocal:
		default:
			return fmt.Errorf(
				"spec.cni.ipam.type %s is not compatible with spec.cni.type %s, valid IPAM values %s",
				instance.Spec.CNI.IPAM.Type, instance.Spec.CNI.Type, operatorv1.IPAMPluginHostLocal)
		}
	case operatorv1.PluginAmazonVPC:
		// The AmazonVPC CNI plugin is only supported on EKS or BYO.
		switch instance.Spec.KubernetesProvider {
		case operatorv1.ProviderEKS, "":
		default:
			return fmt.Errorf("spec.kubernetesProvider %s is not compatible with spec.cni.type %s",
				instance.Spec.KubernetesProvider, instance.Spec.CNI.Type)
		}

		switch instance.Spec.CNI.IPAM.Type {
		case operatorv1.IPAMPluginAmazonVPC:
		default:
			return fmt.Errorf(
				"spec.cni.ipam.type  %s is not compatible with spec.cni.type %s, valid IPAM values %s",
				instance.Spec.CNI.IPAM.Type, instance.Spec.CNI.Type, operatorv1.IPAMPluginAmazonVPC)
		}
	case operatorv1.PluginAzureVNET:
		// The AzureVNET CNI plugin is only supported on AKS or BYO.
		switch instance.Spec.KubernetesProvider {
		case operatorv1.ProviderAKS, "":
		default:
			return fmt.Errorf("spec.kubernetesProvider %s is not compatible with spec.cni.type %s",
				instance.Spec.KubernetesProvider, instance.Spec.CNI.Type)
		}

		switch instance.Spec.CNI.IPAM.Type {
		case operatorv1.IPAMPluginAzureVNET:
		default:
			return fmt.Errorf(
				"spec.cni.ipam.type %s is not compatible with spec.cni.type %s, valid IPAM values %s",
				instance.Spec.CNI.IPAM.Type, instance.Spec.CNI.Type, operatorv1.IPAMPluginAzureVNET)
		}
	default:
		// The specified CNI plugin is not supported by this version of the operator.
		return fmt.Errorf("invalid value '%s' for spec.cni.type, it should be one of %s",
			instance.Spec.CNI.Type, strings.Join(operatorv1.CNIPluginTypesString, ","))
	}

	// Verify Calico settings, if specified.
	if instance.Spec.CalicoNetwork != nil {
		bpfDataplane := instance.Spec.CalicoNetwork.LinuxDataplane != nil && *instance.Spec.CalicoNetwork.LinuxDataplane == operatorv1.LinuxDataplaneBPF
		felixClusterRoutingMode := felixProgramsClusterRoutes(instance)

		// Perform validation on non-IPPool fields that rely on IP pool configuration. Validation of the IP pools themselves
		// happens in the IP pool controller.
		for _, pool := range instance.Spec.CalicoNetwork.IPPools {
			// Perform validation based on IP address family.
			isIPv4 := !strings.Contains(pool.CIDR, ":")
			if isIPv4 {
				if bpfDataplane && instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 == nil {
					return fmt.Errorf("spec.calicoNetwork.nodeAddressAutodetectionV4 is required for the BPF dataplane")
				}
			} else {
				// This is an IPv6 pool.
				if pool.Encapsulation == operatorv1.EncapsulationIPIP || pool.Encapsulation == operatorv1.EncapsulationIPIPCrossSubnet {
					return fmt.Errorf("IPIP encapsulation is not supported by IPv6 pools, but it is set for %s", pool.CIDR)
				}

				if bpfDataplane && instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6 == nil {
					return fmt.Errorf("spec.calicoNetwork.nodeAddressAutodetectionV6 is required for the BPF dataplane")
				}
			}

			// Check that the encapsulation mode on the IP pool is compatible with the CNI plugin that is in-use.
			if instance.Spec.CNI.Type == operatorv1.PluginCalico {
				switch instance.Spec.CNI.IPAM.Type {
				case operatorv1.IPAMPluginCalico:
					// Verify the specified encapsulation type is valid.
					switch pool.Encapsulation {
					case operatorv1.EncapsulationIPIP, operatorv1.EncapsulationIPIPCrossSubnet:
						// In BIRD cluster routing mode, IPIP currently requires BGP to be running in order to program routes.
						if !felixClusterRoutingMode &&
							(instance.Spec.CalicoNetwork.BGP == nil || *instance.Spec.CalicoNetwork.BGP == operatorv1.BGPDisabled) {
							return fmt.Errorf("with BIRD cluster routing mode, IPIP encapsulation requires that BGP is enabled")
						}
					case operatorv1.EncapsulationVXLAN, operatorv1.EncapsulationVXLANCrossSubnet:
					case operatorv1.EncapsulationNone:
						// In BIRD cluster routing mode, Unencapsulated currently requires BGP to be running in order to program routes.
						if !felixClusterRoutingMode &&
							(instance.Spec.CalicoNetwork.BGP == nil || *instance.Spec.CalicoNetwork.BGP == operatorv1.BGPDisabled) {
							return fmt.Errorf("with BIRD cluster routing mode, unencapsulated IP pools require that BGP is enabled")
						}
					}
				case operatorv1.IPAMPluginHostLocal:
					// The host-local IPAM plugin doesn't support VXLAN.
					switch pool.Encapsulation {
					case operatorv1.EncapsulationVXLAN, operatorv1.EncapsulationVXLANCrossSubnet:
						return fmt.Errorf("%s is invalid for ipPool.encapsulation with %s CNI and %s IPAM",
							pool.Encapsulation,
							instance.Spec.CNI.Type,
							instance.Spec.CNI.IPAM.Type)
					}
				}
			} else {
				// If not using Calico CNI, then the encapsulation must be None and BGP must be disabled.
				switch pool.Encapsulation {
				case "":
					// If empty, the IP pool controller hasn't defaulted the value yet. We'll let the IP pool controller
					// handle this before passing judgment.
				case operatorv1.EncapsulationNone:
				default:
					return fmt.Errorf("%s is invalid for ipPool.encapsulation when using non-Calico CNI, should be None",
						pool.Encapsulation)
				}
				if instance.Spec.CalicoNetwork.BGP != nil && *instance.Spec.CalicoNetwork.BGP == operatorv1.BGPEnabled {
					return fmt.Errorf("BGP is not supported when using non-Calico CNI")
				}
			}

		}

		// VPP specific validation
		if instance.Spec.CalicoNetwork.LinuxDataplane != nil && *instance.Spec.CalicoNetwork.LinuxDataplane == operatorv1.LinuxDataplaneVPP {
			if instance.Spec.Variant != operatorv1.Calico {
				return fmt.Errorf("the VPP dataplane only supports the Calico variant (configured: %s)", instance.Spec.Variant)
			}
			if instance.Spec.CNI.Type != operatorv1.PluginCalico {
				return fmt.Errorf("the VPP dataplane only supports the Calico CNI (configured: %s)", instance.Spec.CNI.Type)
			}
			if instance.Spec.CalicoNetwork.BGP == nil || *instance.Spec.CalicoNetwork.BGP == operatorv1.BGPDisabled {
				return fmt.Errorf("VPP requires BGP to be enabled")
			}
			if instance.Spec.CalicoNetwork.HostPorts != nil && *instance.Spec.CalicoNetwork.HostPorts == operatorv1.HostPortsDisabled {
				return fmt.Errorf("VPP doesn't support disabling HostPorts")
			}
		}

		if instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 != nil {
			err := validateNodeAddressDetection(instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4)
			if err != nil {
				return err
			}
		}

		if instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6 != nil {
			err := validateNodeAddressDetection(instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6)
			if err != nil {
				return err
			}
		}

		if instance.Spec.CalicoNetwork.HostPorts != nil {
			if *instance.Spec.CalicoNetwork.HostPorts == operatorv1.HostPortsEnabled {
				if instance.Spec.CNI.Type != operatorv1.PluginCalico {
					return fmt.Errorf("spec.calicoNetwork.hostPorts is supported only for Calico CNI")
				}
			}

			err := validateHostPorts(instance.Spec.CalicoNetwork.HostPorts)
			if err != nil {
				return err
			}
		}

		if instance.Spec.CalicoNetwork.MultiInterfaceMode != nil {
			if instance.Spec.CNI.Type != operatorv1.PluginCalico {
				return fmt.Errorf("spec.calicoNetwork.multiInterfaceMode is supported only for Calico CNI")
			}
		}

		if instance.Spec.CalicoNetwork.ContainerIPForwarding != nil {
			if instance.Spec.CNI.Type != operatorv1.PluginCalico {
				return fmt.Errorf("spec.calicoNetwork.containerIPForwarding is supported only for Calico CNI")
			}
		}

		if instance.Spec.CalicoNetwork.LinuxPodInterfaceType != nil {
			if instance.Spec.CNI.Type != operatorv1.PluginCalico {
				return fmt.Errorf("spec.calicoNetwork.linuxPodInterfaceType is supported only for Calico CNI")
			}
		}

		if instance.Spec.CalicoNetwork.Sysctl != nil {
			// CNI tuning plugin
			pluginData := instance.Spec.CalicoNetwork.Sysctl

			if err := utils.VerifySysctl(pluginData); err != nil {
				return err
			}

		}

		if instance.Spec.CalicoNetwork.LinuxPolicySetupTimeoutSeconds != nil {
			// Pod readiness delays.
			if *instance.Spec.CalicoNetwork.LinuxPolicySetupTimeoutSeconds < 0 {
				return fmt.Errorf("spec.calicoNetwork.linuxPolicySetupTimeoutSeconds negative value is not valid")
			}
			if instance.Spec.CalicoNetwork.LinuxDataplane == nil {
				return fmt.Errorf("spec.calicoNetwork.linuxPolicySetupTimeoutSeconds requires the Iptables Linux dataplane to be set")
			}
			if *instance.Spec.CalicoNetwork.LinuxDataplane != operatorv1.LinuxDataplaneIptables &&
				*instance.Spec.CalicoNetwork.LinuxDataplane != operatorv1.LinuxDataplaneBPF &&
				*instance.Spec.CalicoNetwork.LinuxDataplane != operatorv1.LinuxDataplaneNftables {
				return fmt.Errorf("spec.calicoNetwork.linuxPolicySetupTimeoutSeconds is supported only for the Iptables, Nftables and BPF Linux dataplanes")
			}
		}
	}

	// Verify that the flexvolume path is valid - either "None" (to disable) or a valid absolute path.
	if instance.Spec.FlexVolumePath != "None" && !path.IsAbs(instance.Spec.FlexVolumePath) {
		return fmt.Errorf("installation spec.FlexVolumePath '%s' is not an absolute path",
			instance.Spec.FlexVolumePath)
	}

	// Verify that the kubeletVolumePluginPath is valid - either "None" (to disable) or a valid absolute path.
	if instance.Spec.KubeletVolumePluginPath != "None" && !path.IsAbs(instance.Spec.KubeletVolumePluginPath) {
		return fmt.Errorf("installation spec.KubeletVolumePluginPath '%s' is not an absolute path",
			instance.Spec.KubeletVolumePluginPath)
	}

	// We only support RollingUpdate for the node daemonset strategy.
	if instance.Spec.NodeUpdateStrategy.Type != appsv1.RollingUpdateDaemonSetStrategyType {
		return fmt.Errorf("installation spec.NodeUpdateStrategy.type '%s' is not supported",
			instance.Spec.NodeUpdateStrategy.RollingUpdate)
	}

	if instance.Spec.ControlPlaneNodeSelector != nil {
		if v, ok := instance.Spec.ControlPlaneNodeSelector["beta.kubernetes.io/os"]; ok && v != "linux" {
			return fmt.Errorf("installation spec.ControlPlaneNodeSelector 'beta.kubernetes.io/os=%s' is not supported", v)
		}
		if v, ok := instance.Spec.ControlPlaneNodeSelector["kubernetes.io/os"]; ok && v != "linux" {
			return fmt.Errorf("installation spec.ControlPlaneNodeSelector 'kubernetes.io/os=%s' is not supported", v)
		}
	}

	if instance.Spec.ControlPlaneReplicas != nil && *instance.Spec.ControlPlaneReplicas <= 0 {
		return fmt.Errorf("installation spec.ControlPlaneReplicas should be greater than 0")
	}

	validComponentNames := map[operatorv1.ComponentName]struct{}{
		operatorv1.ComponentNameKubeControllers: {},
		operatorv1.ComponentNameNode:            {},
		operatorv1.ComponentNameTypha:           {},
	}

	for _, resource := range instance.Spec.ComponentResources {
		if _, ok := validComponentNames[resource.ComponentName]; !ok {
			return fmt.Errorf("installation spec.ComponentResources.ComponentName %s is not supported", resource.ComponentName)
		}
	}

	// Verify that non-privileged mode is not Enabled, since it's been deprecated.
	if instance.Spec.NonPrivileged != nil && *instance.Spec.NonPrivileged == operatorv1.NonPrivilegedEnabled {
		return fmt.Errorf("non-privileged Calico is deprecated and cannot be Enabled; please, remove this field from your installation spec")
	}

	// Verify the CalicoNodeDaemonSet overrides, if specified, is valid.
	if ds := instance.Spec.CalicoNodeDaemonSet; ds != nil {
		err := validation.ValidateReplicatedPodResourceOverrides(ds, node.ValidateCalicoNodeDaemonSetContainer, node.ValidateCalicoNodeDaemonSetInitContainer)
		err2 := validateExclusiveInitContainers(rcc.GetInitContainers(ds))
		if err != nil || err2 != nil {
			return fmt.Errorf("installation spec.CalicoNodeDaemonSet is not valid: %w", errors.Join(err, err2))
		}
	}

	// Verify the CalicoNodeWindowsDaemonSet overrides, if specified, is valid.
	if ds := instance.Spec.CalicoNodeWindowsDaemonSet; ds != nil {
		err := validation.ValidateReplicatedPodResourceOverrides(ds, node.ValidateCalicoNodeWindowsDaemonSetContainer, node.ValidateCalicoNodeWindowsDaemonSetInitContainer)
		if err != nil {
			return fmt.Errorf("installation spec.CalicoNodeWindowsDaemonSet is not valid: %w", err)
		}
	}

	// Verify the CalicoKubeControllersDeployment overrides, if specified, is valid.
	if deploy := instance.Spec.CalicoKubeControllersDeployment; deploy != nil {
		err := validation.ValidateReplicatedPodResourceOverrides(deploy, kubecontrollers.ValidateCalicoKubeControllersDeploymentContainer, validation.NoContainersDefined)
		if err != nil {
			return fmt.Errorf("installation spec.CalicoKubeControllersDeployment is not valid: %w", err)
		}
	}

	// Verify the TyphaDeployment overrides, if specified, is valid.
	if deploy := instance.Spec.TyphaDeployment; deploy != nil {
		err := validation.ValidateReplicatedPodResourceOverrides(deploy, typha.ValidateTyphaDeploymentContainer, typha.ValidateTyphaDeploymentInitContainer)
		if err != nil {
			return fmt.Errorf("installation spec.TyphaDeployment is not valid: %w", err)
		}
	}

	// Verify the CSINodeDriverDaemonSet overrides, if specified, is valid.
	if ds := instance.Spec.CSINodeDriverDaemonSet; ds != nil {
		err := validation.ValidateReplicatedPodResourceOverrides(ds, csinodedriver.ValidateCSINodeDriverDaemonSetContainer, validation.NoContainersDefined)
		if err != nil {
			return fmt.Errorf("installation spec.CSINodeDriverDaemonSet is not valid: %w", err)
		}
	}

	// Verify CNILogging to not exist for non-calico cni
	if cni := instance.Spec.CNI.Type; cni != operatorv1.PluginCalico {
		if instance.Spec.Logging != nil && instance.Spec.Logging.CNI != nil {
			return fmt.Errorf("installation spec.Logging.cni is not valid and should not be provided when spec.cni.type is Not Calico")
		}
	}

	if common.WindowsEnabled(instance.Spec) {
		if k8sapi.Endpoint.Host == "" || k8sapi.Endpoint.Port == "" {
			return fmt.Errorf("services endpoint configmap '%s' does not have all required information for Calico Windows daemonset configuration", render.K8sSvcEndpointConfigMapName)
		}
		if instance.Spec.CNI.Type == operatorv1.PluginCalico {
			if len(instance.Spec.ServiceCIDRs) == 0 {
				return fmt.Errorf("installation spec.ServiceCIDRs must be provided when using Calico CNI on Windows")
			}
			if instance.Spec.CalicoNetwork != nil {
				if v4pool := render.GetIPv4Pool(instance.Spec.CalicoNetwork.IPPools); v4pool != nil {
					if v4pool.Encapsulation != operatorv1.EncapsulationVXLAN && v4pool.Encapsulation != operatorv1.EncapsulationNone {
						return fmt.Errorf("IPv4 IPPool encapsulation %s is not supported by Calico for Windows", v4pool.Encapsulation)
					}
				}
			}
		}
	} else {
		if instance.Spec.WindowsNodes != nil {
			return fmt.Errorf("installation spec.WindowsNodes is not valid and should not be provided when Calico for Windows is disabled")
		}
	}

	if operatorv1.IsFIPSModeEnabled(instance.Spec.FIPSMode) {
		return fmt.Errorf("installation spec.FIPSMode=%v is not supported; FIPS mode has been removed", *instance.Spec.FIPSMode)
	}

	if instance.Spec.KubernetesProvider != operatorv1.ProviderAKS && instance.Spec.Azure != nil {
		return fmt.Errorf("installation spec.Azure should be set only for AKS provider")
	}

	return nil
}

// validateExclusiveInitContainers checks that the init containers do not contain both mount-bpffs and ebpf-bootstrap.
func validateExclusiveInitContainers(initContainers []v1.Container) error {
	hasMountBpffs, hasEbpfBootstrap := false, false
	for _, c := range initContainers {
		switch c.Name {
		case "mount-bpffs":
			hasMountBpffs = true
		case "ebpf-bootstrap":
			hasEbpfBootstrap = true
		}
		if hasMountBpffs && hasEbpfBootstrap {
			return fmt.Errorf("init container names mount-bpffs and ebpf-bootstrap are mutually exclusive, please remove one of them")
		}
	}
	return nil
}

// validateNodeAddressDetection checks that at most one form of IP auto-detection is configured per-family.
func validateNodeAddressDetection(ad *operatorv1.NodeAddressAutodetection) error {
	numEnabled := 0
	if len(ad.Interface) != 0 {
		numEnabled++
	}
	if len(ad.SkipInterface) != 0 {
		numEnabled++
	}
	if len(ad.CanReach) != 0 {
		numEnabled++
	}
	if ad.FirstFound != nil && *ad.FirstFound {
		numEnabled++
	}
	if len(ad.CIDRS) != 0 {
		numEnabled++
		for _, c := range ad.CIDRS {
			_, _, err := net.ParseCIDR(c)
			if err != nil {
				return fmt.Errorf("invalid CIDR provided for node address autodetection: %s", c)
			}
		}
	}

	if ad.Kubernetes != nil {
		numEnabled++
	}

	if numEnabled > 1 {
		return fmt.Errorf("no more than one node address autodetection method can be specified per-family")
	}
	return nil
}

func validateHostPorts(hp *operatorv1.HostPortsType) error {
	if hp == nil {
		return fmt.Errorf("HostPorts must be set, it should be one of %s",
			strings.Join(operatorv1.HostPortsTypesString, ","))
	}
	valid := false
	for _, t := range operatorv1.HostPortsTypes {
		if *hp == t {
			valid = true
		}
	}
	if !valid {
		return fmt.Errorf("%s is invalid for HostPorts, it should be one of %s",
			hp, strings.Join(operatorv1.HostPortsTypesString, ","))
	}

	return nil
}
