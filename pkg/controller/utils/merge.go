// Copyright (c) 2020, 2022-2026 Tigera, Inc. All rights reserved.

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
	"reflect"

	v1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/tigera/operator/api/v1"
)

type CompareResult int

const (
	Same CompareResult = iota
	AOnlySet
	BOnlySet
	Different
)

func OverrideInstallationSpec(cfg, override operatorv1.InstallationSpec) operatorv1.InstallationSpec {
	inst := *cfg.DeepCopy()

	switch compareFields(inst.Variant, override.Variant) {
	case BOnlySet, Different:
		inst.Variant = override.Variant
	}

	switch compareFields(inst.Registry, override.Registry) {
	case BOnlySet, Different:
		inst.Registry = override.Registry
	}

	switch compareFields(inst.ImagePath, override.ImagePath) {
	case BOnlySet, Different:
		inst.ImagePath = override.ImagePath
	}

	switch compareFields(inst.ImagePrefix, override.ImagePrefix) {
	case BOnlySet, Different:
		inst.ImagePrefix = override.ImagePrefix
	}

	switch compareFields(inst.ImagePullSecrets, override.ImagePullSecrets) {
	case BOnlySet, Different:
		inst.ImagePullSecrets = make([]v1.LocalObjectReference, len(override.ImagePullSecrets))
		copy(inst.ImagePullSecrets, override.ImagePullSecrets)
	}

	switch compareFields(inst.ImagePullPolicy, override.ImagePullPolicy) {
	case BOnlySet, Different:
		inst.ImagePullPolicy = ptr.To(*override.ImagePullPolicy)
	}

	switch compareFields(inst.KubernetesProvider, override.KubernetesProvider) {
	case BOnlySet, Different:
		inst.KubernetesProvider = override.KubernetesProvider
	}

	switch compareFields(inst.CNI, override.CNI) {
	case BOnlySet:
		inst.CNI = override.CNI.DeepCopy()
	case Different:
		inst.CNI = mergeCNISpecs(inst.CNI, override.CNI)
	}

	switch compareFields(inst.CalicoNetwork, override.CalicoNetwork) {
	case BOnlySet:
		inst.CalicoNetwork = override.CalicoNetwork.DeepCopy()
	case Different:
		inst.CalicoNetwork = mergeCalicoNetwork(inst.CalicoNetwork, override.CalicoNetwork)
	}

	switch compareFields(inst.ControlPlaneNodeSelector, override.ControlPlaneNodeSelector) {
	case BOnlySet, Different:
		inst.ControlPlaneNodeSelector = make(map[string]string, len(override.ControlPlaneNodeSelector))
		for key, val := range override.ControlPlaneNodeSelector {
			inst.ControlPlaneNodeSelector[key] = val
		}
	}

	switch compareFields(inst.ControlPlaneTolerations, override.ControlPlaneTolerations) {
	case BOnlySet, Different:
		inst.ControlPlaneTolerations = make([]v1.Toleration, len(override.ControlPlaneTolerations))
		copy(inst.ControlPlaneTolerations, override.ControlPlaneTolerations)
	}

	switch compareFields(inst.ControlPlaneReplicas, override.ControlPlaneReplicas) {
	case BOnlySet, Different:
		inst.ControlPlaneReplicas = override.ControlPlaneReplicas
	}

	switch compareFields(inst.NodeMetricsPort, override.NodeMetricsPort) {
	case BOnlySet, Different:
		inst.NodeMetricsPort = override.NodeMetricsPort
	}

	switch compareFields(inst.TyphaMetricsPort, override.TyphaMetricsPort) {
	case BOnlySet, Different:
		inst.TyphaMetricsPort = override.TyphaMetricsPort
	}

	switch compareFields(inst.FlexVolumePath, override.FlexVolumePath) {
	case BOnlySet, Different:
		inst.FlexVolumePath = override.FlexVolumePath
	}

	switch compareFields(inst.KubeletVolumePluginPath, override.KubeletVolumePluginPath) {
	case BOnlySet, Different:
		inst.KubeletVolumePluginPath = override.KubeletVolumePluginPath
	}

	switch compareFields(inst.NodeUpdateStrategy, override.NodeUpdateStrategy) {
	case BOnlySet, Different:
		override.NodeUpdateStrategy.DeepCopyInto(&inst.NodeUpdateStrategy)
	}

	switch compareFields(inst.ComponentResources, override.ComponentResources) {
	case BOnlySet, Different:
		inst.ComponentResources = make([]operatorv1.ComponentResource, len(override.ComponentResources))
		copy(inst.ComponentResources, override.ComponentResources)
	}

	switch compareFields(inst.TyphaAffinity, override.TyphaAffinity) {
	case BOnlySet, Different:
		inst.TyphaAffinity = override.TyphaAffinity
	}

	switch compareFields(inst.CertificateManagement, override.CertificateManagement) {
	case BOnlySet:
		inst.CertificateManagement = override.CertificateManagement.DeepCopy()
	case Different:
		override.CertificateManagement.DeepCopyInto(inst.CertificateManagement)
	}

	switch compareFields(inst.TLSCipherSuites, override.TLSCipherSuites) {
	case BOnlySet, Different:
		inst.TLSCipherSuites = override.TLSCipherSuites
	}

	switch compareFields(inst.NonPrivileged, override.NonPrivileged) {
	case BOnlySet, Different:
		inst.NonPrivileged = override.NonPrivileged
	}

	switch compareFields(inst.CalicoNodeDaemonSet, override.CalicoNodeDaemonSet) {
	case BOnlySet:
		inst.CalicoNodeDaemonSet = override.CalicoNodeDaemonSet.DeepCopy()
	case Different:
		inst.CalicoNodeDaemonSet = mergeCalicoNodeDaemonSet(inst.CalicoNodeDaemonSet, override.CalicoNodeDaemonSet)
	}
	switch compareFields(inst.CSINodeDriverDaemonSet, override.CSINodeDriverDaemonSet) {
	case BOnlySet:
		inst.CSINodeDriverDaemonSet = override.CSINodeDriverDaemonSet.DeepCopy()
	case Different:
		inst.CSINodeDriverDaemonSet = mergeCSINodeDriverDaemonset(inst.CSINodeDriverDaemonSet, override.CSINodeDriverDaemonSet)
	}

	switch compareFields(inst.CalicoNodeWindowsDaemonSet, override.CalicoNodeWindowsDaemonSet) {
	case BOnlySet:
		inst.CalicoNodeWindowsDaemonSet = override.CalicoNodeWindowsDaemonSet.DeepCopy()
	case Different:
		inst.CalicoNodeWindowsDaemonSet = mergeCalicoNodeWindowsDaemonSet(inst.CalicoNodeWindowsDaemonSet, override.CalicoNodeWindowsDaemonSet)
	}

	switch compareFields(inst.CalicoKubeControllersDeployment, override.CalicoKubeControllersDeployment) {
	case BOnlySet:
		inst.CalicoKubeControllersDeployment = override.CalicoKubeControllersDeployment.DeepCopy()
	case Different:
		inst.CalicoKubeControllersDeployment = mergeCalicoKubeControllersDeployment(inst.CalicoKubeControllersDeployment, override.CalicoKubeControllersDeployment)
	}

	switch compareFields(inst.TyphaDeployment, override.TyphaDeployment) {
	case BOnlySet:
		inst.TyphaDeployment = override.TyphaDeployment.DeepCopy()
	case Different:
		inst.TyphaDeployment = mergeTyphaDeployment(inst.TyphaDeployment, override.TyphaDeployment)
	}

	switch compareFields(inst.TyphaPodDisruptionBudget, override.TyphaPodDisruptionBudget) {
	case BOnlySet, Different:
		inst.TyphaPodDisruptionBudget = override.TyphaPodDisruptionBudget.DeepCopy()
	}

	switch compareFields(inst.CalicoWindowsUpgradeDaemonSet, override.CalicoWindowsUpgradeDaemonSet) {
	case BOnlySet:
		inst.CalicoWindowsUpgradeDaemonSet = override.CalicoWindowsUpgradeDaemonSet.DeepCopy()
	case Different:
		inst.CalicoWindowsUpgradeDaemonSet = mergeCalicoWindowsUpgradeDaemonSet(inst.CalicoWindowsUpgradeDaemonSet, override.CalicoWindowsUpgradeDaemonSet)
	}

	switch compareFields(inst.FIPSMode, override.FIPSMode) {
	case BOnlySet, Different:
		inst.FIPSMode = override.FIPSMode
	}

	switch compareFields(inst.Logging, override.Logging) {
	case BOnlySet, Different:
		inst.Logging = override.Logging
	}

	switch compareFields(inst.WindowsNodes, override.WindowsNodes) {
	case BOnlySet:
		inst.WindowsNodes = override.WindowsNodes.DeepCopy()
	case Different:
		inst.WindowsNodes = mergeWindowsNodes(inst.WindowsNodes, override.WindowsNodes)
	}

	switch compareFields(inst.ServiceCIDRs, override.ServiceCIDRs) {
	case BOnlySet, Different:
		inst.ServiceCIDRs = override.ServiceCIDRs
	}

	switch compareFields(inst.Azure, override.Azure) {
	case BOnlySet, Different:
		inst.Azure = override.Azure
	}

	switch compareFields(inst.Proxy, override.Proxy) {
	case BOnlySet, Different:
		inst.Proxy = override.Proxy
	}

	switch compareFields(inst.NetworkPolicy, override.NetworkPolicy) {
	case BOnlySet, Different:
		inst.NetworkPolicy = override.NetworkPolicy
	}

	return inst
}

func compareFields(a, b interface{}) CompareResult {
	// Flag if az or bz are the nil/zero value
	az := reflect.DeepEqual(a, reflect.Zero(reflect.TypeOf(a)).Interface())
	bz := reflect.DeepEqual(b, reflect.Zero(reflect.TypeOf(b)).Interface())
	if az && bz {
		return Same
	}
	if reflect.DeepEqual(a, b) {
		return Same
	}
	if az {
		return BOnlySet
	}
	if bz {
		return AOnlySet
	}
	return Different
}

func mergeCNISpecs(cfg, override *operatorv1.CNISpec) *operatorv1.CNISpec {
	out := cfg.DeepCopy()

	switch compareFields(out.Type, override.Type) {
	case BOnlySet, Different:
		out.Type = override.Type
	}

	switch compareFields(out.IPAM, override.IPAM) {
	case BOnlySet, Different:
		out.IPAM = override.IPAM.DeepCopy()
	}

	switch compareFields(out.SpecVersion, override.SpecVersion) {
	case BOnlySet, Different:
		out.SpecVersion = override.SpecVersion
	}

	switch compareFields(out.BinDir, override.BinDir) {
	case BOnlySet, Different:
		out.BinDir = override.BinDir
	}

	switch compareFields(out.ConfDir, override.ConfDir) {
	case BOnlySet, Different:
		out.ConfDir = override.ConfDir
	}

	switch compareFields(out.InstallMode, override.InstallMode) {
	case BOnlySet, Different:
		out.InstallMode = override.InstallMode
	}

	return out
}

func mergeCalicoNetwork(cfg, override *operatorv1.CalicoNetworkSpec) *operatorv1.CalicoNetworkSpec {
	out := cfg.DeepCopy()

	switch compareFields(out.BGP, override.BGP) {
	case BOnlySet, Different:
		out.BGP = override.BGP
	}

	switch compareFields(out.ClusterRoutingMode, override.ClusterRoutingMode) {
	case BOnlySet, Different:
		out.ClusterRoutingMode = override.ClusterRoutingMode
	}

	switch compareFields(out.IPPools, override.IPPools) {
	case BOnlySet, Different:
		out.IPPools = make([]operatorv1.IPPool, len(override.IPPools))
		for i := range override.IPPools {
			override.IPPools[i].DeepCopyInto(&out.IPPools[i])
		}
	}

	switch compareFields(out.MTU, override.MTU) {
	case BOnlySet, Different:
		out.MTU = override.MTU
	}

	switch compareFields(out.LinuxPolicySetupTimeoutSeconds, override.LinuxPolicySetupTimeoutSeconds) {
	case BOnlySet, Different:
		out.LinuxPolicySetupTimeoutSeconds = override.LinuxPolicySetupTimeoutSeconds
	}

	switch compareFields(out.LinuxDataplane, override.LinuxDataplane) {
	case BOnlySet, Different:
		out.LinuxDataplane = override.LinuxDataplane
	}

	switch compareFields(out.WindowsDataplane, override.WindowsDataplane) {
	case BOnlySet, Different:
		out.WindowsDataplane = override.WindowsDataplane
	}

	switch compareFields(out.BPFNetworkBootstrap, override.BPFNetworkBootstrap) {
	case BOnlySet, Different:
		out.BPFNetworkBootstrap = override.BPFNetworkBootstrap
	}

	switch compareFields(out.KubeProxyManagement, override.KubeProxyManagement) {
	case BOnlySet, Different:
		out.KubeProxyManagement = override.KubeProxyManagement
	}

	switch compareFields(out.NodeAddressAutodetectionV4, override.NodeAddressAutodetectionV4) {
	case BOnlySet, Different:
		out.NodeAddressAutodetectionV4 = override.NodeAddressAutodetectionV4
	}

	switch compareFields(out.NodeAddressAutodetectionV6, override.NodeAddressAutodetectionV6) {
	case BOnlySet, Different:
		out.NodeAddressAutodetectionV6 = override.NodeAddressAutodetectionV6
	}

	switch compareFields(out.HostPorts, override.HostPorts) {
	case BOnlySet, Different:
		out.HostPorts = override.HostPorts
	}

	switch compareFields(out.MultiInterfaceMode, override.MultiInterfaceMode) {
	case BOnlySet, Different:
		out.MultiInterfaceMode = override.MultiInterfaceMode
	}

	switch compareFields(out.ContainerIPForwarding, override.ContainerIPForwarding) {
	case BOnlySet, Different:
		out.ContainerIPForwarding = override.ContainerIPForwarding
	}

	switch compareFields(out.LinuxPodInterfaceType, override.LinuxPodInterfaceType) {
	case BOnlySet, Different:
		out.LinuxPodInterfaceType = override.LinuxPodInterfaceType
	}

	switch compareFields(out.Sysctl, override.Sysctl) {
	case BOnlySet, Different:
		out.Sysctl = override.Sysctl
	}
	return out
}

func mergeMetadata(cfg, override *operatorv1.Metadata) *operatorv1.Metadata {
	out := cfg.DeepCopy()

	switch compareFields(out.Labels, override.Labels) {
	case BOnlySet, Different:
		out.Labels = make(map[string]string, len(override.Labels))
		for key, val := range override.Labels {
			out.Labels[key] = val
		}
	}

	switch compareFields(out.Annotations, override.Annotations) {
	case BOnlySet, Different:
		out.Annotations = make(map[string]string, len(override.Annotations))
		for key, val := range override.Annotations {
			out.Annotations[key] = val
		}
	}
	return out
}

func mergeCalicoNodeDaemonSet(cfg, override *operatorv1.CalicoNodeDaemonSet) *operatorv1.CalicoNodeDaemonSet {
	out := cfg.DeepCopy()

	switch compareFields(out.Metadata, override.Metadata) {
	case BOnlySet:
		out.Metadata = override.Metadata.DeepCopy()
	case Different:
		out.Metadata = mergeMetadata(out.Metadata, override.Metadata)
	}

	mergePodSpec := func(cfg, override *operatorv1.CalicoNodeDaemonSetPodSpec) *operatorv1.CalicoNodeDaemonSetPodSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.InitContainers, override.InitContainers) {
		case BOnlySet, Different:
			out.InitContainers = make([]operatorv1.CalicoNodeDaemonSetInitContainer, len(override.InitContainers))
			copy(out.InitContainers, override.InitContainers)
		}

		switch compareFields(out.Containers, override.Containers) {
		case BOnlySet, Different:
			out.Containers = make([]operatorv1.CalicoNodeDaemonSetContainer, len(override.Containers))
			copy(out.Containers, override.Containers)
		}

		switch compareFields(out.Affinity, override.Affinity) {
		case BOnlySet, Different:
			out.Affinity = override.Affinity
		}

		switch compareFields(out.NodeSelector, override.NodeSelector) {
		case BOnlySet, Different:
			out.NodeSelector = override.NodeSelector
		}

		switch compareFields(out.Tolerations, override.Tolerations) {
		case BOnlySet, Different:
			out.Tolerations = override.Tolerations
		}
		return out
	}
	mergeTemplateSpec := func(cfg, override *operatorv1.CalicoNodeDaemonSetPodTemplateSpec) *operatorv1.CalicoNodeDaemonSetPodTemplateSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.Metadata, override.Metadata) {
		case BOnlySet:
			out.Metadata = override.Metadata.DeepCopy()
		case Different:
			out.Metadata = mergeMetadata(out.Metadata, override.Metadata)
		}

		switch compareFields(out.Spec, override.Spec) {
		case BOnlySet:
			out.Spec = override.Spec.DeepCopy()
		case Different:
			out.Spec = mergePodSpec(out.Spec, override.Spec)
		}

		return out
	}
	mergeSpec := func(cfg, override *operatorv1.CalicoNodeDaemonSetSpec) *operatorv1.CalicoNodeDaemonSetSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.MinReadySeconds, override.MinReadySeconds) {
		case BOnlySet, Different:
			out.MinReadySeconds = override.MinReadySeconds
		}

		switch compareFields(out.Template, override.Template) {
		case BOnlySet:
			out.Template = override.Template.DeepCopy()
		case Different:
			out.Template = mergeTemplateSpec(out.Template, override.Template)
		}

		return out
	}

	switch compareFields(out.Spec, override.Spec) {
	case BOnlySet:
		out.Spec = override.Spec.DeepCopy()
	case Different:
		out.Spec = mergeSpec(out.Spec, override.Spec)
	}

	return out
}

func mergeCalicoNodeWindowsDaemonSet(cfg, override *operatorv1.CalicoNodeWindowsDaemonSet) *operatorv1.CalicoNodeWindowsDaemonSet {
	out := cfg.DeepCopy()

	switch compareFields(out.Metadata, override.Metadata) {
	case BOnlySet:
		out.Metadata = override.Metadata.DeepCopy()
	case Different:
		out.Metadata = mergeMetadata(out.Metadata, override.Metadata)
	}

	mergePodSpec := func(cfg, override *operatorv1.CalicoNodeWindowsDaemonSetPodSpec) *operatorv1.CalicoNodeWindowsDaemonSetPodSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.InitContainers, override.InitContainers) {
		case BOnlySet, Different:
			out.InitContainers = make([]operatorv1.CalicoNodeWindowsDaemonSetInitContainer, len(override.InitContainers))
			copy(out.InitContainers, override.InitContainers)
		}

		switch compareFields(out.Containers, override.Containers) {
		case BOnlySet, Different:
			out.Containers = make([]operatorv1.CalicoNodeWindowsDaemonSetContainer, len(override.Containers))
			copy(out.Containers, override.Containers)
		}

		switch compareFields(out.Affinity, override.Affinity) {
		case BOnlySet, Different:
			out.Affinity = override.Affinity
		}

		switch compareFields(out.NodeSelector, override.NodeSelector) {
		case BOnlySet, Different:
			out.NodeSelector = override.NodeSelector
		}

		switch compareFields(out.Tolerations, override.Tolerations) {
		case BOnlySet, Different:
			out.Tolerations = override.Tolerations
		}
		return out
	}
	mergeTemplateSpec := func(cfg, override *operatorv1.CalicoNodeWindowsDaemonSetPodTemplateSpec) *operatorv1.CalicoNodeWindowsDaemonSetPodTemplateSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.Metadata, override.Metadata) {
		case BOnlySet:
			out.Metadata = override.Metadata.DeepCopy()
		case Different:
			out.Metadata = mergeMetadata(out.Metadata, override.Metadata)
		}

		switch compareFields(out.Spec, override.Spec) {
		case BOnlySet:
			out.Spec = override.Spec.DeepCopy()
		case Different:
			out.Spec = mergePodSpec(out.Spec, override.Spec)
		}

		return out
	}
	mergeSpec := func(cfg, override *operatorv1.CalicoNodeWindowsDaemonSetSpec) *operatorv1.CalicoNodeWindowsDaemonSetSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.MinReadySeconds, override.MinReadySeconds) {
		case BOnlySet, Different:
			out.MinReadySeconds = override.MinReadySeconds
		}

		switch compareFields(out.Template, override.Template) {
		case BOnlySet:
			out.Template = override.Template.DeepCopy()
		case Different:
			out.Template = mergeTemplateSpec(out.Template, override.Template)
		}

		return out
	}

	switch compareFields(out.Spec, override.Spec) {
	case BOnlySet:
		out.Spec = override.Spec.DeepCopy()
	case Different:
		out.Spec = mergeSpec(out.Spec, override.Spec)
	}

	return out
}

func mergeCSINodeDriverDaemonset(cfg, override *operatorv1.CSINodeDriverDaemonSet) *operatorv1.CSINodeDriverDaemonSet {
	out := cfg.DeepCopy()

	switch compareFields(out.Metadata, override.Metadata) {
	case BOnlySet:
		out.Metadata = override.Metadata.DeepCopy()
	case Different:
		out.Metadata = mergeMetadata(out.Metadata, override.Metadata)
	}

	mergePodSpec := func(cfg, override *operatorv1.CSINodeDriverDaemonSetPodSpec) *operatorv1.CSINodeDriverDaemonSetPodSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.Containers, override.Containers) {
		case BOnlySet, Different:
			out.Containers = make([]operatorv1.CSINodeDriverDaemonSetContainer, len(override.Containers))
			copy(out.Containers, override.Containers)
		}

		switch compareFields(out.Affinity, override.Affinity) {
		case BOnlySet, Different:
			out.Affinity = override.Affinity
		}

		switch compareFields(out.NodeSelector, override.NodeSelector) {
		case BOnlySet, Different:
			out.NodeSelector = override.NodeSelector
		}

		switch compareFields(out.Tolerations, override.Tolerations) {
		case BOnlySet, Different:
			out.Tolerations = override.Tolerations
		}
		return out
	}
	mergeTemplateSpec := func(cfg, override *operatorv1.CSINodeDriverDaemonSetPodTemplateSpec) *operatorv1.CSINodeDriverDaemonSetPodTemplateSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.Metadata, override.Metadata) {
		case BOnlySet:
			out.Metadata = override.Metadata.DeepCopy()
		case Different:
			out.Metadata = mergeMetadata(out.Metadata, override.Metadata)
		}

		switch compareFields(out.Spec, override.Spec) {
		case BOnlySet:
			out.Spec = override.Spec.DeepCopy()
		case Different:
			out.Spec = mergePodSpec(out.Spec, override.Spec)
		}

		return out
	}
	mergeSpec := func(cfg, override *operatorv1.CSINodeDriverDaemonSetSpec) *operatorv1.CSINodeDriverDaemonSetSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.Template, override.Template) {
		case BOnlySet:
			out.Template = override.Template.DeepCopy()
		case Different:
			out.Template = mergeTemplateSpec(out.Template, override.Template)
		}

		return out
	}

	switch compareFields(out.Spec, override.Spec) {
	case BOnlySet:
		out.Spec = override.Spec.DeepCopy()
	case Different:
		out.Spec = mergeSpec(out.Spec, override.Spec)
	}

	return out
}

func mergeCalicoKubeControllersDeployment(cfg, override *operatorv1.CalicoKubeControllersDeployment) *operatorv1.CalicoKubeControllersDeployment {
	out := cfg.DeepCopy()

	switch compareFields(out.Metadata, override.Metadata) {
	case BOnlySet:
		out.Metadata = override.Metadata.DeepCopy()
	case Different:
		out.Metadata = mergeMetadata(out.Metadata, override.Metadata)
	}

	mergePodSpec := func(cfg, override *operatorv1.CalicoKubeControllersDeploymentPodSpec) *operatorv1.CalicoKubeControllersDeploymentPodSpec {
		out := cfg.DeepCopy()

		// CalicoKubeControllersDeployment doesn't have init containers.
		switch compareFields(out.Containers, override.Containers) {
		case BOnlySet, Different:
			out.Containers = make([]operatorv1.CalicoKubeControllersDeploymentContainer, len(override.Containers))
			copy(out.Containers, override.Containers)
		}

		switch compareFields(out.Affinity, override.Affinity) {
		case BOnlySet, Different:
			out.Affinity = override.Affinity
		}

		switch compareFields(out.NodeSelector, override.NodeSelector) {
		case BOnlySet, Different:
			out.NodeSelector = override.NodeSelector
		}

		switch compareFields(out.Tolerations, override.Tolerations) {
		case BOnlySet, Different:
			out.Tolerations = override.Tolerations
		}
		return out
	}
	mergeTemplateSpec := func(cfg, override *operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec) *operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.Metadata, override.Metadata) {
		case BOnlySet:
			out.Metadata = override.Metadata.DeepCopy()
		case Different:
			out.Metadata = mergeMetadata(out.Metadata, override.Metadata)
		}

		switch compareFields(out.Spec, override.Spec) {
		case BOnlySet:
			out.Spec = override.Spec.DeepCopy()
		case Different:
			out.Spec = mergePodSpec(out.Spec, override.Spec)
		}

		return out
	}
	mergeSpec := func(cfg, override *operatorv1.CalicoKubeControllersDeploymentSpec) *operatorv1.CalicoKubeControllersDeploymentSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.MinReadySeconds, override.MinReadySeconds) {
		case BOnlySet, Different:
			out.MinReadySeconds = override.MinReadySeconds
		}

		switch compareFields(out.Template, override.Template) {
		case BOnlySet:
			out.Template = override.Template.DeepCopy()
		case Different:
			out.Template = mergeTemplateSpec(out.Template, override.Template)
		}

		return out
	}

	switch compareFields(out.Spec, override.Spec) {
	case BOnlySet:
		out.Spec = override.Spec.DeepCopy()
	case Different:
		out.Spec = mergeSpec(out.Spec, override.Spec)
	}

	return out
}

func mergeTyphaDeployment(cfg, override *operatorv1.TyphaDeployment) *operatorv1.TyphaDeployment {
	out := cfg.DeepCopy()

	switch compareFields(out.Metadata, override.Metadata) {
	case BOnlySet:
		out.Metadata = override.Metadata.DeepCopy()
	case Different:
		out.Metadata = mergeMetadata(out.Metadata, override.Metadata)
	}

	mergePodSpec := func(cfg, override *operatorv1.TyphaDeploymentPodSpec) *operatorv1.TyphaDeploymentPodSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.InitContainers, override.InitContainers) {
		case BOnlySet, Different:
			out.InitContainers = make([]operatorv1.TyphaDeploymentInitContainer, len(override.Containers))
			copy(out.InitContainers, override.InitContainers)
		}

		switch compareFields(out.Containers, override.Containers) {
		case BOnlySet, Different:
			out.Containers = make([]operatorv1.TyphaDeploymentContainer, len(override.Containers))
			copy(out.Containers, override.Containers)
		}

		switch compareFields(out.Affinity, override.Affinity) {
		case BOnlySet, Different:
			out.Affinity = override.Affinity
		}

		switch compareFields(out.NodeSelector, override.NodeSelector) {
		case BOnlySet, Different:
			out.NodeSelector = override.NodeSelector
		}

		switch compareFields(out.TerminationGracePeriodSeconds, override.TerminationGracePeriodSeconds) {
		case BOnlySet, Different:
			out.TerminationGracePeriodSeconds = override.TerminationGracePeriodSeconds
		}

		switch compareFields(out.Tolerations, override.Tolerations) {
		case BOnlySet, Different:
			out.Tolerations = override.Tolerations
		}
		return out
	}
	mergeTemplateSpec := func(cfg, override *operatorv1.TyphaDeploymentPodTemplateSpec) *operatorv1.TyphaDeploymentPodTemplateSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.Metadata, override.Metadata) {
		case BOnlySet:
			out.Metadata = override.Metadata.DeepCopy()
		case Different:
			out.Metadata = mergeMetadata(out.Metadata, override.Metadata)
		}

		switch compareFields(out.Spec, override.Spec) {
		case BOnlySet:
			out.Spec = override.Spec.DeepCopy()
		case Different:
			out.Spec = mergePodSpec(out.Spec, override.Spec)
		}

		return out
	}
	mergeSpec := func(cfg, override *operatorv1.TyphaDeploymentSpec) *operatorv1.TyphaDeploymentSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.MinReadySeconds, override.MinReadySeconds) {
		case BOnlySet, Different:
			out.MinReadySeconds = override.MinReadySeconds
		}

		switch compareFields(out.Template, override.Template) {
		case BOnlySet:
			out.Template = override.Template.DeepCopy()
		case Different:
			out.Template = mergeTemplateSpec(out.Template, override.Template)
		}

		switch compareFields(out.Strategy, override.Strategy) {
		case BOnlySet, Different:
			out.Strategy = override.Strategy.DeepCopy()
		}

		return out
	}

	switch compareFields(out.Spec, override.Spec) {
	case BOnlySet:
		out.Spec = override.Spec.DeepCopy()
	case Different:
		out.Spec = mergeSpec(out.Spec, override.Spec)
	}

	return out
}

func mergeCalicoWindowsUpgradeDaemonSet(cfg, override *operatorv1.CalicoWindowsUpgradeDaemonSet) *operatorv1.CalicoWindowsUpgradeDaemonSet {
	out := cfg.DeepCopy()

	switch compareFields(out.Metadata, override.Metadata) {
	case BOnlySet:
		out.Metadata = override.Metadata.DeepCopy()
	case Different:
		out.Metadata = mergeMetadata(out.Metadata, override.Metadata)
	}

	mergePodSpec := func(cfg, override *operatorv1.CalicoWindowsUpgradeDaemonSetPodSpec) *operatorv1.CalicoWindowsUpgradeDaemonSetPodSpec {
		out := cfg.DeepCopy()

		// CalicoWindowsUpgradeDaemonSet doesn't have init containers.
		switch compareFields(out.Containers, override.Containers) {
		case BOnlySet, Different:
			out.Containers = make([]operatorv1.CalicoWindowsUpgradeDaemonSetContainer, len(override.Containers))
			copy(out.Containers, override.Containers)
		}

		switch compareFields(out.Affinity, override.Affinity) {
		case BOnlySet, Different:
			out.Affinity = override.Affinity
		}

		switch compareFields(out.NodeSelector, override.NodeSelector) {
		case BOnlySet, Different:
			out.NodeSelector = override.NodeSelector
		}

		switch compareFields(out.Tolerations, override.Tolerations) {
		case BOnlySet, Different:
			out.Tolerations = override.Tolerations
		}
		return out
	}
	mergeTemplateSpec := func(cfg, override *operatorv1.CalicoWindowsUpgradeDaemonSetPodTemplateSpec) *operatorv1.CalicoWindowsUpgradeDaemonSetPodTemplateSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.Metadata, override.Metadata) {
		case BOnlySet:
			out.Metadata = override.Metadata.DeepCopy()
		case Different:
			out.Metadata = mergeMetadata(out.Metadata, override.Metadata)
		}

		switch compareFields(out.Spec, override.Spec) {
		case BOnlySet:
			out.Spec = override.Spec.DeepCopy()
		case Different:
			out.Spec = mergePodSpec(out.Spec, override.Spec)
		}

		return out
	}
	mergeSpec := func(cfg, override *operatorv1.CalicoWindowsUpgradeDaemonSetSpec) *operatorv1.CalicoWindowsUpgradeDaemonSetSpec {
		out := cfg.DeepCopy()

		switch compareFields(out.MinReadySeconds, override.MinReadySeconds) {
		case BOnlySet, Different:
			out.MinReadySeconds = override.MinReadySeconds
		}

		switch compareFields(out.Template, override.Template) {
		case BOnlySet:
			out.Template = override.Template.DeepCopy()
		case Different:
			out.Template = mergeTemplateSpec(out.Template, override.Template)
		}

		return out
	}

	switch compareFields(out.Spec, override.Spec) {
	case BOnlySet:
		out.Spec = override.Spec.DeepCopy()
	case Different:
		out.Spec = mergeSpec(out.Spec, override.Spec)
	}

	return out
}

func mergeWindowsNodes(cfg, override *operatorv1.WindowsNodeSpec) *operatorv1.WindowsNodeSpec {
	out := cfg.DeepCopy()

	switch compareFields(out.CNIBinDir, override.CNIBinDir) {
	case BOnlySet, Different:
		out.CNIBinDir = override.CNIBinDir
	}

	switch compareFields(out.CNIConfigDir, override.CNIConfigDir) {
	case BOnlySet, Different:
		out.CNIConfigDir = override.CNIConfigDir
	}

	switch compareFields(out.CNILogDir, override.CNILogDir) {
	case BOnlySet, Different:
		out.CNILogDir = override.CNILogDir
	}

	switch compareFields(out.VXLANMACPrefix, override.VXLANMACPrefix) {
	case BOnlySet, Different:
		out.VXLANMACPrefix = override.VXLANMACPrefix
	}

	switch compareFields(out.VXLANAdapter, override.VXLANAdapter) {
	case BOnlySet, Different:
		out.VXLANAdapter = override.VXLANAdapter
	}

	return out
}
