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

package convert

import (
	"encoding/json"
	"fmt"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/migration/cni"
	"github.com/tigera/operator/pkg/controller/utils"
)

const (
	containerCalicoNode      = "calico-node"
	containerInstallCNI      = "install-cni"
	containerKubeControllers = "calico-kube-controllers"
)

// handleNetwork is a migration handler that validates any network settings that are common across
// all calico installations regardless of their networking configuration.
func handleNetwork(c *components, install *operatorv1.Installation) error {
	// Verify FELIX_DEFAULTENDPOINTTOHOSTACTION is set to Accept because that is what the operator sets it to.
	if err := c.node.assertEnv(ctx, c.client, containerCalicoNode, "FELIX_DEFAULTENDPOINTTOHOSTACTION", "accept"); err != nil {
		return err
	}

	return nil
}

// handleCalicoCNI is a migration handler that validates and converts Calico CNI configuration if Calico CNI is in use. This
// includes verifying that compatible networking backend and IPAM plugin are in use.
func handleCalicoCNI(c *components, install *operatorv1.Installation) error {
	plugin, err := getCNIPlugin(c)
	if err != nil {
		return err
	}
	if plugin != operatorv1.PluginCalico {
		return nil
	}

	if c.cni.CalicoConfig == nil {
		return ErrIncompatibleCluster{
			err:       "detected Calico CNI but couldn't find any CNI plugin with type=calico",
			component: ComponentCNIConfig,
			fix:       "ensure CNI config contains a plugin with type=calico, or if not using Calico CNI, ensure FELIX_INTERFACEPREFIX is set correctly on calico-node",
		}
	}

	if install.Spec.CNI == nil {
		install.Spec.CNI = &operatorv1.CNISpec{}
	}
	install.Spec.CNI.Type = plugin

	if install.Spec.CNI.IPAM == nil {
		install.Spec.CNI.IPAM = &operatorv1.IPAMSpec{}
	}

	if install.Spec.CalicoNetwork == nil {
		install.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
	}

	netBackend, err := getNetworkingBackend(c.node, c.client)
	if err != nil {
		return err
	}

	switch c.cni.CalicoConfig.IPAM.Type {
	case "calico-ipam":
		install.Spec.CNI.IPAM.Type = operatorv1.IPAMPluginCalico

		if err := subhandleCalicoIPAM(netBackend, *c.cni.CalicoConfig, install); err != nil {
			return err
		}
	case "host-local":
		install.Spec.CNI.IPAM.Type = operatorv1.IPAMPluginHostLocal

		if c.cni.HostLocalIPAMConfig == nil {
			return ErrIncompatibleCluster{
				err:       "detected Calico CNI with host-local IPAM, but failed to load host-local config",
				component: ComponentCNIConfig,
			}
		}

		if err := subhandleHostLocalIPAM(netBackend, *c.cni.HostLocalIPAMConfig, install); err != nil {
			return err
		}
	default:
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("unrecognized IPAM plugin '%s'", c.cni.CalicoConfig.IPAM.Type),
			component: ComponentCNIConfig,
			fix:       "update cluster to supported type 'calico-ipam' or 'host-local'",
		}
	}

	ip, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "IP")
	if err != nil {
		return err
	}

	// IP can be 'autodetect', 'none', or not defined.
	if ip == nil || *ip == "autodetect" {
		if err := handleIPAutoDetectionMethod(c, install); err != nil {
			return err
		}
	} else if ip != nil && *ip == "none" {
		c.node.ignoreEnv(containerCalicoNode, "IP_AUTODETECTION_METHOD")
	} else {
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("IP=%s is not supported", *ip),
			component: ComponentCalicoNode,
			fix:       "remove the IP env var or set it to 'none' or 'autodetect', depending on your cluster configuration",
		}
	}

	ip6, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "IP6")
	if err != nil {
		return err
	}
	// IP6 can be 'autodetect', 'none', or not defined.
	if ip6 != nil {
		switch *ip6 {
		case "none":
			// If IP6=none then if FELIX_IPV6SUPPORT is set it must be false.
			if err := c.node.assertEnv(ctx, c.client, containerCalicoNode, "FELIX_IPV6SUPPORT", "false"); err != nil {
				return err
			}
			// If IP6=none then if IP6_AUTODETECTION_METHOD is set it must be none. This is not a valid value
			// for the env var but Kops sets it.
			if err := c.node.assertEnv(ctx, c.client, containerCalicoNode, "IP6_AUTODETECTION_METHOD", "none"); err != nil {
				return err
			}
		case "autodetect":
			if err := handleIPv6AutoDetectionMethod(c, install); err != nil {
				return err
			}
			// If IP6=autodetect then if FELIX_IPV6SUPPORT is set it must be true.
			if err := c.node.assertEnv(ctx, c.client, containerCalicoNode, "FELIX_IPV6SUPPORT", "true"); err != nil {
				return err
			}
		default:
			return ErrIncompatibleCluster{
				err:       fmt.Sprintf("IP6=%s is not supported", *ip),
				component: ComponentCalicoNode,
				fix:       "remove the IP6 env var or set it to 'none' or 'autodetect', depending on your cluster configuration",
			}
		}
	} else {
		if err := c.node.assertEnv(ctx, c.client, containerCalicoNode, "FELIX_IPV6SUPPORT", "false"); err != nil {
			return err
		}
	}

	// If IPv6 only and bird backend is used, check that CALICO_ROUTER_ID, if defined, is set to `hash`.
	// Custom router ID values are only used for manual calico-node deployments and not
	// applicable to calico-node running as a daemonset.
	// In IPv6-only mode, calico-node will be rendered with CALICO_ROUTER_ID="hash".
	if ip6 != nil && *ip6 == "autodetect" && ip != nil && *ip == "none" {
		if install.Spec.CalicoNetwork.BGP != nil && *install.Spec.CalicoNetwork.BGP == operatorv1.BGPEnabled {
			if err := c.node.assertEnv(ctx, c.client, containerCalicoNode, "CALICO_ROUTER_ID", "hash"); err != nil {
				return err
			}
		} else {
			// IPv6-only clusters with BGP disabled should not have CALICO_ROUTER_ID set.
			routerID, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "CALICO_ROUTER_ID")
			if err != nil {
				return err
			}
			if routerID != nil {
				return ErrIncompatibleCluster{
					err:       "CNI config indicates an IPv6-only VXLAN cluster but CALICO_ROUTER_ID is only used for BGP-enabled clusters",
					component: ComponentCNIConfig,
					fix:       "remove the CALICO_ROUTER_ID env var",
				}
			}
		}
	}

	// CNI portmap plugin
	if _, ok := c.cni.Plugins["portmap"]; ok {
		hp := operatorv1.HostPortsEnabled
		install.Spec.CalicoNetwork.HostPorts = &hp
	} else {
		hp := operatorv1.HostPortsDisabled
		install.Spec.CalicoNetwork.HostPorts = &hp
	}

	type TuningSpec struct {
		Sysctl *map[string]string `json:"sysctl,omitempty"`
		Type   string             `json:"type"`
	}

	// CNI tuning plugin
	if pluginData, ok := c.cni.Plugins["tuning"]; ok {
		// parse JSON data
		var tuningSpecData TuningSpec
		if err := json.Unmarshal([]byte(pluginData.Bytes), &tuningSpecData); err != nil {
			return ErrIncompatibleCluster{
				err:       "error parsing CNI config plugin type 'tuning'",
				component: ComponentCNIConfig,
				fix:       "fix CNI config",
			}
		}

		sysctlTuning := []operatorv1.Sysctl{}
		for k, v := range *tuningSpecData.Sysctl {
			sysctl := operatorv1.Sysctl{
				Key:   k,
				Value: v,
			}
			sysctlTuning = append(sysctlTuning, sysctl)
		}

		if err = utils.VerifySysctl(sysctlTuning); err != nil {
			return ErrIncompatibleCluster{
				err:       err.Error(),
				component: ComponentCNIConfig,
				fix:       "remove unsupported Tuning parameter from CNI config",
			}
		}

		if len(sysctlTuning) > 0 {
			install.Spec.CalicoNetwork.Sysctl = sysctlTuning
		}
	}

	if c.cni.ConfigName != "k8s-pod-network" {
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("only 'k8s-pod-network' is supported as CNI name, found %s", c.cni.ConfigName),
			component: ComponentCNIConfig,
			fix:       "set CNI config name to 'k8s-pod-network'",
		}
	}

	// Other CNI features
	if c.cni.CalicoConfig.FeatureControl.FloatingIPs {
		return ErrIncompatibleCluster{
			err:       "floating IPs not supported",
			component: ComponentCNIConfig,
			fix:       "disable 'floating_ips' in the CNI configuration",
		}
	}
	if c.cni.CalicoConfig.FeatureControl.IPAddrsNoIpam {
		return ErrIncompatibleCluster{
			err:       "IpAddrsNoIpam not supported",
			component: ComponentCNIConfig,
			fix:       "disable 'IpAddrsNoIpam' in the CNI configuration",
		}
	}

	if c.cni.CalicoConfig.ContainerSettings.AllowIPForwarding {
		containerIPForward := operatorv1.ContainerIPForwardingEnabled
		install.Spec.CalicoNetwork.ContainerIPForwarding = &containerIPForward
	}

	return nil
}

func getNetworkingBackend(node CheckedDaemonSet, client client.Client) (string, error) {
	netBackend, err := node.getEnv(ctx, client, containerCalicoNode, "CALICO_NETWORKING_BACKEND")
	if err != nil {
		return "", err
	}

	switch {
	case netBackend == nil:
		return "bird", nil
	case *netBackend == "":
		return "bird", nil
	case *netBackend == "bird":
		return "bird", nil
	case *netBackend == "vxlan":
		return "vxlan", nil
	case *netBackend == "none":
		return "none", nil
	default:
		return "", fmt.Errorf("CALICO_NETWORKING_BACKEND %s is not valid", *netBackend)
	}
}

// subhandleCalicoIPAM checks all fields in the Calico IPAM configuration,
// if any fields have unexpected values an error message will be returned.
// The function tries to collect all the errors and report one message.
// If there are no errors and the config can be added to the passed in 'install'
// then nil is returned.
func subhandleCalicoIPAM(netBackend string, cnicfg cni.CalicoConf, install *operatorv1.Installation) error {
	switch netBackend {
	case "bird":
		install.Spec.CalicoNetwork.BGP = operatorv1.BGPOptionPtr(operatorv1.BGPEnabled)
	case "vxlan":
		install.Spec.CalicoNetwork.BGP = operatorv1.BGPOptionPtr(operatorv1.BGPDisabled)
	default:
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("detected networking backend '%s' is unknown or incompatible with Calico IPAM", netBackend),
			component: ComponentCalicoNode,
		}
	}

	// ignored fields:
	//   - c.cni.CalicoCNIConfig.IPAM.Name

	invalidFields := []string{}
	if cnicfg.IPAM.Subnet != "" {
		invalidFields = append(invalidFields, "ipam.subnet field is unsupported")
	}

	if len(cnicfg.IPAM.IPv4Pools) != 0 {
		invalidFields = append(invalidFields, "ipam.ipv4pools field is unsupported")
	}
	if len(cnicfg.IPAM.IPv6Pools) != 0 {
		invalidFields = append(invalidFields, "ipam.ipv6pools field is unsupported")
	}

	if len(invalidFields) > 0 {
		return ErrIncompatibleCluster{
			err:       "configuration could not be migrated: " + strings.Join(invalidFields, ","),
			component: ComponentCNIConfig,
			fix:       "remove the unsupported fields from the IPAM config",
		}
	}
	return nil
}

// subhandleHostLocalIPAM checks all fields in the Host Local IPAM configuration,
// if any fields have unexpected values an error message will be returned.
// The function tries to collect all the errors and report one message.
// If there are no errors and the config can be added to the passed in 'install'
// then nil is returned.
func subhandleHostLocalIPAM(netBackend string, ipamcfg cni.HostLocalIPAMConfig, install *operatorv1.Installation) error {
	switch netBackend {
	case "bird":
		install.Spec.CalicoNetwork.BGP = operatorv1.BGPOptionPtr(operatorv1.BGPEnabled)
	case "none":
		install.Spec.CalicoNetwork.BGP = operatorv1.BGPOptionPtr(operatorv1.BGPDisabled)
	default:
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("CALICO_NETWORKING_BACKEND %s is not valid", netBackend),
			component: ComponentCalicoNode,
		}
	}

	// ignored fields:
	//   - ipamcfg.Name

	invalidFields := []string{}
	if ipamcfg.Range != nil {
		invalidFields = checkRange("", *ipamcfg.Range)
	}
	if len(ipamcfg.Routes) != 0 {
		invalidFields = append(invalidFields, "routes is unsupported")
	}
	if ipamcfg.DataDir != "" {
		invalidFields = append(invalidFields, "dataDir is unsupported")
	}
	if ipamcfg.ResolvConf != "" {
		invalidFields = append(invalidFields, "resolveConf is unsupported")
	}
	switch len(ipamcfg.Ranges) {
	case 0:
	case 1:
		fallthrough
	case 2:
		for _, r := range ipamcfg.Ranges {
			switch len(r) {
			case 0:
			case 1:
				invalidFields = append(invalidFields, checkRange("ranges.", r[0])...)
			default:
				invalidFields = append(invalidFields, "only zero or one range is valid in the ranges field")
			}
		}
	default:
		invalidFields = append(invalidFields, "only zero, one, or two ranges are valid in the ranges field")
	}

	if len(invalidFields) > 0 {
		return ErrIncompatibleCluster{
			err:       "configuration could not be migrated: " + strings.Join(invalidFields, ","),
			component: ComponentCNIConfig,
			fix:       "adjust CNI config accordingly",
		}
	}

	return nil
}

// checkRange checks the fields in r for invalid values for HostLocal IPAM configuration.
func checkRange(prefix string, r cni.Range) []string {
	bf := []string{}
	if r.Subnet != "" {
		if r.Subnet != "usePodCidr" && r.Subnet != "usePodCidrIPv6" {
			bf = append(bf, prefix+"subnet has invalid value "+r.Subnet)
		}
	}
	if r.RangeStart != "" {
		bf = append(bf, prefix+"rangeStart is unsupported")
	}
	if r.RangeEnd != "" {
		bf = append(bf, prefix+"rangeEnd is unsupported")
	}
	if len(r.Gateway) != 0 {
		bf = append(bf, prefix+"gateway is unsupported")
	}

	return bf
}

// handleCalicoCNI is a migration handler that handles all CNI plugins excluding calico-cni.
// This includes verifying that compatible networking backend and IPAM plugin are in use.
func handleNonCalicoCNI(c *components, install *operatorv1.Installation) error {
	plugin, err := getCNIPlugin(c)
	if err != nil {
		return err
	}
	if plugin == operatorv1.PluginCalico {
		return nil
	}

	if icc := getContainer(c.node.Spec.Template.Spec, containerInstallCNI); icc != nil {
		// the install-cni container is unnecessary when not using calico cni.
		// however, it can still be present when calico-cni is not in use if another cni configuration is present with
		// an alphanumerically higher filename. as such, just log a warning.
		log.V(1).Info("found unexpected install-cni container. ignoring", "container", containerInstallCNI, "plugin", plugin)
	}

	// CALICO_NETWORKING_BACKEND
	if err := c.node.assertEnvIsSet(ctx, c.client, containerCalicoNode, "CALICO_NETWORKING_BACKEND", "none"); err != nil {
		return err
	}

	if install.Spec.CNI == nil {
		install.Spec.CNI = &operatorv1.CNISpec{}
	}

	switch plugin {
	case operatorv1.PluginAmazonVPC:
		install.Spec.CNI.Type = plugin
		// Verify FELIX_IPTABLESMANGLEALLOWACTION is set to Return because the operator will set it to Return
		// when configured with PluginAmazonVPC. The value is also expected to be necessary for Calico policy
		// to correctly function with the AmazonVPC plugin.
		if err := c.node.assertEnvIsSet(ctx, c.client, containerCalicoNode, "FELIX_IPTABLESMANGLEALLOWACTION", "return"); err != nil {
			return err
		}
	case operatorv1.PluginAzureVNET:
		install.Spec.CNI.Type = plugin
	case operatorv1.PluginGKE:
		install.Spec.CNI.Type = plugin
		// Verify FELIX_IPTABLESMANGLEALLOWACTION is set to Return because the operator will set it to Return
		// when configured with PluginGKE. The value is also expected to be necessary for Calico policy
		// to correctly function with the GKE plugin.
		if err := c.node.assertEnvIsSet(ctx, c.client, containerCalicoNode, "FELIX_IPTABLESMANGLEALLOWACTION", "return"); err != nil {
			return err
		}

		// Verify FELIX_IPTABLESFILTERALLOWACTION is set to Return because the operator will set it to Return
		// when configured with PluginGKE. The value is also expected to be necessary for Calico policy
		// to correctly function with the GKE plugin.
		if err := c.node.assertEnvIsSet(ctx, c.client, containerCalicoNode, "FELIX_IPTABLESFILTERALLOWACTION", "return"); err != nil {
			return err
		}
	default:
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("unable to migrate plugin '%s': unsupported.", plugin),
			component: ComponentCNIConfig,
		}
	}

	if err := c.node.assertEnv(ctx, c.client, containerCalicoNode, "IP", ""); err != nil {
		return err
	}

	if err := c.node.assertEnv(ctx, c.client, containerCalicoNode, "NO_DEFAULT_POOLS", "true"); err != nil {
		return err
	}

	return nil
}

// getAutoDetectionMethod gets the corresponding NodeAddressAutodetection for
// the given method or returns an error.
func getAutoDetectionMethod(method *string) (*operatorv1.NodeAddressAutodetection, error) {
	const (
		AutodetectionMethodFirst         = "first-found"
		AutodetectionMethodCanReach      = "can-reach="
		AutodetectionMethodInterface     = "interface="
		AutodetectionMethodSkipInterface = "skip-interface="
		AutodetectionMethodCIDR          = "cidr="
		AutodetectionMethodNodeIP        = "kubernetes-internal-ip"
	)

	// first-found
	if *method == "" || *method == AutodetectionMethodFirst {
		t := true
		return &operatorv1.NodeAddressAutodetection{FirstFound: &t}, nil
	}

	// interface
	if strings.HasPrefix(*method, AutodetectionMethodInterface) {
		ifStr := strings.TrimPrefix(*method, AutodetectionMethodInterface)
		return &operatorv1.NodeAddressAutodetection{Interface: ifStr}, nil
	}

	// can-reach
	if strings.HasPrefix(*method, AutodetectionMethodCanReach) {
		dest := strings.TrimPrefix(*method, AutodetectionMethodCanReach)
		return &operatorv1.NodeAddressAutodetection{CanReach: dest}, nil
	}

	// skip-interface
	if strings.HasPrefix(*method, AutodetectionMethodSkipInterface) {
		ifStr := strings.TrimPrefix(*method, AutodetectionMethodSkipInterface)
		return &operatorv1.NodeAddressAutodetection{SkipInterface: ifStr}, nil
	}

	// cidr=
	if strings.HasPrefix(*method, AutodetectionMethodCIDR) {
		ifStr := strings.TrimPrefix(*method, AutodetectionMethodCIDR)
		cidrs := strings.Split(ifStr, ",")
		return &operatorv1.NodeAddressAutodetection{CIDRS: cidrs}, nil
	}

	// kubernetes-internal-ip
	if *method == "" || *method == AutodetectionMethodNodeIP {
		k := operatorv1.NodeInternalIP
		return &operatorv1.NodeAddressAutodetection{Kubernetes: &k}, nil
	}

	return nil, fmt.Errorf("invalid IP autodetection method")
}

// handleIPAutoDetectionMethod updates the installation with the IP autodetection
// method if defined.
func handleIPAutoDetectionMethod(c *components, install *operatorv1.Installation) error {
	method, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "IP_AUTODETECTION_METHOD")
	if err != nil {
		return err
	}
	if method == nil {
		return nil
	}
	addrMethod, err := getAutoDetectionMethod(method)
	if err != nil {
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("IP_AUTODETECTION_METHOD=%s is not supported", *method),
			component: ComponentCalicoNode,
			fix:       "remove the IP_AUTODETECTION_METHOD env var or set it to 'first-found', 'can-reach=*', 'interface=*', 'skip-interface=*', 'cidr=*', or 'kubernetes-internal-ip'",
		}
	}
	install.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = addrMethod
	return nil
}

// handleIPv6AutoDetectionMethod updates the installation with the IPv6 autodetection
// method if defined.
func handleIPv6AutoDetectionMethod(c *components, install *operatorv1.Installation) error {
	method, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "IP6_AUTODETECTION_METHOD")
	if err != nil {
		return err
	}
	if method == nil {
		return nil
	}
	addrMethod, err := getAutoDetectionMethod(method)
	if err != nil {
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("IP6_AUTODETECTION_METHOD=%s is not supported", *method),
			component: ComponentCalicoNode,
			fix:       "remove the IP6_AUTODETECTION_METHOD env var or set it to 'first-found', 'can-reach=*', 'interface=*', 'skip-interface=*', 'cidr=*', or 'kubernetes-internal-ip'",
		}
	}
	install.Spec.CalicoNetwork.NodeAddressAutodetectionV6 = addrMethod
	return nil
}

func getCNIPlugin(c *components) (operatorv1.CNIPluginType, error) {
	prefix, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "FELIX_INTERFACEPREFIX")
	if err != nil {
		return "", err
	}

	if prefix == nil {
		return operatorv1.PluginCalico, nil
	}
	switch *prefix {
	case "eni":
		return operatorv1.PluginAmazonVPC, nil
	case "azv":
		return operatorv1.PluginAzureVNET, nil
	case "gke":
		return operatorv1.PluginGKE, nil
	case "cali":
		return operatorv1.PluginCalico, nil
	default:
		return "", ErrIncompatibleCluster{
			err:       fmt.Sprintf("unexpected FELIX_INTERFACEPREFIX value: '%s'. Only 'eni, azv, gke, cali' are supported.", *prefix),
			component: ComponentCalicoNode,
		}
	}
}
