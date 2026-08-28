// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
)

var toBeIgnoredAnnotationKeyRegExps []*regexp.Regexp

func init() {
	log.Info("Compiling regular expressions for annotation keys to be ignored...")
	toBeIgnoredAnnotationKeyRegExps = make([]*regexp.Regexp, 0)
	for _, annotationKey := range []string{"^kubectl\\.kubernetes\\.io"} {
		annotationKeyRegexp, err := regexp.Compile(annotationKey)
		if err != nil {
			log.Error(fmt.Errorf("%s is not a valid regular expression", annotationKey), "Error when removing expected annotations")
			continue
		}
		toBeIgnoredAnnotationKeyRegExps = append(toBeIgnoredAnnotationKeyRegExps, annotationKeyRegexp)
	}
}

func handleCore(c *components, install *operatorv1.Installation) error {
	dsType, err := c.node.getEnv(ctx, c.client, "calico-node", "DATASTORE_TYPE")
	if err != nil {
		return err
	}
	if dsType != nil && *dsType != "kubernetes" {
		return ErrIncompatibleCluster{
			err:       "only DATASTORE_TYPE=kubernetes is supported",
			component: ComponentCalicoNode,
		}
	}

	// node resource limits
	node := getContainer(c.node.Spec.Template.Spec, "calico-node")
	if len(node.Resources.Limits) > 0 || len(node.Resources.Requests) > 0 {
		if err = addResources(install, operatorv1.ComponentNameNode, &node.Resources); err != nil {
			return err
		}
	}

	// kube-controllers
	if c.kubeControllers != nil {
		kubeControllers := getContainer(c.kubeControllers.Spec.Template.Spec, containerKubeControllers)
		if kubeControllers != nil && (len(kubeControllers.Resources.Limits) > 0 || len(kubeControllers.Resources.Requests) > 0) {
			if err = addResources(install, operatorv1.ComponentNameKubeControllers, &kubeControllers.Resources); err != nil {
				return err
			}
		}
	}

	if c.typha != nil {
		// typha resource limits. typha is optional so check for nil first
		typha := getContainer(c.typha.Spec.Template.Spec, "calico-typha")
		if typha != nil && (len(typha.Resources.Limits) > 0 || len(typha.Resources.Requests) > 0) {
			if err = addResources(install, operatorv1.ComponentNameTypha, &typha.Resources); err != nil {
				return err
			}
		}
	}

	if c.kubeControllers != nil {
		value, err := getEnv(ctx, c.client, c.kubeControllers.Spec.Template.Spec, ComponentKubeControllers, containerKubeControllers, "ENABLED_CONTROLLERS")
		if err != nil {
			return err
		}

		if value != nil && strings.ToLower(*value) != "node" && strings.ToLower(*value) != "node,loadbalancer" {
			return ErrIncompatibleCluster{
				err:       fmt.Sprintf("%s=%s is not supported", "ENABLED_CONTROLLERS", *value),
				component: ComponentKubeControllers,
				fix:       fmt.Sprintf("remove the %s env var or set it to '%s' or '%s", "ENABLED_CONTROLLERS", "node", "node,loadbalancer"),
			}
		}

		if err := assertEnv(ctx, c.client, c.kubeControllers.Spec.Template.Spec, ComponentKubeControllers, containerKubeControllers, "AUTO_HOST_ENDPOINTS", "disabled"); err != nil {
			return err
		}
	}

	// node update-strategy
	install.Spec.NodeUpdateStrategy = c.node.Spec.UpdateStrategy

	// alp
	vol := getVolume(c.node.Spec.Template.Spec, "flexvol-driver-host")
	if vol != nil {
		// prefer user-defined flexvolpath over detected value
		if install.Spec.FlexVolumePath == "" {
			if vol.HostPath == nil {
				return ErrIncompatibleCluster{
					err:       "volume 'flexvol-driver-host' must be a HostPath",
					component: ComponentCalicoNode,
					fix:       "remove the 'flexvol-driver-host' volume or convert it to type hostPath",
				}
			}
			if fv := getContainer(c.node.Spec.Template.Spec, "flexvol-driver"); fv == nil {
				return ErrIncompatibleCluster{
					err:       "detected 'flexvol-driver-host' volume but no 'flexvol-driver' init container",
					component: ComponentCalicoNode,
					fix:       "remove the 'flexvol-driver-host' volume or restore the 'flexvol-driver' init container",
				}
			}
			install.Spec.FlexVolumePath = vol.HostPath.Path
		}
	} else {
		// verify that no flexvol container is set
		if fv := getContainer(c.node.Spec.Template.Spec, "flexvol-driver"); fv != nil {
			return ErrIncompatibleCluster{
				err:       "detected 'flexvol-driver' init container but no 'flexvol-driver-host' volume",
				component: ComponentCalicoNode,
				fix:       "restore the 'flexvol-driver-host' volume or remove the 'flexvol-driver' init container",
			}
		}
		install.Spec.FlexVolumePath = "None"
	}

	// Volumes for lib-modules, xtables-lock, var-run-calico, var-lib-calico, or policysync have been changed
	if err := checkNodeHostPathVolume(c.node.Spec.Template.Spec, "lib-modules", "/lib/modules"); err != nil {
		return err
	}
	// var-run-calico / var-lib-calico may use non-default hostPaths (e.g. microk8s snap paths).
	// Capture them onto Installation so the operator continues rendering the same host paths.
	if err := handleCalicoHostPathVolume(c.node.Spec.Template.Spec, "var-run-calico", "/var/run/calico", &install.Spec.CalicoRunHostPath); err != nil {
		return err
	}
	if err := handleCalicoHostPathVolume(c.node.Spec.Template.Spec, "var-lib-calico", "/var/lib/calico", &install.Spec.CalicoLibHostPath); err != nil {
		return err
	}
	if err := checkNodeHostPathVolume(c.node.Spec.Template.Spec, "xtables-lock", "/run/xtables.lock"); err != nil {
		return err
	}
	if c.cni.CalicoConfig != nil {
		if err := checkNodeHostPathVolume(c.node.Spec.Template.Spec, "cni-bin-dir", "/opt/cni/bin"); err != nil {
			return err
		}
		if err := checkNodeHostPathVolume(c.node.Spec.Template.Spec, "cni-net-dir", "/etc/cni/net.d"); err != nil {
			return err
		}
	}

	// check that nodename is a ref
	e, err := c.node.getEnvVar("calico-node", "NODENAME")
	if err != nil {
		return err
	}
	if e != nil && (e.ValueFrom == nil || e.ValueFrom.FieldRef == nil || e.ValueFrom.FieldRef.FieldPath != "spec.nodeName") {
		return ErrIncompatibleCluster{
			err:       "NODENAME on 'calico-node' container must be unset or be a FieldRef to 'spec.nodeName'",
			component: ComponentCalicoNode,
			fix:       "remove the NODENAME env var or convert it to a fieldRef with value 'spec.nodeName'",
		}
	}

	if cni := getContainer(c.node.Spec.Template.Spec, "install-cni"); cni != nil {
		e, err = c.node.getEnvVar("install-cni", "KUBERNETES_NODE_NAME")
		if err != nil {
			return err
		}
		if e != nil && (e.ValueFrom == nil || e.ValueFrom.FieldRef == nil || e.ValueFrom.FieldRef.FieldPath != "spec.nodeName") {
			return ErrIncompatibleCluster{
				err:       "KUBERNETES_NODE_NAME on 'install-cni' container must be unset or be a FieldRef to 'spec.nodeName'",
				component: ComponentCalicoNode,
				fix:       "remove the KUBERNETES_NODE_NAME env var or convert it to a fieldRef with value 'spec.nodeName'",
			}
		}

		if err := c.node.assertEnv(ctx, c.client, containerInstallCNI, "CNI_CONF_NAME", "10-calico.conflist"); err != nil {
			return err
		}
	}

	c.node.ignoreEnv("calico-node", "WAIT_FOR_DATASTORE")
	c.node.ignoreEnv("calico-node", "CLUSTER_TYPE")
	c.node.ignoreEnv("calico-node", "CALICO_DISABLE_FILE_LOGGING")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_IPIP")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_VXLAN")
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_CIDR")
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_VXLAN")
	c.node.ignoreEnv("calico-node", "FELIX_LOGSEVERITYSCREEN")
	c.node.ignoreEnv("calico-node", "FELIX_HEALTHENABLED")
	c.node.ignoreEnv("calico-node", "FELIX_USAGEREPORTINGENABLED")
	c.node.ignoreEnv("calico-node", "FELIX_TYPHAK8SSERVICENAME")
	c.node.ignoreEnv("calico-node", "FELIX_LOGSEVERITYSYS")
	c.node.ignoreEnv("upgrade-ipam", "KUBERNETES_NODE_NAME")
	c.node.ignoreEnv("upgrade-ipam", "CALICO_NETWORKING_BACKEND")
	c.node.ignoreEnv("install-cni", "SLEEP")

	return nil
}

// checkNodeHostPathVolume returns an error if a hostpath with the passed in name and path does not exist in a given podspec.
func checkNodeHostPathVolume(spec corev1.PodSpec, name, path string) error {
	v := getVolume(spec, name)
	if v == nil || v.HostPath == nil || v.HostPath.Path != path {
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("missing expected volume '%s' with hostPath '%s'", name, path),
			component: ComponentCalicoNode,
			fix:       fmt.Sprintf("add the expected volume to %s", ComponentCalicoNode),
		}
	}
	return nil
}

// handleCalicoHostPathVolume verifies that a hostPath volume with the given name exists.
// When the host path matches defaultPath, dest is left empty so the operator uses its default.
// When the host path differs (for example microk8s snap-prefixed paths that still end with the
// standard suffix), dest is set so the operator continues using the existing path after migration.
func handleCalicoHostPathVolume(spec corev1.PodSpec, name, defaultPath string, dest *string) error {
	v := getVolume(spec, name)
	if v == nil || v.HostPath == nil || v.HostPath.Path == "" {
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("missing expected volume '%s' with hostPath '%s'", name, defaultPath),
			component: ComponentCalicoNode,
			fix:       fmt.Sprintf("add the expected volume to %s", ComponentCalicoNode),
		}
	}
	path := v.HostPath.Path
	// Accept the standard path, or a path that ends with it (microk8s: /var/snap/.../var/run/calico).
	if path != defaultPath && !strings.HasSuffix(path, defaultPath) {
		return ErrIncompatibleCluster{
			err: fmt.Sprintf("volume '%s' has unsupported hostPath '%s' (expected '%s' or a path ending with it)",
				name, path, defaultPath),
			component: ComponentCalicoNode,
			fix: fmt.Sprintf("set volume '%s' hostPath to '%s' (or a path ending with '%s'), or set Installation.spec accordingly",
				name, defaultPath, defaultPath),
		}
	}
	if path != defaultPath {
		*dest = path
	}
	return nil
}

// addResources adds the rescReq resource for the specified component if none was previously set. If installation
// already had a resource for compName then they are compared and if they are different then an error is returned.
// If the Resource is added to installation or the existing one matches then nil is returned.
func addResources(install *operatorv1.Installation, compName operatorv1.ComponentName, rescReq *corev1.ResourceRequirements) error {
	if install.Spec.ComponentResources == nil {
		install.Spec.ComponentResources = []operatorv1.ComponentResource{}
	}

	var existingRR *corev1.ResourceRequirements
	// See if there is already a ComponentResource with the name
	for _, x := range install.Spec.ComponentResources {
		if x.ComponentName == compName {
			existingRR = x.ResourceRequirements
			break
		}
	}
	if existingRR == nil {
		install.Spec.ComponentResources = append(install.Spec.ComponentResources, operatorv1.ComponentResource{
			ComponentName:        compName,
			ResourceRequirements: rescReq.DeepCopy(),
		})
		return nil
	}
	if reflect.DeepEqual(existingRR, rescReq) {
		return nil
	}

	return ErrIncompatibleCluster{
		err:       "ResourcesRequirements for component did not match between Installation and migration source",
		component: string(compName),
		fix:       "remove the resource requirements / limits from your Installation resource, or remove them from the currently installed component",
	}
}

// handleAnnotations is a migration handler that ensures the components only have expected annotations.
// since Operator does not support setting custom annotations on components, these annotations
// would otherwise be dropped.
func handleAnnotations(c *components, _ *operatorv1.Installation) error {
	if a := removeExpectedAnnotations(c.node.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps); len(a) != 0 {
		return ErrIncompatibleAnnotation(a, ComponentCalicoNode)
	}

	// the following cluster-autoscaler annotation is used to indicate a particular CRD should be handled
	// the same as a daemonset by the cluster-autoscaler. This is not necessary on calico-node since it is
	// not a CRD, but a core daemonset, however some orchestrators explicitly denote it anyways. As such,
	// we ignore it.
	if a := removeExpectedAnnotations(c.node.Spec.Template.Annotations, map[string]string{
		"cluster-autoscaler.kubernetes.io/daemonset-pod": "true",
	}, toBeIgnoredAnnotationKeyRegExps); len(a) != 0 {
		return ErrIncompatibleAnnotation(a, ComponentCalicoNode+" podTemplateSpec")
	}

	if c.kubeControllers != nil {
		if a := removeExpectedAnnotations(c.kubeControllers.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps); len(a) != 0 {
			return ErrIncompatibleAnnotation(a, ComponentKubeControllers)
		}
		if a := removeExpectedAnnotations(c.kubeControllers.Spec.Template.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps); len(a) != 0 {
			return ErrIncompatibleAnnotation(a, ComponentKubeControllers+" podTemplateSpec")
		}
	}

	if c.typha != nil {
		if a := removeExpectedAnnotations(c.typha.Annotations, map[string]string{}, toBeIgnoredAnnotationKeyRegExps); len(a) != 0 {
			return ErrIncompatibleAnnotation(a, ComponentTypha)
		}
		if a := removeExpectedAnnotations(c.typha.Spec.Template.Annotations, map[string]string{
			"cluster-autoscaler.kubernetes.io/safe-to-evict": "true",
		}, toBeIgnoredAnnotationKeyRegExps); len(a) != 0 {
			return ErrIncompatibleAnnotation(a, ComponentTypha+" podTemplateSpec")
		}
	}
	return nil
}

// removeExpectedAnnotations returns the given annotations with common k8s-native annotations removed.
// this function also accepts a second argument of additional annotations to remove.
func removeExpectedAnnotations(existing, ignoreWithValue map[string]string, toBeIgnoredAnnotationKeyRegExps []*regexp.Regexp) map[string]string {
	a := existing

	for key, val := range existing {
		if key == "deprecated.daemonset.template.generation" ||
			key == "deployment.kubernetes.io/revision" ||
			key == "scheduler.alpha.kubernetes.io/critical-pod" {
			delete(a, key)
			continue
		}

		if v, ok := ignoreWithValue[key]; ok && v == val {
			delete(a, key)
			continue
		}

		for _, annotationKeyRegexp := range toBeIgnoredAnnotationKeyRegExps {
			if annotationKeyRegexp.MatchString(key) {
				delete(a, key)
				break
			}
		}
	}

	return a
}

// handleNodeSelectors is a migration handler which ensures that nodeSelectors are set as expected.
// In general, setting custom nodeSelectors and nodeAffinity for components is not supported.
// The exception to this is the calico-node nodeSelector, which is migrated into the
// ControlPlaneNodeSelector field.
func handleNodeSelectors(c *components, install *operatorv1.Installation) error {
	// check calico-node nodeSelectors
	//nolint:staticcheck // Ignore QF1001 could apply De Morgan's law
	if c.node.Spec.Template.Spec.Affinity != nil {
		if !(install.Spec.KubernetesProvider.IsAKS() && reflect.DeepEqual(c.node.Spec.Template.Spec.Affinity, &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      "type",
							Operator: corev1.NodeSelectorOpNotIn,
							Values:   []string{"virtual-kubelet"},
						}},
					}},
				},
			},
		})) && !(install.Spec.KubernetesProvider.IsEKS() && reflect.DeepEqual(c.node.Spec.Template.Spec.Affinity, &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      "eks.amazonaws.com/compute-type",
							Operator: corev1.NodeSelectorOpNotIn,
							Values:   []string{"fargate"},
						}},
					}},
				},
			},
		})) {
			return ErrIncompatibleCluster{
				err:       "node affinity not supported for calico-node daemonset",
				component: ComponentCalicoNode,
				fix:       "remove the affinity",
			}
		}
	}
	nodeSel := removeOSNodeSelectors(c.node.Spec.Template.Spec.NodeSelector)
	delete(nodeSel, "projectcalico.org/operator-node-migration")
	if len(nodeSel) > 0 {
		// raise error unless the only nodeSelector is the  calico-node migration nodeSelector
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("unsupported nodeSelector for calico-node daemonset: %v", nodeSel),
			component: ComponentCalicoNode,
			fix:       "remove the nodeSelector",
		}
	}

	// check typha nodeSelectors
	if c.typha != nil {
		if aff := c.typha.Spec.Template.Spec.Affinity; aff != nil {
			install = ensureTyphaDeploymentAffinityNonNil(install)

			if aff.PodAffinity != nil {
				install.Spec.TyphaDeployment.Spec.Template.Spec.Affinity.PodAffinity = aff.PodAffinity
			}

			if aff.PodAntiAffinity != nil {
				install.Spec.TyphaDeployment.Spec.Template.Spec.Affinity.PodAntiAffinity = aff.PodAntiAffinity
			}

			if aff.NodeAffinity != nil {
				if aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
					return ErrIncompatibleCluster{
						err:       "nodeAffinity 'RequiredDuringSchedulingIgnoredDuringExecution' not supported on Typha.",
						component: ComponentTypha,
						fix:       "remove the affinity",
					}
				}
				install.Spec.TyphaAffinity = &operatorv1.TyphaAffinity{
					NodeAffinity: &operatorv1.NodeAffinity{
						PreferredDuringSchedulingIgnoredDuringExecution: aff.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
					},
				}
			}
		}
		if nodeSel := removeOSNodeSelectors(c.typha.Spec.Template.Spec.NodeSelector); len(nodeSel) != 0 {
			return ErrIncompatibleCluster{
				err:       fmt.Sprintf("invalid nodeSelector for typha deployment: %v", nodeSel),
				component: ComponentTypha,
				fix:       "remove the nodeSelector",
			}
		}
	}

	// check kube-controllers nodeSelectors
	if c.kubeControllers != nil {
		if c.kubeControllers.Spec.Template.Spec.Affinity != nil {
			return ErrIncompatibleCluster{
				err:       "node affinity not supported for kube-controller deployment",
				component: ComponentKubeControllers,
				fix:       "remove the affinity",
			}
		}

		// kube-controllers nodeSelector is unique in that we do have an API for setting it's nodeSelectors.
		// operator rendering code will automatically set the kubernetes.io/os=linux selector, so we just
		// want to set the field to any other nodeSelectors set on it.
		if sels := removeOSNodeSelectors(c.kubeControllers.Spec.Template.Spec.NodeSelector); len(sels) != 0 {
			install.Spec.ControlPlaneNodeSelector = sels
		}
	}

	return nil
}

// removeOSNodeSelectors returns the given nodeSelectors with [beta.]kubernetes.io/os=linux nodeSelectors removed.
func removeOSNodeSelectors(existing map[string]string) map[string]string {
	nodeSel := map[string]string{}
	for key, val := range existing {
		if (key == "kubernetes.io/os" || key == "beta.kubernetes.io/os") && val == "linux" {
			continue
		}
		nodeSel[key] = val
	}

	return nodeSel
}

// handleFelixNodeMetrics is a migration handler which detects custom prometheus settings for felix and
// caries those options forward via the NodeMetricsPort field.
func handleFelixNodeMetrics(c *components, install *operatorv1.Installation) error {
	metricsEnabled, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "FELIX_PROMETHEUSMETRICSENABLED")
	if err != nil {
		return err
	}
	if metricsEnabled != nil && strings.ToLower(*metricsEnabled) == "true" {
		var _9091 int32 = 9091
		install.Spec.NodeMetricsPort = &_9091
		port, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "FELIX_PROMETHEUSMETRICSPORT")
		if err != nil {
			return err
		}
		if port != nil {
			p, err := strconv.ParseInt(*port, 10, 32)
			if err != nil || p <= 0 || p > 65535 {
				return ErrIncompatibleCluster{
					err:       fmt.Sprintf("invalid port defined in FELIX_PROMETHEUSMETRICSPORT=%s", *port),
					component: ComponentCalicoNode,
					fix:       "adjust it to be within the range of 1-65535 or remove the env var",
				}
			}
			i := int32(p)
			install.Spec.NodeMetricsPort = &i
		}
	} else {
		// Ignore the metrics port if metrics is disabled.
		c.node.ignoreEnv(containerCalicoNode, "FELIX_PROMETHEUSMETRICSPORT")
	}

	return nil
}

// ensureTyphaDeploymentAffinityNonNil ensures all the fields under TyphaDeployment are non-nil
// and won't overwrite the fields if they are already populated
func ensureTyphaDeploymentAffinityNonNil(install *operatorv1.Installation) *operatorv1.Installation {
	if install.Spec.TyphaDeployment == nil {
		install.Spec.TyphaDeployment = &operatorv1.TyphaDeployment{}
	}
	if install.Spec.TyphaDeployment.Spec == nil {
		install.Spec.TyphaDeployment.Spec = &operatorv1.TyphaDeploymentSpec{}
	}
	if install.Spec.TyphaDeployment.Spec.Template == nil {
		install.Spec.TyphaDeployment.Spec.Template = &operatorv1.TyphaDeploymentPodTemplateSpec{}
	}
	if install.Spec.TyphaDeployment.Spec.Template.Spec == nil {
		install.Spec.TyphaDeployment.Spec.Template.Spec = &operatorv1.TyphaDeploymentPodSpec{}
	}
	if install.Spec.TyphaDeployment.Spec.Template.Spec.Affinity == nil {
		install.Spec.TyphaDeployment.Spec.Template.Spec.Affinity = &corev1.Affinity{}
	}
	return install
}
