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
	"strings"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func copyK8sServicesEPConfigMap(c *components) error {
	// Extract end point host, port from configmap in kube-system namespace
	cmName := render.K8sSvcEndpointConfigMapName
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      cmName,
		Namespace: "kube-system",
	}
	if err := c.client.Get(ctx, cmNamespacedName, cm); err != nil {
		return fmt.Errorf("failed read to configMap %q: %s", cmName, err)
	}
	host := cm.Data["KUBERNETES_SERVICE_HOST"]
	port := cm.Data["KUBERNETES_SERVICE_PORT"]

	// Create the config map in tigera-operator namespace
	cmNamespacedName.Namespace = common.OperatorNamespace()
	err := c.client.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: common.OperatorNamespace(),
		},
		Data: map[string]string{
			"KUBERNETES_SERVICE_HOST": host,
			"KUBERNETES_SERVICE_PORT": port,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create configmap %q in tigera-operator ns %s", cmName, err)
	}
	return nil
}

// handleBPF is a migration handler which ensures BPF configuration is carried forward.
func handleBPF(c *components, install *operatorv1.Installation) error {
	felixConfiguration := &v3.FelixConfiguration{}
	bpf := operatorv1.LinuxDataplaneBPF
	err := c.client.Get(ctx, types.NamespacedName{Name: "default"}, felixConfiguration)
	if err != nil {
		return fmt.Errorf("error reading felixconfiguration %w", err)
	}

	bpfEnabled, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "FELIX_BPFENABLED")
	if err != nil {
		return fmt.Errorf("error reading FELIX_BPFENABLED env var %w", err)
	}

	if felixConfiguration.Spec.BPFEnabled != nil && *felixConfiguration.Spec.BPFEnabled ||
		bpfEnabled != nil && strings.ToLower(*bpfEnabled) == "true" {

		err := copyK8sServicesEPConfigMap(c)
		if err != nil {
			return err
		}
		if install.Spec.CalicoNetwork == nil {
			install.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
		}

		// Make sure dataplane mode isn't already set by another handler.
		// If we hit this, it means that either there was conflicting configuration in the
		// manifest, or that a dataplane combination exists that is not supported by the operator.
		if install.Spec.CalicoNetwork.LinuxDataplane != nil {
			return fmt.Errorf("cannot enable bpf, already set to %s", *install.Spec.CalicoNetwork.LinuxDataplane)
		}

		install.Spec.CalicoNetwork.LinuxDataplane = &bpf
		install.Spec.CalicoNetwork.HostPorts = nil
	}
	return nil
}
