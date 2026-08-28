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

package render

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
)

func Namespaces(cfg *NamespaceConfiguration) Component {
	return &namespaceComponent{
		cfg: cfg,
	}
}

// NamespaceConfiguration contains all the config information needed to render the component.
type NamespaceConfiguration struct {
	Installation *operatorv1.InstallationSpec
	PullSecrets  []*corev1.Secret
	Terminating  bool
}

type namespaceComponent struct {
	cfg *NamespaceConfiguration
}

func (c *namespaceComponent) ResolveImages(is *operatorv1.ImageSet) error {
	// No images on a namespace
	return nil
}

func (c *namespaceComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}

func (c *namespaceComponent) Objects() ([]client.Object, []client.Object) {
	ns := []client.Object{
		CreateNamespace(common.CalicoNamespace, c.cfg.Installation.KubernetesProvider, PSSPrivileged, c.cfg.Installation.Azure),
		CreateOperatorSecretsRoleBinding(common.CalicoNamespace),
	}

	// If we're terminating, we don't want to delete the namespace right away.
	// It will be cleaned up by Kubernetes when the Installation object is finally released.
	if c.cfg.Terminating {
		ns = []client.Object{}
	}

	if len(c.cfg.PullSecrets) > 0 {
		ns = append(ns, secret.ToRuntimeObjects(secret.CopyToNamespace(common.CalicoNamespace, c.cfg.PullSecrets...)...)...)
	}

	if c.cfg.Terminating {
		return nil, ns
	}

	return ns, nil
}

func (c *namespaceComponent) Ready() bool {
	return true
}

type PodSecurityStandard string

const (
	PSSPrivileged = "privileged"
	PSSBaseline   = "baseline"
	PSSRestricted = "restricted"
)

func CreateNamespace(name string, provider operatorv1.Provider, pss PodSecurityStandard, azure *operatorv1.Azure) *corev1.Namespace {
	ns := &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"name": name,
			},
			Annotations: map[string]string{},
		},
	}

	// Add in labels for configuring pod security standards.
	// https://kubernetes.io/docs/concepts/security/pod-security-standards/
	ns.Labels["pod-security.kubernetes.io/enforce"] = string(pss)
	ns.Labels["pod-security.kubernetes.io/enforce-version"] = "latest"

	switch provider {
	case operatorv1.ProviderOpenShift:
		ns.Annotations["openshift.io/node-selector"] = ""
		ns.Annotations["security.openshift.io/scc.podSecurityLabelSync"] = "false"
		ns.Labels["openshift.io/run-level"] = "0"
	case operatorv1.ProviderAKS:
		if applyAzurePolicy(azure, pss) {
			ns.Labels["control-plane"] = "true"
		}
	}
	return ns
}

func applyAzurePolicy(azure *operatorv1.Azure, pss PodSecurityStandard) bool {
	if azure == nil || azure.PolicyMode == nil || *azure.PolicyMode == operatorv1.PolicyModeDefault {
		return PSSPrivileged == pss
	}
	return false
}
