// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
//
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
	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type SetUpConfiguration struct {
	OpenShift    bool
	Installation *operatorv1.InstallationSpec
	PullSecrets  []*corev1.Secret
	Namespace    string
	PSS          PodSecurityStandard

	CreateNamespace bool
}

func NewSetup(cfg *SetUpConfiguration) Component {
	return &SetUpComponent{cfg: cfg}
}

// SetUpComponent is an implementation of a Component that setup common resource between
// controllers
type SetUpComponent struct {
	cfg *SetUpConfiguration
}

// ResolveImages should call components.GetReference for all images that the Component
// needs, passing 'is' to the GetReference call and if there are any errors those
// are returned. It is valid to pass nil for 'is' as GetReference accepts the value.
// ResolveImages must be called before Objects is called for the component.
func (p *SetUpComponent) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

// Objects returns the lists of objects in this component that should be created and/or deleted during
// rendering.
func (p *SetUpComponent) Objects() (objsToCreate []client.Object, objsToDelete []client.Object) {
	if p.cfg.CreateNamespace {
		objsToCreate = append(objsToCreate, CreateNamespace(p.cfg.Namespace, p.cfg.Installation.KubernetesProvider, p.cfg.PSS, p.cfg.Installation.Azure))
	}

	objsToCreate = append(objsToCreate, CreateOperatorSecretsRoleBinding(p.cfg.Namespace))
	if len(p.cfg.PullSecrets) > 0 {
		objsToCreate = append(objsToCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(p.cfg.Namespace, p.cfg.PullSecrets...)...)...)
	}
	return objsToCreate, objsToDelete
}

// Ready returns true if the component is ready to be created.
func (p *SetUpComponent) Ready() bool {
	return true
}

// SupportedOSType returns operating systems that is supported of the components returned by the Objects() function.
// The "componentHandler" converts the returned OSTypes to a node selectors for the "kubernetes.io/os" label on client.Objects
// that create pods. Return OSTypeAny means that no node selector should be set for the "kubernetes.io/os" label.
func (p *SetUpComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}
