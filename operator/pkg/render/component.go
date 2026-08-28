// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
)

type Component interface {
	// ResolveImages should call components.GetReference for all images that the Component
	// needs, passing 'is' to the GetReference call and if there are any errors those
	// are returned. It is valid to pass nil for 'is' as GetReference accepts the value.
	// ResolveImages must be called before Objects is called for the component.
	ResolveImages(is *operatorv1.ImageSet) error

	// Objects returns the lists of objects in this component that should be created and/or deleted during
	// rendering.
	Objects() (objsToCreate, objsToDelete []client.Object)

	// Ready returns true if the component is ready to be created.
	Ready() bool

	// SupportedOSTypes returns operating systems that is supported of the components returned by the Objects() function.
	// The "componentHandler" converts the returned OSTypes to a node selectors for the "kubernetes.io/os" label on client.Objects
	// that create pods. Return OSTypeAny means that no node selector should be set for the "kubernetes.io/os" label.
	SupportedOSType() rmeta.OSType
}

// A component that exposes an extension point hands a variant the config it rendered
// from. The accessor names differ per component, so an unrelated one can't match.
type (
	NodeComponent interface {
		Component
		NodeConfig() *NodeConfiguration
	}

	TyphaComponent interface {
		Component
		TyphaConfig() *TyphaConfiguration
	}

	WindowsComponent interface {
		Component
		WindowsConfig() *WindowsConfiguration
	}

	GuardianComponent interface {
		Component
		GuardianConfig() *GuardianConfiguration
	}

	GuardianPolicyComponent interface {
		Component
		GuardianPolicyConfig() *GuardianConfiguration
	}

	APIServerComponent interface {
		Component
		APIServerConfig() *APIServerConfiguration
	}

	APIServerPolicyComponent interface {
		Component
		APIServerPolicyConfig() *APIServerConfiguration
	}
)

// Component names, which key the image overrides a variant resolves through.
const (
	ComponentNameNode = "node"

	// ComponentNameCNIPlugins keys the upstream CNI plugins image. The node
	// component renders the cni-plugins init container, so the image resolves
	// through its own override key.
	ComponentNameCNIPlugins = "cni-plugins"

	// The two windows images get their own keys, since one component renders both.
	ComponentNameWindowsNodeImg = "windows-node-image"
	ComponentNameWindowsCNIImg  = "windows-cni-image"

	ComponentNameKubeControllers = "kube-controllers"
)
