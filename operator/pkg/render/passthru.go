// Copyright (c) 2021,2023-2024,2026 Tigera, Inc. All rights reserved.
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
	"reflect"

	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewPassthrough(objsToCreate, objsToDelete []client.Object) Component {
	return &passthroughComponent{toCreate: objsToCreate, toDelete: objsToDelete, log: log}
}

func NewDeletionPassthrough(objs ...client.Object) Component {
	return &passthroughComponent{toDelete: objs, log: log}
}

func NewCreationPassthrough(objs ...client.Object) Component {
	return &passthroughComponent{toCreate: objs, log: log}
}

func NewCreationPassthroughWithLog(l logr.Logger, objs ...client.Object) Component {
	return &passthroughComponent{toCreate: objs, log: l}
}

// passthroughComponent is an implementation of a Component that simply passes back
// the objects it was given unmodified.
type passthroughComponent struct {
	toCreate, toDelete []client.Object
	log                logr.Logger
}

// ResolveImages should call components.GetReference for all images that the Component
// needs, passing 'is' to the GetReference call and if there are any errors those
// are returned. It is valid to pass nil for 'is' as GetReference accepts the value.
// ResolveImages must be called before Objects is called for the component.
func (p *passthroughComponent) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

// Objects returns the lists of objects in this component that should be created and deleted during
// rendering.
func (p *passthroughComponent) Objects() (toCreate, toDelete []client.Object) {
	// Filter out nil objects. This makes it easier for the calling code, so we don't need to duplicate
	// this filtering logic in all the controllers that uses this component.
	for _, o := range p.toCreate {
		if o == nil {
			continue
		}
		p.log.V(1).Info("PassThrough processing object", "type", reflect.TypeOf(o), "name", o.GetName(), "namespace", o.GetNamespace())
		toCreate = append(toCreate, o)
	}

	for _, o := range p.toDelete {
		if o == nil {
			continue
		}
		p.log.V(1).Info("PassThrough processing object", "type", reflect.TypeOf(o), "name", o.GetName(), "namespace", o.GetNamespace())
		toDelete = append(toDelete, o)
	}
	return
}

// Ready returns true if the component is ready to be created.
func (p *passthroughComponent) Ready() bool {
	return true
}

// SupportedOSTypes returns operating systems that is supported of the components returned by the Objects() function.
// The "componentHandler" converts the returned OSTypes to a node selectors for the "kubernetes.io/os" label on client.Objects
// that create pods. Return OSTypeAny means that no node selector should be set for the "kubernetes.io/os" label.
func (p *passthroughComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}
