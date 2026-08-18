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

// Package controller holds the controller-phase inputs a reconcile hands to a
// variant extension. They live here rather than in the extensions package because
// they are what a controller gathers, not part of the extension mechanism.
package controller

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render"
)

// Name identifies the controller a ControllerExtension extends, so a variant can
// register a different hook per controller.
type Name string

const (
	Installation      Name = "installation"
	Windows           Name = "windows"
	APIServer         Name = "apiserver"
	ClusterConnection Name = "clusterconnection"
)

// Inputs is what a controller hands its variant extension: the render-phase inputs
// plus the deps needed to produce artifacts. The deps live here and not on
// render.Inputs so that modifiers, which only see render.Inputs, can't do I/O.
type Inputs struct {
	RenderInputs render.Inputs

	Client             client.Client
	CertificateManager certificatemanager.CertificateManager

	// Status and ShutdownContext are set by the controllers whose extension owns a
	// background goroutine. Everywhere else they are nil.
	Status          status.StatusManager
	ShutdownContext context.Context

	// Terminating reports that the resource this controller owns is being deleted.
	Terminating bool
}
