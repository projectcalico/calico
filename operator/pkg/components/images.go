// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package components

// Default registries for Calico and Tigera.
const (
	CalicoRegistry = "quay.io/"
	TigeraRegistry = "gcr.io/unique-caldron-775/cnx/"

	// The operator publishes alongside the Calico component images. It keeps its own
	// name because Enterprise points TigeraRegistry at a test repo while its operator
	// image still goes to quay.
	OperatorRegistry = CalicoRegistry
)

// Default image paths for components.
const (
	CalicoImagePath   = "calico/"
	TigeraImagePath   = "tigera/"
	OperatorImagePath = CalicoImagePath
)
