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

package extensions

// Set is the extensions a variant supplies, one per extended controller. What it
// leaves unset runs the core behavior.
type Set struct {
	Installation      InstallationExtension
	Windows           WindowsExtension
	APIServer         APIServerExtension
	ClusterConnection ClusterConnectionExtension
}

// Extensions is the variant behavior the operator runs with. The zero value extends
// nothing, so the accessors never return nil.
type Extensions struct {
	set Set
}

// New returns the extensions the operator runs with. A variant builds this once at
// startup; see pkg/enterprise.
func New(s Set) Extensions {
	return Extensions{set: s}
}

func (e Extensions) Installation() InstallationExtension {
	if e.set.Installation == nil {
		return noopInstallation{}
	}
	return e.set.Installation
}

func (e Extensions) Windows() WindowsExtension {
	if e.set.Windows == nil {
		return noopWindows{}
	}
	return e.set.Windows
}

func (e Extensions) APIServer() APIServerExtension {
	if e.set.APIServer == nil {
		return noopAPIServer{}
	}
	return e.set.APIServer
}

func (e Extensions) ClusterConnection() ClusterConnectionExtension {
	if e.set.ClusterConnection == nil {
		return noopClusterConnection{}
	}
	return e.set.ClusterConnection
}
