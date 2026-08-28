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

package options

// Options is the Calico Enterprise controller-phase options, held by the hooks that
// need them. It lives in its own leaf package so the hooks and main can both
// reference it.
type Options struct {
	// MultiTenant reports whether the operator runs in multi-tenant mode.
	MultiTenant bool

	// Cloud reports whether this is a Calico Cloud install.
	Cloud bool

	// ManageCRDs and UseV3CRDs mirror the operator's CRD management options. The
	// installation hook watches the CRDs the variant adds.
	ManageCRDs bool
	UseV3CRDs  bool
}
