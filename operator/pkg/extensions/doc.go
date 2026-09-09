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

// Package extensions is the seam other product variants (today just Calico
// Enterprise) use to layer variant-specific behavior onto the core operator's
// render output, so core code never branches on variant.
//
// Extensions holds one extension per controller a variant extends. Each is an
// interface the variant implements, covering two phases.
//
// ExtendInputs is the controller phase. It has cluster access via controller.Inputs
// and does the side-effecting work a render hook can't: rejecting unsupported
// config, creating certificates, extending the trusted bundle.
//
// The Modify methods are the render phase: pure hooks handed the component and the
// same typed config the core operator rendered it from, returning a component whose
// objects the variant has adjusted. Decorate does the wrapping.
//
// A variant builds the whole set in one place at startup - see pkg/enterprise.
package extensions
