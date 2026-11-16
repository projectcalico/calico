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

package env

import "fmt"

// Environment variables the component Makefiles read. A typo in one of these is
// silent: make treats an unknown variable as empty rather than failing.
const (
	Confirm = "CONFIRM"
	DryRun  = "DRYRUN"
	Debug   = "DEBUG"

	Release       = "RELEASE"
	ReleaseBranch = "RELEASE_BRANCH"
	Version       = "VERSION"
	ImageTag      = "IMAGETAG"
	Arches        = "ARCHES"

	// DevRegistries is the destination when pushing and the source when
	// retagging, so its meaning depends on ImageOnly.
	DevRegistries = "DEV_REGISTRIES"

	DevTag            = "DEV_TAG"
	ReleaseTag        = "RELEASE_TAG"
	ReleaseRegistries = "RELEASE_REGISTRIES"
	ImageOnly         = "IMAGE_ONLY"
	SkipDevImageRetag = "SKIP_DEV_IMAGE_RETAG"

	GitVersion = "GIT_VERSION"

	ProductVersion           = "PRODUCT_VERSION"
	OperatorVersion          = "OPERATOR_VERSION"
	OperatorRegistryOverride = "OPERATOR_REGISTRY_OVERRIDE"
	OperatorImageOverride    = "OPERATOR_IMAGE_OVERRIDE"
	Registry                 = "REGISTRY"

	CalicoRegistry        = "CALICO_REGISTRY"
	CalicoImagePath       = "CALICO_IMAGE_PATH"
	CalicoVersion         = "CALICO_VERSION"
	OperatorImageRegistry = "OPERATOR_IMAGE_REGISTRY"
	OperatorImagePath     = "OPERATOR_IMAGE_PATH"

	ChartDestination = "CHART_DESTINATION"
	TZ               = "TZ" // TZ fixes the timezone helm stamps index entries with.
)

func Var(name string, value any) string {
	return fmt.Sprintf("%s=%v", name, value)
}

// True renders a flag the Makefiles test for presence of.
func True(name string) string {
	return Var(name, true)
}
