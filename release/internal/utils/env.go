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

package utils

import "fmt"

// Environment variables the component Makefiles read. A typo in one of these is
// silent: make treats an unknown variable as empty rather than failing.
const (
	// EnvConfirm and EnvDryRun are the publish latch. Exactly one is set.
	EnvConfirm = "CONFIRM"
	EnvDryRun  = "DRYRUN"

	EnvRelease       = "RELEASE"
	EnvReleaseBranch = "RELEASE_BRANCH"
	EnvVersion       = "VERSION"
	EnvImageTag      = "IMAGETAG"
	EnvArches        = "ARCHES"

	// EnvDevRegistries is the destination when pushing and the source when
	// retagging, so its meaning depends on EnvImageOnly.
	EnvDevRegistries = "DEV_REGISTRIES"

	EnvDevTag            = "DEV_TAG"
	EnvReleaseTag        = "RELEASE_TAG"
	EnvReleaseRegistries = "RELEASE_REGISTRIES"
	EnvImageOnly         = "IMAGE_ONLY"
	EnvSkipDevImageRetag = "SKIP_DEV_IMAGE_RETAG"
)

// Env renders one NAME=value pair for a command's environment.
func Env(name string, value any) string {
	return fmt.Sprintf("%s=%v", name, value)
}

// EnvTrue renders a boolean flag the Makefiles test for presence of.
func EnvTrue(name string) string {
	return Env(name, true)
}
