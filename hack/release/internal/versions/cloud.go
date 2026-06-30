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

// These cloud-specific config keys are always compiled in; they are only consumed by the release
// tool's cloud path (VARIANT=cloud), so they have no effect on the regular Calico / Calico
// Enterprise release flow.

package versions

const (

	// Cloud-specific component configs
	CloudRegistryConfigKey           = "CloudRegistry"
	CloudComponentImageConfigRelPath = "pkg/components/cloud_images.go"
)

func init() {
	// Register cloud-specific component image config keys.
	componentImageConfigMap[CloudRegistryConfigKey] = "Cloud Registry"
}
