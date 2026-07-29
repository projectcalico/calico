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

package components

import (
	operatorv1 "github.com/tigera/operator/api/v1"
)

// CalicoBinaryPath is the absolute path to the combined "calico" binary inside the calico/calico image.
// Components deployed from the combined image invoke this binary via Command / probe exec.
const CalicoBinaryPath = "/usr/bin/calico"

// CombinedCalicoImage returns the combined calico/calico Component for the given installation.
// The right Component is selected based on the installation variant (Calico OSS vs. Calico Enterprise).
func CombinedCalicoImage(installation *operatorv1.InstallationSpec) Component {
	if installation.Variant.IsEnterprise() {
		return ComponentTigeraCalico
	}
	return ComponentCalico
}

// CalicoCloudImage returns the tesla-compiled variant of the combined calico image. It is the same
// image repository as ComponentTigeraCalico (so ImageSet digests still resolve by that name),
// published under a tesla- tag. It carries the Calico Cloud behavior for the components that need it
// — currently only kube-controllers, the sole component with tesla-gated code. See TSLA-11580, and
// TSLA-11650 for possible removal of this cloud-image handling.
func CalicoCloudImage() Component {
	c := ComponentTigeraCalico
	c.Version = "tesla-" + c.Version
	return c
}
