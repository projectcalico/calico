// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package convert

import operatorv1 "github.com/tigera/operator/api/v1"

// handlers are grouped by feature or product and check various
// fields on Calico components to construct a Installation resource that
// represents the currently installed resources.
// Handlers will do any combination of the following:
// - mark incompatible clusters by returning a IncompatibleClusterError
// - carry user config forward by setting the Installation resource according to the installed config
// - mark variables as 'checked' so that the final env var catch-all doesn't throw an 'unexpected env var' error
type handler func(*components, *operatorv1.Installation) error

var handlers = []handler{
	checkTypha,
	handleAddonManager,
	handleNetwork,
	handleCore,
	handleAnnotations,
	handleNodeSelectors,
	handleFelixNodeMetrics,
	handleTyphaMetrics,
	handleCalicoCNI,
	handleNonCalicoCNI,
	handleMTU,
	handleIPPools,
	handleBPF,
	handleNftables,
}
