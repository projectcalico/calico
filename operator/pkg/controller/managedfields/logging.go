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

package managedfields

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("managedfields")

// logResolution records what the writer did with fields it does not simply own. Reconciles that
// only rewrite the operator's own values say nothing, so the log carries the surprises.
func logResolution(obj client.Object, manager string, deferred, removed, forced []string) {
	if len(deferred) == 0 && len(removed) == 0 && len(forced) == 0 {
		return
	}
	log.Info("Resolved shared configuration ownership",
		"kind", kindOf(obj),
		"manager", manager,
		"deferred", deferred,
		"removed", removed,
		"forced", forced,
	)
}
