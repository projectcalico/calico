// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.

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

package tenancy

import (
	"github.com/tigera/operator/pkg/common"
)

func GetWatchNamespaces(multiTenant bool, defaultNS string) (installNS, truthNS string, watchNamespaces []string) {
	if multiTenant {
		// For multi-tenant, the manager could be installed in any number of namespaces.
		// So, we need to watch the resources we care about across all namespaces.
		watchNamespaces = []string{""}
	} else {
		installNS = defaultNS
		truthNS = common.OperatorNamespace()
		watchNamespaces = []string{installNS, truthNS}
	}
	return installNS, truthNS, watchNamespaces
}
