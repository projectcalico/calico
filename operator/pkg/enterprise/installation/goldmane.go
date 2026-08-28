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

package installation

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/extensions"
)

// validateNoGoldmane rejects a Goldmane CR, which Enterprise doesn't support. The
// operator never deletes it; the user does.
func validateNoGoldmane(ctx context.Context, c client.Client) error {
	goldmane, err := utils.GetIfExists[operatorv1.Goldmane](ctx, utils.DefaultInstanceKey, c)
	if err != nil {
		if meta.IsNoMatchError(err) {
			return nil
		}
		return fmt.Errorf("error reading Goldmane: %w", err)
	}
	if goldmane == nil {
		return nil
	}
	return extensions.InvalidConfigf("Goldmane is not supported by Calico Enterprise; delete the Goldmane %q resource", goldmane.Name)
}
