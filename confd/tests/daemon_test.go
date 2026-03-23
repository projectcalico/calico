// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func TestBGPFilterDeletion(t *testing.T) {
	for _, be := range activeBackends {
		t.Run(be.name, func(t *testing.T) {
			d := startConfdDaemon(t, be)

			// Step 1: apply resources and verify output with filter active.
			cleanup := applyResources(t, be, "mock_data/calicoctl/bgpfilter/filter_deletion/input.yaml")
			d.expectOutput("bgpfilter/filter_deletion/step1")

			// Step 2: delete the BGPFilter, verify output updates.
			ctx := context.Background()
			_, err := be.calicoClient.BGPFilter().Delete(ctx, "test-filter", options.DeleteOptions{})
			require.NoError(t, err, "deleting BGPFilter test-filter")
			d.expectOutput("bgpfilter/filter_deletion/step2")

			cleanup()
		})
	}
}
