// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
//
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

package node

import (
	"context"
)

// CleanupBlocksForRemovedNodes is a no-op implementation for the fake IPAM client
func (c *fakeIPAMClient) CleanupBlocksForRemovedNodes(ctx context.Context, activeNodes []string, force bool) (int, error) {
	// This is a simple implementation for testing purposes
	// Just return 0 (no blocks cleaned up) and nil (no error)
	return 0, nil
}
