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

import (
	"context"
	"fmt"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func PatchBGPConfiguration(
	ctx context.Context,
	c client.Client,
	patchFn func(bgpc *v3.BGPConfiguration) (bool, error),
) (*v3.BGPConfiguration, error) {
	// Fetch any existing default BGPConfiguration object.
	bgpConfig := &v3.BGPConfiguration{}
	err := c.Get(ctx, types.NamespacedName{Name: "default"}, bgpConfig)
	if err != nil && !errors.IsNotFound(err) {
		return nil, fmt.Errorf("unable to read BGPConfiguration: %w", err)
	}

	// Create a base state for the upcoming patch operation.
	patchFrom := client.MergeFrom(bgpConfig.DeepCopy())

	if err = RestoreV3Metadata(bgpConfig); err != nil {
		return nil, err
	}

	// Apply desired changes to the BGPConfiguration.
	updated, err := patchFn(bgpConfig)
	if err != nil {
		return nil, err
	}
	if updated {
		// Apply the patch.
		if bgpConfig.ResourceVersion == "" {
			bgpConfig.Name = "default"
			if err := c.Create(ctx, bgpConfig); err != nil {
				return nil, err
			}
		} else {
			if err := c.Patch(ctx, bgpConfig, patchFrom); err != nil {
				return nil, err
			}
		}
	}

	return bgpConfig, nil
}

func GetBGPConfiguration(
	ctx context.Context,
	c client.Client,
) (*v3.BGPConfiguration, error) {
	bgpConfig := &v3.BGPConfiguration{}
	err := c.Get(ctx, types.NamespacedName{Name: "default"}, bgpConfig)
	if err != nil && !errors.IsNotFound(err) {
		return nil, fmt.Errorf("unable to read BGPConfiguration: %w", err)
	}
	return bgpConfig, nil
}
