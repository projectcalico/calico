// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package resources

import (
	"context"
)

type patchModeKey struct{}
type PatchMode string

const (
	PatchModeCNI         PatchMode = "patchModeCNI"
	PatchModeUnspecified PatchMode = "patchModeUnspecified"
)

func ContextWithPatchMode(ctx context.Context, mode PatchMode) context.Context {
	if mode == PatchModeCNI {
		return context.WithValue(ctx, patchModeKey{}, mode)
	}
	return ctx
}

func PatchModeOf(ctx context.Context) PatchMode {
	v := ctx.Value(patchModeKey{})
	if v != nil {
		return v.(PatchMode)
	}
	return PatchModeUnspecified
}
