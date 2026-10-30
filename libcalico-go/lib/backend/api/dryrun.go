// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package api

import "context"

type dryRunKey struct{}

// WithDryRun returns a context that asks the backend to validate a Create, Update
// or UpdateStatus the same way as a real write, without persisting it. A backend
// that can't do that must refuse the write rather than persist it.
func WithDryRun(ctx context.Context) context.Context {
	return context.WithValue(ctx, dryRunKey{}, true)
}

// IsDryRun reports whether ctx came from WithDryRun.
func IsDryRun(ctx context.Context) bool {
	dryRun, _ := ctx.Value(dryRunKey{}).(bool)
	return dryRun
}
