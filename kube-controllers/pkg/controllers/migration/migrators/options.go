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

package migrators

import (
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// Option configures a ResourceMigrator.
type Option func(*config)

type config struct {
	convert  any // func(*model.KVPair) (*T, error) — stored as any, applied in New
	listOpts model.ListInterface
}

// WithConvert provides a custom conversion function. Use this for resource
// types that need special handling (e.g., policy name migration, IPAM types).
func WithConvert[T any](fn func(*model.KVPair) (*T, error)) Option {
	return func(c *config) {
		c.convert = fn
	}
}

// WithListOptions provides custom list options for the v1 backend client.
// Use this for types that can't be listed via ResourceListOptions (e.g., IPAM).
func WithListOptions(opts model.ListInterface) Option {
	return func(c *config) {
		c.listOpts = opts
	}
}
