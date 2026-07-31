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

package defaults

import (
	"fmt"

	cli "github.com/urfave/cli/v3"
)

// MK returns a cli.ValueSource that resolves key from the embedded
// metadata.mk. Unknown keys and load/parse failures (already logged by
// readMetadata) yield (_, false), so the surrounding chain falls through
// to the next source.
func MK(key string) cli.ValueSource {
	return &mkSource{key: key}
}

type mkSource struct{ key string }

func (s *mkSource) Lookup() (string, bool) {
	v, ok := load()[s.key]
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

func (s *mkSource) String() string   { return fmt.Sprintf("metadata.mk:%s", s.key) }
func (s *mkSource) GoString() string { return fmt.Sprintf("defaults.MK(%q)", s.key) }
