// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package calico

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRepositoryOptionsPreserveTags(t *testing.T) {
	m := &CalicoManager{}
	registries := []string{"Quay.IO/Team", "Registry.Example:5000/Other"}
	for _, option := range []Option{WithOperatorImage("Quay.IO/Team", "Mixed/Operator", "v1.RC1"), WithImageRegistries(registries), WithHelmRegistries(registries), WithRetagImages("Quay.IO/Team", "v2.RC2")} {
		require.NoError(t, option(m))
	}
	require.Equal(t, "quay.io/team", m.operatorRegistry)
	require.Equal(t, "mixed/operator", m.operatorImage)
	require.Equal(t, "v1.RC1", m.operatorVersion)
	require.Equal(t, []string{"quay.io/team", "registry.example:5000/other"}, m.imageRegistries)
	require.Equal(t, m.imageRegistries, m.helmRegistries)
	require.Equal(t, "Quay.IO/Team", registries[0], "caller input must not change")
	require.Equal(t, "quay.io/team", m.fromRegistry)
	require.Equal(t, "v2.RC2", m.fromTag)
	f := newFakeRunner().on("docker inspect", "v1.RC1", nil)
	m.runner = f
	require.NoError(t, m.assertOperatorImageVersion())
	require.Len(t, f.calls, 1)
	require.Contains(t, f.calls[0], "quay.io/team/mixed/operator:v1.RC1")
}
