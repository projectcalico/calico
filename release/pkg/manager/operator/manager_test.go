// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package operator

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// envRecorder is a command.CommandRunner that records the environment each
// command was given, so a test can assert what reached make.
type envRecorder struct {
	envs [][]string
}

func (e *envRecorder) Run(_ string, _ []string, env []string) (string, error) {
	e.envs = append(e.envs, env)
	return "", nil
}

func (e *envRecorder) RunNoCapture(_ string, _ []string, env []string) error {
	e.envs = append(e.envs, env)
	return nil
}

func (e *envRecorder) RunInDir(_, _ string, _ []string, env []string) (string, error) {
	e.envs = append(e.envs, env)
	return "", nil
}

func (e *envRecorder) RunInDirNoCapture(_, _ string, _ []string, env []string) error {
	e.envs = append(e.envs, env)
	return nil
}

func (e *envRecorder) RunInDirToFile(_, _ string, _ []string, env []string, _ string) (string, error) {
	e.envs = append(e.envs, env)
	return "", nil
}

func TestOperatorDirIsInTree(t *testing.T) {
	m := NewManager(WithCalicoDirectory("/some/calico"))
	require.Equal(t, "/some/calico/operator", m.dir)
}

// A publish without CONFIRM echoes its pushes and exits 0, so the release passes
// having published nothing.
func TestPublishLatchesThePush(t *testing.T) {
	for _, tc := range []struct {
		name    string
		opts    []Option
		wantEnv string
		notEnv  string
	}{
		{
			name:    "confirms by default",
			wantEnv: "CONFIRM=true",
			notEnv:  "DRYRUN=true",
		},
		{
			name:    "dry run",
			opts:    []Option{IsDryRun()},
			wantEnv: "DRYRUN=true",
			notEnv:  "CONFIRM=true",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &envRecorder{}
			opts := append([]Option{
				WithCalicoDirectory("/some/calico"),
				WithVersion("v3.34.0-test"),
			}, tc.opts...)
			m := NewManager(opts...)
			m.runner = r

			require.NoError(t, m.Publish())
			require.Len(t, r.envs, 1)
			require.True(t, slices.Contains(r.envs[0], tc.wantEnv), "expected %s in publish env", tc.wantEnv)
			require.False(t, slices.Contains(r.envs[0], tc.notEnv), "did not expect %s in publish env", tc.notEnv)
		})
	}
}

func TestProductRegistryParts(t *testing.T) {
	for _, tc := range []struct {
		registry     string
		expRegistry  string
		expNamespace string
		shouldErr    bool
	}{
		{
			registry:     "my-registry/my-namespace",
			expRegistry:  "my-registry/",
			expNamespace: "my-namespace/",
		},
		{
			registry:  "my-registry",
			shouldErr: true,
		},
		{
			registry:     "my-registry/extra/my-namespace",
			expRegistry:  "my-registry/extra/",
			expNamespace: "my-namespace/",
		},
		{
			registry:     "my-registry/extra/more/my-namespace",
			expRegistry:  "my-registry/extra/more/",
			expNamespace: "my-namespace/",
		},
		{
			registry:     "my-registry//extra/more/my-namespace",
			expRegistry:  "my-registry/extra/more/",
			expNamespace: "my-namespace/",
		},
		{
			registry:     "my-registry//extra/more/my-namespace/",
			expRegistry:  "my-registry/extra/more/",
			expNamespace: "my-namespace/",
		},
	} {
		t.Run(tc.registry, func(t *testing.T) {
			m := &OperatorManager{
				productRegistry: tc.registry,
			}
			registry, namespace, err := m.productRegistryParts()
			if tc.shouldErr {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if registry != tc.expRegistry {
				t.Errorf("expected registry %s but got %s", tc.expRegistry, registry)
			}
			if namespace != tc.expNamespace {
				t.Errorf("expected namespace %s but got %s", tc.expNamespace, namespace)
			}
		})
	}
}
