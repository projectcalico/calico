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

package main

import (
	"context"
	"slices"
	"testing"

	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/operator"
)

func TestBuildStepFlags(t *testing.T) {
	for _, tc := range []struct {
		name        string
		hashrelease bool
	}{
		{name: "a release does not offer release notes", hashrelease: false},
		{name: "a hashrelease offers release notes", hashrelease: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := slices.Contains(buildStepFlags(tc.hashrelease), cli.Flag(releaseNotesFlag))
			if got != tc.hashrelease {
				t.Errorf("--%s offered = %v, want %v", releaseNotesFlag.Name, got, tc.hashrelease)
			}
		})
	}
}

func TestOperatorSteps(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		wantOn bool
	}{
		{name: "the operator on gives both steps", wantOn: true},
		{name: "the operator off gives neither step", args: []string{"--no-operator"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var build, publish func() error
			c := &cli.Command{
				Name:  "build",
				Flags: []cli.Flag{operatorFlag()},
				Action: func(_ context.Context, c *cli.Command) error {
					build = operatorBuild(c, operator.Operator{}, false, t.TempDir())
					publish = operatorPublish(c, operator.Operator{}, false, t.TempDir(), t.TempDir())
					return nil
				},
			}
			if err := c.Run(context.Background(), append([]string{"build"}, tc.args...)); err != nil {
				t.Fatalf("run: %v", err)
			}
			if (build != nil) != tc.wantOn {
				t.Errorf("build step on = %v, want %v", build != nil, tc.wantOn)
			}
			if (publish != nil) != tc.wantOn {
				t.Errorf("publish step on = %v, want %v", publish != nil, tc.wantOn)
			}
		})
	}
}
