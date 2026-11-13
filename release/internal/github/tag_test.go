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

package github

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/distribution"
)

func TestTagUpload(t *testing.T) {
	const (
		tag       = "v3.30.0"
		remote    = "origin"
		localSHA  = "1111111111111111111111111111111111111111"
		remoteSHA = "2222222222222222222222222222222222222222"
		tagObjSHA = "3333333333333333333333333333333333333333"
	)
	lsRemote := fmt.Sprintf("git ls-remote --tags %s refs/tags/%s", remote, tag)
	push := fmt.Sprintf("git push %s %s", remote, tag)

	// upload answers each git command from replies; one with no reply fails.
	upload := func(o TagOptions, replies map[string]string) (distribution.Upload, *command.Recorder) {
		rec := &command.Recorder{Reply: func(c command.Call) (string, error) {
			out, ok := replies[strings.Join(append([]string{c.Name}, c.Args...), " ")]
			if !ok {
				return "", errors.New("no reply")
			}
			return out, nil
		}}
		o.Tag, o.Remote, o.Runner = tag, remote, rec
		return TagUpload(o), rec
	}
	ran := func(rec *command.Recorder) []string {
		var out []string
		for _, c := range rec.Calls() {
			out = append(out, strings.Join(append([]string{c.Name}, c.Args...), " "))
		}
		return out
	}

	for _, tc := range []struct {
		name        string
		lsRemote    string
		wantPush    bool
		errContains []string
	}{
		{name: "a tag missing on the remote is pushed", wantPush: true},
		{name: "a remote tag at the local commit is skipped", lsRemote: fmt.Sprintf("%s\trefs/tags/%s", localSHA, tag)},
		{
			name:        "a remote tag at another commit fails",
			lsRemote:    fmt.Sprintf("%s\trefs/tags/%s", remoteSHA, tag),
			errContains: []string{localSHA, remoteSHA},
		},
		{
			name:     "an annotated remote tag is compared by its commit",
			lsRemote: fmt.Sprintf("%s\trefs/tags/%s\n%s\trefs/tags/%s^{}", tagObjSHA, tag, localSHA, tag),
		},
		{
			name:        "an annotated remote tag at another commit fails",
			lsRemote:    fmt.Sprintf("%s\trefs/tags/%s\n%s\trefs/tags/%s^{}", tagObjSHA, tag, remoteSHA, tag),
			errContains: []string{localSHA, remoteSHA},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, rec := upload(TagOptions{}, map[string]string{
				lsRemote:                  tc.lsRemote,
				"git rev-list -n1 " + tag: localSHA,
				push:                      "",
			})
			err := u.Handler.Publish(context.Background(), "")
			if len(tc.errContains) > 0 {
				if err == nil {
					t.Fatal("Publish() = nil, want an error")
				}
				for _, sub := range tc.errContains {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("error %q does not contain %q", err, sub)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Publish: %v", err)
			}
			if got := slices.Contains(ran(rec), push); got != tc.wantPush {
				t.Errorf("pushed = %v, want %v (ran %v)", got, tc.wantPush, ran(rec))
			}
		})
	}

	t.Run("a dry run previews the push", func(t *testing.T) {
		u, rec := upload(TagOptions{DryRun: true}, map[string]string{lsRemote: "", push + " --dry-run": ""})
		if err := u.Handler.Publish(context.Background(), ""); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		if !slices.Contains(ran(rec), push+" --dry-run") {
			t.Errorf("ran %v, want a previewed push", ran(rec))
		}
	})

	t.Run("a missing local tag fails validation", func(t *testing.T) {
		u, _ := upload(TagOptions{}, nil)
		if err := u.Handler.(distribution.Validator).Validate(u); err == nil {
			t.Error("Validate() = nil, want an error")
		}
	})

	t.Run("passes the step name and skip through", func(t *testing.T) {
		u, _ := upload(TagOptions{Skip: true}, nil)
		if u.Name != TagStep || !u.Skip {
			t.Errorf("Name, Skip = %q, %v, want %q, true", u.Name, u.Skip, TagStep)
		}
	})
}
