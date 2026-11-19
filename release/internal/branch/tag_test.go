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

package branch

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/distribution"
)

const (
	testTag   = "v3.30.0"
	localSHA  = "1111111111111111111111111111111111111111"
	remoteSHA = "2222222222222222222222222222222222222222"
)

// replyRunner answers each git command from replies; one with no reply fails
// as a missing ref.
func replyRunner(replies map[string]string) *command.Recorder {
	return &command.Recorder{Reply: func(c command.Call) (string, error) {
		out, ok := replies[callString(c)]
		if !ok {
			return "", errNoRef
		}
		return out, nil
	}}
}

func callString(c command.Call) string {
	return strings.Join(append([]string{c.Name}, c.Args...), " ")
}

func gitCalls(rec *command.Recorder) []string {
	var out []string
	for _, c := range rec.Calls() {
		out = append(out, callString(c))
	}
	return out
}

func TestCreateTag(t *testing.T) {
	resolveTag := fmt.Sprintf("git rev-parse --verify --quiet refs/tags/%s^{commit}", testTag)
	annotated := fmt.Sprintf("git tag -a -m Release %s %s", testTag, testTag)
	lightweight := "git tag --no-sign " + testTag
	moved := "git tag -f --no-sign " + testTag
	atCommit := fmt.Sprintf("git tag --no-sign %s %s", testTag, remoteSHA)

	for _, tc := range []struct {
		name        string
		tagCommit   string // empty: the tag is missing
		opts        []TagOption
		want        string // the git tag command run, if any
		errContains []string
	}{
		{name: "a missing tag is created lightweight", want: lightweight},
		{name: "a message makes an annotated tag", opts: []TagOption{TagMessage("Release " + testTag)}, want: annotated},
		{name: "a tag at HEAD is kept", tagCommit: localSHA},
		{name: "a tag at another commit fails", tagCommit: remoteSHA, errContains: []string{localSHA, remoteSHA}},
		{name: "a moved tag at another commit is retagged", tagCommit: remoteSHA, opts: []TagOption{MoveTag()}, want: moved},
		{name: "a missing tag is created at the given commit", opts: []TagOption{TagCommit(remoteSHA)}, want: atCommit},
		{name: "a tag at the given commit is kept", tagCommit: remoteSHA, opts: []TagOption{TagCommit(remoteSHA)}},
		{name: "a tag off the given commit fails", tagCommit: localSHA, opts: []TagOption{TagCommit(remoteSHA)}, errContains: []string{localSHA, remoteSHA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replies := map[string]string{"git rev-parse --verify --quiet HEAD^{commit}": localSHA, "git rev-parse --verify --quiet " + remoteSHA + "^{commit}": remoteSHA, annotated: "", lightweight: "", moved: "", atCommit: ""}
			if tc.tagCommit != "" {
				replies[resolveTag] = tc.tagCommit
			}
			rec := replyRunner(replies)
			err := CreateTag(command.Git(rec), testTag, tc.opts...)
			if len(tc.errContains) > 0 {
				if err == nil {
					t.Fatal("CreateTag() = nil, want an error")
				}
				for _, sub := range tc.errContains {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("error %q does not contain %q", err, sub)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateTag: %v", err)
			}
			var got string
			for _, c := range gitCalls(rec) {
				if strings.HasPrefix(c, "git tag ") {
					got = c
				}
			}
			if got != tc.want {
				t.Errorf("ran %q, want %q (ran %v)", got, tc.want, gitCalls(rec))
			}
		})
	}
}

func TestTagUpload(t *testing.T) {
	const (
		remote    = "origin"
		tagObjSHA = "3333333333333333333333333333333333333333"
	)
	ref := tagRefPrefix + testTag
	lsRemote := fmt.Sprintf("git ls-remote %s %s %s^{}", remote, ref, ref)
	resolveTag := fmt.Sprintf("git rev-parse --verify --quiet %s^{commit}", ref)
	push := fmt.Sprintf("git push %s %s", remote, ref)

	upload := func(o PushTagOptions, replies map[string]string) (distribution.Upload, *command.Recorder) {
		rec := replyRunner(replies)
		o.Tag, o.Remote, o.Runner = testTag, remote, rec
		return TagUpload(o), rec
	}

	for _, tc := range []struct {
		name        string
		lsRemote    string
		wantPush    bool
		errContains []string
	}{
		{name: "a tag missing on the remote is pushed", wantPush: true},
		{name: "a remote tag at the local commit is skipped", lsRemote: fmt.Sprintf("%s\t%s", localSHA, ref)},
		{
			name:        "a remote tag at another commit fails",
			lsRemote:    fmt.Sprintf("%s\t%s", remoteSHA, ref),
			errContains: []string{localSHA, remoteSHA},
		},
		{
			name:     "an annotated remote tag is compared by its commit",
			lsRemote: fmt.Sprintf("%s\t%s\n%s\t%s^{}", tagObjSHA, ref, localSHA, ref),
		},
		{
			name:        "an annotated remote tag at another commit fails",
			lsRemote:    fmt.Sprintf("%s\t%s\n%s\t%s^{}", tagObjSHA, ref, remoteSHA, ref),
			errContains: []string{localSHA, remoteSHA},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, rec := upload(PushTagOptions{}, map[string]string{lsRemote: tc.lsRemote, resolveTag: localSHA, push: ""})
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
			if got := slices.Contains(gitCalls(rec), push); got != tc.wantPush {
				t.Errorf("pushed = %v, want %v (ran %v)", got, tc.wantPush, gitCalls(rec))
			}
		})
	}

	t.Run("a failed remote query pushes nothing", func(t *testing.T) {
		u, rec := upload(PushTagOptions{}, map[string]string{push: ""})
		if err := u.Handler.Publish(context.Background(), ""); err == nil {
			t.Fatal("Publish() = nil, want an error")
		}
		if slices.Contains(gitCalls(rec), push) {
			t.Errorf("pushed after a failed remote query (ran %v)", gitCalls(rec))
		}
	})

	t.Run("a dry run previews the push", func(t *testing.T) {
		dryPush := fmt.Sprintf("git push %s --dry-run %s", remote, ref)
		u, rec := upload(PushTagOptions{DryRun: true}, map[string]string{lsRemote: "", dryPush: ""})
		if err := u.Handler.Publish(context.Background(), ""); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		if !slices.Contains(gitCalls(rec), dryPush) {
			t.Errorf("ran %v, want a previewed push", gitCalls(rec))
		}
	})

	t.Run("a missing local tag fails validation", func(t *testing.T) {
		u, _ := upload(PushTagOptions{}, nil)
		if err := u.Handler.(distribution.Validator).Validate(u); err == nil {
			t.Error("Validate() = nil, want an error")
		}
	})

	t.Run("a tag without a remote fails validation", func(t *testing.T) {
		rec := &command.Recorder{Reply: func(command.Call) (string, error) { return localSHA, nil }}
		u := TagUpload(PushTagOptions{Tag: testTag, Runner: rec})
		if err := u.Handler.(distribution.Validator).Validate(u); err == nil || !strings.Contains(err.Error(), "remote") {
			t.Errorf("Validate() = %v, want a missing-remote error", err)
		}
	})

	t.Run("passes the step name and skip through", func(t *testing.T) {
		u, _ := upload(PushTagOptions{Skip: true}, nil)
		if u.Name != PushTagStep || !u.Skip {
			t.Errorf("Name, Skip = %q, %v, want %q, true", u.Name, u.Skip, PushTagStep)
		}
	})
}
