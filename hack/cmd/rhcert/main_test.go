// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// Preflight writes results to <artifacts>/<platform>/, so --artifacts must be
// the image directory or results land in <image>/<platform>/<platform>/.
func TestPreflightCommandArtifactsPaths(t *testing.T) {
	job := scanJob{image: "calico", platform: "arm64", project: "p", workdir: "out/calico/arm64"}
	abs := "/abs/out/calico/arm64"

	for _, tc := range []struct {
		runtime   containerRuntime
		mount     string
		artifacts string
		logfile   string
	}{
		{runtimePodman, "/abs/out/calico:/artifacts", "/artifacts", "/artifacts/arm64/preflight.log"},
		{runtimeDocker, "/abs/out/calico:/artifacts", "/artifacts", "/artifacts/arm64/preflight.log"},
		{runtimeNative, "", "/abs/out/calico", "/abs/out/calico/arm64/preflight.log"},
	} {
		t.Run(string(tc.runtime), func(t *testing.T) {
			_, args := preflightCommand(runOpts{runtime: tc.runtime}, abs, "img", job, "preflight", false)
			if tc.mount != "" {
				if got := flagValue(args, "-v"); got != tc.mount {
					t.Errorf("-v = %q, want %q", got, tc.mount)
				}
			}
			if got := flagValue(args, "--artifacts"); got != tc.artifacts {
				t.Errorf("--artifacts = %q, want %q", got, tc.artifacts)
			}
			if got := flagValue(args, "--logfile"); got != tc.logfile {
				t.Errorf("--logfile = %q, want %q", got, tc.logfile)
			}
		})
	}
}

func TestMissingImages(t *testing.T) {
	published := map[string]map[string]bool{
		"quay.io/calico/calico:v1": {"amd64": true, "arm64": true},
	}
	var lookups int
	lookup := func(_ context.Context, ref string) (map[string]bool, error) {
		lookups++
		if p, ok := published[ref]; ok {
			return p, nil
		}
		return nil, &transport.Error{StatusCode: http.StatusNotFound}
	}
	jobs := buildJobs("", "v1", "v1")
	jobs = filterJobs(jobs, []string{"calico", "node"}, []string{"amd64", "s390x"})

	got := missingImages(context.Background(), jobs, lookup)
	want := []string{
		"quay.io/calico/calico:v1: no linux/s390x image",
		"quay.io/calico/node:v1: not found",
	}
	if !slices.Equal(got, want) {
		t.Errorf("missingImages = %q, want %q", got, want)
	}
	if lookups != 2 {
		t.Errorf("lookups = %d, want one per image ref (2)", lookups)
	}
}

func TestPublishedPlatforms(t *testing.T) {
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	var idx v1.ImageIndex = empty.Index
	for _, p := range []v1.Platform{
		{OS: "linux", Architecture: "amd64"},
		{OS: "linux", Architecture: "arm64"},
		{OS: "windows", Architecture: "s390x"},
	} {
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatal(err)
		}
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &p}})
	}
	ref, err := name.ParseReference(host + "/calico/calico:v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(ref, idx); err != nil {
		t.Fatal(err)
	}

	got, err := publishedPlatforms(context.Background(), ref.String())
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]bool{"amd64": true, "arm64": true}; !maps.Equal(got, want) {
		t.Errorf("publishedPlatforms = %v, want %v", got, want)
	}

	_, err = publishedPlatforms(context.Background(), host+"/calico/node:v1")
	if got := lookupFailureReason(err); got != "not found" {
		t.Errorf("missing image reason = %q (err %v), want %q", got, err, "not found")
	}
}

func TestLookupFailureReason(t *testing.T) {
	_, badName := name.ParseReference("Not A Ref")
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&transport.Error{StatusCode: http.StatusNotFound}, "not found"},
		{&transport.Error{StatusCode: http.StatusUnauthorized}, "access denied (check registry credentials)"},
		{&transport.Error{StatusCode: http.StatusForbidden}, "access denied (check registry credentials)"},
		{&transport.Error{StatusCode: http.StatusTooManyRequests}, "rate limited by registry"},
		{&transport.Error{StatusCode: http.StatusBadGateway}, "registry error (HTTP 502)"},
		{fmt.Errorf("wrapped: %w", &transport.Error{StatusCode: http.StatusNotFound}), "not found"},
		{badName, "invalid image reference"},
		{errors.New("dial tcp: connection refused"), "could not reach registry"},
	} {
		if got := lookupFailureReason(tc.err); got != tc.want {
			t.Errorf("lookupFailureReason(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func flagValue(args []string, flag string) string {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return ""
	}
	return args[i+1]
}
