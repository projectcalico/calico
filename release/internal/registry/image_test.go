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

package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// registryServer serves a minimal registry API, answering manifest requests
// with the given status.
func registryServer(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if status == http.StatusOK {
			sum := sha256.Sum256([]byte(body))
			w.Header().Set("Docker-Content-Digest", "sha256:"+hex.EncodeToString(sum[:]))
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// A published tag reports its digest.
func TestResolveDigestPresent(t *testing.T) {
	host := registryServer(t, http.StatusOK, `{"schemaVersion":2}`)

	digest, exists, err := ResolveDigest(host + "/calico/node:v3.30.0")
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	if !exists {
		t.Fatal("a published tag reported as absent")
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest = %q, want a sha256 digest", digest)
	}
}

// An absent tag is not an error: the caller skips it rather than aborting.
func TestResolveDigestAbsent(t *testing.T) {
	host := registryServer(t, http.StatusNotFound, "")

	digest, exists, err := ResolveDigest(host + "/calico/node:v3.30.0")
	if err != nil {
		t.Fatalf("a missing tag must not be an error, got %v", err)
	}
	if exists {
		t.Error("a missing tag reported as present")
	}
	if digest != "" {
		t.Errorf("digest = %q, want empty", digest)
	}
}

// A registry that cannot answer must not be read as "not published".
func TestResolveDigestFailuresAreNotAbsence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"unauthorized", http.StatusUnauthorized},
		{"forbidden", http.StatusForbidden},
		{"server error", http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := registryServer(t, tc.status, "")

			_, exists, err := ResolveDigest(host + "/calico/node:v3.30.0")
			if err == nil {
				t.Fatalf("status %d must report an error", tc.status)
			}
			if exists {
				t.Errorf("status %d reported the tag as present", tc.status)
			}
		})
	}
}

func TestResolveDigestRejectsBadReference(t *testing.T) {
	if _, _, err := ResolveDigest("not a reference"); err == nil {
		t.Fatal("expected an error for an unparseable reference")
	}
}

// CheckImage separates absence from failure the same way.
func TestCheckImageDistinguishesAbsentFromFailure(t *testing.T) {
	absent := registryServer(t, http.StatusNotFound, "")
	exists, err := CheckImage(absent + "/calico/node:v3.30.0")
	if err != nil || exists {
		t.Errorf("absent image: got (%v, %v), want (false, nil)", exists, err)
	}

	broken := registryServer(t, http.StatusInternalServerError, "")
	if _, err := CheckImage(broken + "/calico/node:v3.30.0"); err == nil {
		t.Error("an unreachable registry must report an error")
	}
}
