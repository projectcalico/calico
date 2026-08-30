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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

func TestImageNotFound(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "404 transport.Error",
			err:  &transport.Error{StatusCode: http.StatusNotFound},
			want: true,
		},
		{
			name: "404 wrapped in fmt.Errorf",
			err:  fmt.Errorf("checking image: %w", &transport.Error{StatusCode: http.StatusNotFound}),
			want: true,
		},
		{
			name: "401 transport.Error",
			err:  &transport.Error{StatusCode: http.StatusUnauthorized},
			want: false,
		},
		{
			name: "500 transport.Error",
			err:  &transport.Error{StatusCode: http.StatusInternalServerError},
			want: false,
		},
		{
			// Mirrors the real shape remote.Head produces when the registry's
			// WWW-Authenticate realm can't be reached (auth-dance DNS failure).
			name: "url.Error (auth-dance network failure)",
			err: &url.Error{
				Op:  "Get",
				URL: "https://invalid.example.test/?service=x",
				Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("lookup invalid.example.test: no such host")},
			},
			want: false,
		},
		{
			// Mirrors the real shape remote.Head produces when the manifest
			// response is missing required headers — plain fmt.Errorf with no
			// wrapped transport.Error in the chain.
			name: "*errors.errorString (protocol issue)",
			err:  fmt.Errorf("HEAD http://example.test/v2/foo/manifests/v1: response did not include Content-Type header"),
			want: false,
		},
		{
			// Mirrors the real shape remote.Head produces when both an HTTPS
			// and HTTP attempt fail (transport.multierrs is unexported, but
			// errors.Join uses the same Unwrap() []error pattern that
			// errors.As walks).
			name: "joined multi-error wrapping *transport.Error{404}",
			err:  errors.Join(errors.New("https attempt failed"), &transport.Error{StatusCode: http.StatusNotFound}),
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := imageNotFound(tc.err); got != tc.want {
				t.Errorf("imageNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
