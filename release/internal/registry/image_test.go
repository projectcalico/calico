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
	"io"
	"net/http"
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
			name: "non-transport error",
			err:  errors.New("dial tcp: connection refused"),
			want: false,
		},
		{
			name: "wrapped non-transport error",
			err:  fmt.Errorf("probe: %w", io.ErrUnexpectedEOF),
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := imageNotFound(tc.err); got != tc.want {
				t.Errorf("imageNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
