// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestTerminationHandler_ServeHTTP(t *testing.T) {
	th := httpTerminationHandler{make(chan bool, 1)}
	req := httptest.NewRequest("POST", "http://127.0.0.1:7777/terminate", nil)
	w := httptest.NewRecorder()
	th.ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected OK but instead got %v", resp.StatusCode)
		return
	}

	select {
	case <-th.termChan:
		return
	default:
		t.Error("termination handler did not write to channel as expected")
	}
}

func TestHttpTerminationHandler_RunHTTPServer(t *testing.T) {
	th := httpTerminationHandler{make(chan bool, 1)}
	type input struct {
		addr, port string
	}
	type output struct {
		addr, err string
	}
	tests := []struct {
		name string
		in   input
		want output
	}{
		{
			name: "no addr empty port",
			in:   input{"", ""},
			want: output{"", "error parsing provided HTTP listen port: strconv.Atoi: parsing \"\": invalid syntax"},
		},
		{
			name: "no addr zero port",
			in:   input{"", "0"},
			want: output{"", "please provide non-zero, non-negative port number for HTTP listening port"},
		},
		{
			name: "no addr valid port",
			in:   input{"", "7777"},
			want: output{":7777", ""},
		},
		{
			name: "invalid addr valid port",
			in:   input{"invalid", "7777"},
			want: output{"", "invalid HTTP bind address \"invalid\""},
		},
		{
			name: "valid addr valid port",
			in:   input{"127.0.0.1", "7777"},
			want: output{"127.0.0.1:7777", ""},
		},
	}

	for _, tc := range tests {
		gotSvr, _, gotErr := th.RunHTTPServer(tc.in.addr, tc.in.port)
		got := output{"", ""}
		if gotSvr != nil {
			got.addr = gotSvr.Addr
		}
		if gotErr != nil {
			got.err = gotErr.Error()
		}
		if !reflect.DeepEqual(tc.want, got) {
			t.Fatalf("%s: expected: %v got: %v", tc.name, tc.want, got)
		}
	}
}
