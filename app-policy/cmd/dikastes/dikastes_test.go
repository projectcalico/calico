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
	"os"
	"syscall"
	"testing"
)

func TestTerminationHandler_ServeHTTP(t *testing.T) {
	th := terminationHandler{make(chan os.Signal, 2)}
	req := httptest.NewRequest("POST", "http://127.0.0.1:7777/terminate", nil)
	w := httptest.NewRecorder()
	th.ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected OK but instead got %v", resp.StatusCode)
		return
	}

	select {
	case rcvSig := <-th.sigChan:
		if rcvSig != syscall.SIGTERM {
			t.Errorf("expect syscall.SIGTERM but instead got %v", rcvSig)
		}
	default:
		t.Error("termination handler did not write to channel as expected")
	}
}
