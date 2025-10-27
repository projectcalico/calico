// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
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

package proxy

import (
	"net"
	"testing"
)

// The main suite of tests in kube-proxy_test.go use a real proxy, making it
// hard to check for the start of day race between the CheckXXX methods and the
// initial sync.  These tests hack in a mock proxy so we can test the low
// level logic

func TestConntrackFrontendHasBackendChecksHasSynced(t *testing.T) {
	m := &mockProxy{}
	kp := KubeProxy{
		proxy: m,
	}

	if !kp.ConntrackFrontendHasBackend(nil, 0, nil, 0, 0) {
		t.Errorf("ConntrackFrontendHasBackend should return true when proxy has not synced")
	}
	m.synced = true
	if kp.ConntrackFrontendHasBackend(nil, 0, nil, 0, 0) {
		t.Errorf("ConntrackFrontendHasBackend should return false when proxy has synced")
	}
}

func TestConntrackDestIsServiceChecksHasSynced(t *testing.T) {
	m := &mockProxy{}
	kp := KubeProxy{
		proxy: m,
	}

	if kp.ConntrackDestIsService(nil, 0, 0) {
		t.Errorf("ConntrackDestIsService should return false when proxy has not synced")
	}
	m.synced = true
	if !kp.ConntrackDestIsService(nil, 0, 0) {
		t.Errorf("ConntrackDestIsService should return true when proxy has synced")
	}
}

type mockProxy struct {
	ProxyFrontend
	synced bool
}

func (p *mockProxy) HasSynced() bool {
	return p.synced
}

func (p *mockProxy) ConntrackFrontendHasBackend(ip net.IP, port uint16, backendIP net.IP,
	backendPort uint16, proto uint8) bool {
	return false
}

func (p *mockProxy) ConntrackDestIsService(ip net.IP, port uint16, proto uint8) bool {
	return true
}
