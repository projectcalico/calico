// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package config

import (
	"bytes"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestEndpointCredentialsOmittedFromLogsAndErrors(t *testing.T) {
	var output bytes.Buffer
	logger := log.StandardLogger()
	oldOutput, oldLevel := logger.Out, logger.GetLevel()
	logger.SetOutput(&output)
	logger.SetLevel(log.DebugLevel)
	t.Cleanup(func() { logger.SetOutput(oldOutput); logger.SetLevel(oldLevel) })
	p := EndpointListParam{Metadata: Metadata{Name: "EtcdEndpoints"}}
	for _, endpoint := range []string{"https://test-user:test-password@example.com?token=test-token", "https://test-user:test-password@example.com/%zz"} {
		_, err := p.Parse(endpoint)
		if err == nil {
			t.Fatal("credential-bearing endpoint accepted")
		}
		got := output.String() + err.Error()
		for _, secret := range []string{"test-user", "test-password", "test-token"} {
			if strings.Contains(got, secret) {
				t.Fatal("endpoint diagnostic contains credential")
			}
		}
	}
	cfg := New()
	_, _ = cfg.UpdateFrom(map[string]string{"EtcdEndpoints": "https://test-user:test-password@example.com?token=test-token", "UnknownCredential": "test-token"}, EnvironmentVariable)
	for _, secret := range []string{"test-user", "test-password", "test-token"} {
		if strings.Contains(output.String(), secret) {
			t.Fatal("config log contains credential")
		}
	}
}
