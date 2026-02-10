// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package server

import (
	"crypto/tls"
	"os"
	"testing"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
)

func TestCATypeFlagParsing(t *testing.T) {
	testCases := []struct {
		args                                        []string
		expectedmanagementClusterCAType             string
		expectedEnableValidatingAdmissionController bool
	}{
		{[]string{}, "", true},
		{[]string{"--enable-validating-admission-policy=true"}, "", true},
		{[]string{"--enable-validating-admission-policy=false"}, "", false},
	}

	for _, testCase := range testCases {
		cmd, opts, err := NewCommandStartCalicoServer(os.Stdout)
		if err != nil {
			t.Fatalf("Failed to create the server command: %v", err)
		}

		err = cmd.ParseFlags(testCase.args)
		if err != nil {
			t.Fatalf("Failed to parse flags from the server command: %v", err)
		}

		parsedEnableValidatingAdmissionController, err := cmd.Flags().GetBool("enable-validating-admission-policy")
		if err != nil {
			t.Fatalf("Failed to get enable-validating-admission-policy flag from the server command: %v", err)
		}

		if parsedEnableValidatingAdmissionController != testCase.expectedEnableValidatingAdmissionController || opts.EnableValidatingAdmissionPolicy != testCase.expectedEnableValidatingAdmissionController {
			t.Fatalf(
				"Parsed value %v for enable-validating-admission-policy flag, expected %v for args %v",
				parsedEnableValidatingAdmissionController,
				testCase.expectedEnableValidatingAdmissionController,
				testCase.args,
			)
		}
	}
}

func TestTLSVersionEnvironmentVariable(t *testing.T) {
	testCases := []struct {
		name               string
		tlsMinVersionEnv   string
		expectedMinVersion uint16
		expectError        bool
	}{
		{
			name:               "default TLS 1.2 when not set",
			tlsMinVersionEnv:   "",
			expectedMinVersion: tls.VersionTLS12,
			expectError:        false,
		},
		{
			name:               "TLS 1.3 configured",
			tlsMinVersionEnv:   "1.3",
			expectedMinVersion: tls.VersionTLS13,
			expectError:        false,
		},
		{
			name:               "TLS 1.2 explicitly configured",
			tlsMinVersionEnv:   "1.2",
			expectedMinVersion: tls.VersionTLS12,
			expectError:        false,
		},
		{
			name:               "invalid TLS version",
			tlsMinVersionEnv:   "1.1",
			expectedMinVersion: 0,
			expectError:        true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.tlsMinVersionEnv != "" {
				os.Setenv("TLS_MIN_VERSION", testCase.tlsMinVersionEnv)
				defer os.Unsetenv("TLS_MIN_VERSION")
			} else {
				os.Unsetenv("TLS_MIN_VERSION")
			}

			minVersion, err := calicotls.ParseTLSVersion(os.Getenv("TLS_MIN_VERSION"))

			if testCase.expectError {
				if err == nil {
					t.Fatalf("Expected error for TLS_MIN_VERSION=%s, but got none", testCase.tlsMinVersionEnv)
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error for TLS_MIN_VERSION=%s: %v", testCase.tlsMinVersionEnv, err)
				}

				if minVersion != testCase.expectedMinVersion {
					t.Fatalf(
						"Expected MinTLSVersion to be %v, got %v for TLS_MIN_VERSION=%s",
						testCase.expectedMinVersion,
						minVersion,
						testCase.tlsMinVersionEnv,
					)
				}
			}
		})
	}
}
