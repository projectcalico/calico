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
	tests := []struct {
		name        string
		envValue    string
		expected    uint16
		expectError bool
	}{
		{
			name:        "default to TLS 1.2 when not set",
			envValue:    "",
			expected:    0x0303,
			expectError: false,
		},
		{
			name:        "explicit TLS 1.2",
			envValue:    "1.2",
			expected:    0x0303,
			expectError: false,
		},
		{
			name:        "TLS 1.3",
			envValue:    "1.3",
			expected:    0x0304,
			expectError: false,
		},
		{
			name:        "invalid version",
			envValue:    "1.0",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := calicotls.ParseTLSVersion(tt.envValue)
			if tt.expectError {
				if err == nil {
					t.Fatalf("Expected error for value %v, but got none", tt.envValue)
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Fatalf("Expected %v, got %v", tt.expected, result)
				}
			}
		})
	}
}
