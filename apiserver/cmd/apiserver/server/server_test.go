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
