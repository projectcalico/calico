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

package checker

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
)

func TestRequestPathCredentialsOmitted(t *testing.T) {
	var output bytes.Buffer
	logger := log.StandardLogger()
	oldOutput, oldLevel := logger.Out, logger.GetLevel()
	logger.SetOutput(&output)
	logger.SetLevel(log.DebugLevel)
	t.Cleanup(func() { logger.SetOutput(oldOutput); logger.SetLevel(oldLevel) })
	paths := []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/valid"}}}
	for _, path := range []string{"invalid?token=test-secret", "/%zz?token=test-secret", "/valid?token=test-secret"} {
		func() {
			defer func() {
				if p := recover(); p != nil && strings.Contains(fmt.Sprint(p), "test-secret") {
					t.Error("panic contains request credential")
				}
			}()
			matchHTTPPaths(paths, &path)
		}()
	}
	if strings.Contains(output.String(), "test-secret") {
		t.Fatal("log contains request credential")
	}
}
