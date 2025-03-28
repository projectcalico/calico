// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package slack

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestPostFailureMessage(t *testing.T) {
	RegisterTestingT(t)
	err := PostFailureMessage(nil, &FailureMessageData{
		BaseMessageData: BaseMessageData{
			ReleaseName:     "RELEASE-NAME",
			Product:         "PRODUCT",
			Stream:          "STREAM",
			ProductVersion:  "PRODUCT-VERSION",
			OperatorVersion: "OPERATOR-VERSION",
			ReleaseType:     "RELEASE-TYPE",
			CIURL:           "CI-URL",
		},
		Error: "ERROR\nERROR",
	})

	// We expect an error here because of the nil config arg.  The important thing is that it's
	// the "no configuration provided" error and not "invalid character \n in string literal".
	Expect(err).To(HaveOccurred())
	Expect(err.Error()).To(ContainSubstring("no configuration provided"))
}
