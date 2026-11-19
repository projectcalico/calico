// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package capability

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2/reporters"
)

// caseName is the JUnit case the check reports as, so Lens shows one stable
// test per lane whatever the check found.
const caseName = "capability check"

// WriteJUnit writes the result as a one-case JUnit report. The case carries an
// [Undeclared:<Capability>] tag per undeclared capability, which Lens turns
// into a case_Undeclared field. It fails when the lane is missing a declared
// capability, so the lane goes red as one visible failure.
func WriteJUnit(path string, r *Result, took time.Duration) error {
	testCase := reporters.JUnitTestCase{
		Name:      caseName + undeclaredTags(r),
		Classname: caseName,
		Status:    "passed",
		Time:      took.Seconds(),
		SystemOut: r.Summary(),
	}
	failures := 0
	if r.Failed() {
		failures = 1
		testCase.Status = "failed"
		testCase.Failure = &reporters.JUnitFailure{
			Message:     failureMessage(r),
			Type:        "failed",
			Description: r.Summary(),
		}
	}

	report := reporters.JUnitTestSuites{
		Tests:    1,
		Failures: failures,
		Time:     took.Seconds(),
		TestSuites: []reporters.JUnitTestSuite{{
			Name:      caseName,
			Tests:     1,
			Failures:  failures,
			Time:      took.Seconds(),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			TestCases: []reporters.JUnitTestCase{testCase},
		}},
	}

	out, err := xml.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal capability report: %w", err)
	}
	if err := os.WriteFile(path, append([]byte(xml.Header), out...), 0o644); err != nil {
		return fmt.Errorf("write capability report: %w", err)
	}
	return nil
}

// failureMessage is the one line Lens shows for a failed check.
func failureMessage(r *Result) string {
	if r.SetupErr != nil {
		return "capability check could not run: " + r.SetupErr.Error()
	}
	missing := make([]string, len(r.Missing))
	for i, m := range r.Missing {
		missing[i] = string(m.Capability)
	}
	return "lane declares capabilities the cluster lacks: " + strings.Join(missing, ", ")
}

// undeclaredTags renders the undeclared capabilities in the [Key:Value] form
// the Lens uploader maps to case fields.
func undeclaredTags(r *Result) string {
	var b strings.Builder
	for _, c := range r.Undeclared {
		fmt.Fprintf(&b, " [Undeclared:%s]", c)
	}
	return b.String()
}
