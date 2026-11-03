// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testutils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/reporters"
	"github.com/onsi/ginkgo/v2/types"
)

// RegisterJUnitReporter registers a ReportAfterSuite node that writes a JUnit
// report named filename to the report/ directory of the component containing
// the suite (e.g. felix/report/), located by walking up from the test
// binary's working directory to the repo root.  Call it before RunSpecs.
//
// Unlike ginkgo's --junit-report flag (or reporterConfig.JUnitReport), the
// generated report omits the captured log output of passing specs.  That
// output dominates report size — log-heavy suites produce reports of tens of
// MB or more — and CI's "test-results publish" parser is OOM-killed trying to
// parse them, so none of the suite results reach the CI test dashboard.
// Failing specs keep their timelines (including GinkgoWriter/logrus output).
//
// To see the full output of every spec locally, run the suite in verbose
// mode, which streams captured output to the console:
//
//	go test ./felix/calc/ -ginkgo.v -ginkgo.focus="<spec name>"
//
// or pass -ginkgo.junit-report=<path> to also write a full-detail JUnit
// report alongside the slim one.
//
// Don't combine this with reporterConfig.JUnitReport, which would write a
// second, full-fat report.
func RegisterJUnitReporter(filename string) {
	ginkgo.ReportAfterSuite("JUnit report", func(report ginkgo.Report) {
		path, err := reportPath(filename)
		if err == nil {
			err = reporters.GenerateJUnitReportWithConfig(report, path, reporters.JunitReportConfig{
				OmitTimelinesForSpecState: types.SpecStatePassed | types.SpecStateSkipped | types.SpecStatePending,
				OmitCapturedStdOutErr:     true,
			})
		}
		if err != nil {
			// Matching ginkgo's own behaviour for a failed report write:
			// warn, don't fail the suite.
			fmt.Fprintf(os.Stderr, "Failed to write JUnit report %s: %v\n", filename, err)
		}
	})
}

// reportPath resolves filename into the report/ directory of the component
// whose tests are running: go test runs each test binary with the package
// directory as its working directory, and the component is the first path
// element under the repo root (CI publishes <component>/report/*.xml).
func reportPath(filename string) (path string, err error) {
	// FindRepoRoot panics when the root can't be located; a missing report
	// must not take the suite down with it.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	root := FindRepoRoot()
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, cwd)
	if err != nil {
		return "", err
	}
	component := strings.Split(rel, string(filepath.Separator))[0]
	if component == "." {
		// Working directory is the repo root itself.
		return filepath.Join(root, "report", filename), nil
	}
	return filepath.Join(root, component, "report", filename), nil
}
