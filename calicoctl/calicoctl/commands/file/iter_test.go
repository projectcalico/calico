// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package file_test

import (
	"errors"
	"os"
	"strings"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/file"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// Check handling of file or directory enumeration
var _ = Describe("File and directory iteration", func() {
	var fname string
	var dname string
	var dfname1, dfname2, dfname3 string
	var df2name1, df2name2, df2name3 string
	var invocations []map[string]interface{}
	var testError error

	BeforeEach(func() {
		// Create a temporary file and directory with a couple of files for performing our tests
		f, err := os.CreateTemp(".", "testfile*")
		Expect(err).NotTo(HaveOccurred())
		fname = f.Name()
		err = f.Close()
		Expect(err).NotTo(HaveOccurred())

		dname, err = os.MkdirTemp(".", "testdir*")
		Expect(err).NotTo(HaveOccurred())

		f, err = os.CreateTemp(dname, "testfile*.yaml")
		Expect(err).NotTo(HaveOccurred())
		dfname1 = f.Name()
		err = f.Close()
		Expect(err).NotTo(HaveOccurred())

		f, err = os.CreateTemp(dname, "testfile*.yml")
		Expect(err).NotTo(HaveOccurred())
		dfname2 = f.Name()
		err = f.Close()
		Expect(err).NotTo(HaveOccurred())

		f, err = os.CreateTemp(dname, "testfile*.json")
		Expect(err).NotTo(HaveOccurred())
		dfname3 = f.Name()
		err = f.Close()
		Expect(err).NotTo(HaveOccurred())

		f, err = os.CreateTemp(dname, "testfile*.txt")
		Expect(err).NotTo(HaveOccurred())
		err = f.Close()
		Expect(err).NotTo(HaveOccurred())

		// Create a sub-directory.
		dname2, err := os.MkdirTemp(dname, "subdir*")
		Expect(err).NotTo(HaveOccurred())

		f, err = os.CreateTemp(dname2, "testfile*.yaml")
		Expect(err).NotTo(HaveOccurred())
		df2name1 = f.Name()
		err = f.Close()
		Expect(err).NotTo(HaveOccurred())

		f, err = os.CreateTemp(dname2, "testfile*.yml")
		Expect(err).NotTo(HaveOccurred())
		df2name2 = f.Name()
		err = f.Close()
		Expect(err).NotTo(HaveOccurred())

		f, err = os.CreateTemp(dname2, "testfile*.json")
		Expect(err).NotTo(HaveOccurred())
		df2name3 = f.Name()
		err = f.Close()
		Expect(err).NotTo(HaveOccurred())

		f, err = os.CreateTemp(dname2, "testfile*.txt")
		Expect(err).NotTo(HaveOccurred())
		err = f.Close()
		Expect(err).NotTo(HaveOccurred())

		// Reset the callback invocations and test error
		invocations = nil
		testError = nil

		// Remove leading . in path to allow for simpler comparison.
		fname = strings.TrimPrefix(fname, "./")
		dname = strings.TrimPrefix(dname, "./")
		dfname1 = strings.TrimPrefix(dfname1, "./")
		dfname2 = strings.TrimPrefix(dfname2, "./")
		dfname3 = strings.TrimPrefix(dfname3, "./")
		df2name1 = strings.TrimPrefix(df2name1, "./")
		df2name2 = strings.TrimPrefix(df2name2, "./")
		df2name3 = strings.TrimPrefix(df2name3, "./")
	})

	AfterEach(func() {
		Expect(os.Remove(fname)).ToNot(HaveOccurred())
		Expect(os.RemoveAll(dname)).ToNot(HaveOccurred())
	})

	runTest := func(filename string, recursive bool, expected []string) error {
		args := map[string]interface{}{
			"--abc": 1,
			"--def": "hello",
		}
		if filename != "" {
			args["--filename"] = filename
		}
		if recursive {
			args["--recursive"] = true
		}

		err := file.Iter(args, func(updated map[string]interface{}) error {
			invocations = append(invocations, updated)
			return testError
		})
		Expect(invocations).To(HaveLen(len(expected)))
		for i := range invocations {
			var count int
			if filename == "" {
				Expect(invocations[i]).NotTo(HaveKey("--filename"))
				count = 2
			} else {
				Expect(invocations[i]).To(HaveKey("--filename"))

				// Trim leading ./ (if any) for easier comparison.
				fn := invocations[i]["--filename"].(string)
				fn = strings.TrimPrefix(fn, "./")
				Expect(fn).To(BeElementOf(expected))
				count = 3
			}
			if recursive {
				count++
			}
			Expect(invocations[i]).To(HaveLen(count))
			Expect(invocations[i]).To(HaveKey("--abc"))
			Expect(invocations[i]["--abc"]).To(Equal(1))
			Expect(invocations[i]["--def"]).To(Equal("hello"))
		}
		return err
	}

	It("should handle no filename", func() {
		err := runTest("", false, []string{""})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle stdin", func() {
		err := runTest("-", false, []string{"-"})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle non-existent file", func() {
		err := runTest("this-file-should-not-exist", false, []string{"this-file-should-not-exist"})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle error", func() {
		testError = errors.New("test")
		err := runTest("-", false, []string{"-"})
		Expect(err).To(HaveOccurred())
	})

	It("should handle file", func() {
		err := runTest(fname, false, []string{fname})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle directory and different file extensions", func() {
		err := runTest(dname, false, []string{dfname1, dfname2, dfname3})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle directory and sub directories when running recursively", func() {
		err := runTest(dname, true, []string{dfname1, dfname2, dfname3, df2name1, df2name2, df2name3})
		Expect(err).NotTo(HaveOccurred())
	})
})
