// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package status

import (
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var log = logrus.WithField("UT", "true")

// This section contains unit tests for the Status pkg.
var _ = Describe("Status pkg UTs", func() {

	It("should correctly read and write the status file", func() {
		f, err := ioutil.TempFile("", "test")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(f.Name())
		st := New(f.Name())

		st.SetReady("anykey", false, "the-reason")
		err = st.WriteStatus()
		By("writing the readiness file", func() {
			Expect(err).NotTo(HaveOccurred())
			_, err = os.Stat(f.Name())
			Expect(err).NotTo(HaveOccurred())
		})

		readSt, err := ReadStatusFile(f.Name())
		By("reading the readiness file", func() {
			Expect(err).NotTo(HaveOccurred())
		})
		By("read status file should return proper Status object", func() {
			Expect(readSt.Readiness).Should(HaveKeyWithValue("anykey", ConditionStatus{Ready: false, Reason: "the-reason"}))
		})
	})

	It("should report failed readiness with no condition statuses", func() {
		st := New("no-needed")

		Expect(st.GetReadiness()).To(BeFalse())
	})

	It("should update the status file when changes happen", func() {
		f, err := ioutil.TempFile("", "test")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(f.Name())
		st := New(f.Name())

		st.SetReady("anykey", false, "reason1")

		By("status file should return proper Status object", func() {
			readSt, err := ReadStatusFile(f.Name())
			Expect(err).NotTo(HaveOccurred())

			Expect(readSt.Readiness).Should(HaveKeyWithValue("anykey",
				ConditionStatus{Ready: false, Reason: "reason1"}))
			Expect(readSt.GetReadiness()).Should(Equal(false))
		})

		By("status file should be updated when reason changes", func() {
			st.SetReady("anykey", false, "reason2")
			readSt, err := ReadStatusFile(f.Name())
			Expect(err).NotTo(HaveOccurred())

			Expect(readSt.Readiness).Should(HaveKeyWithValue("anykey",
				ConditionStatus{Ready: false, Reason: "reason2"}))
			Expect(readSt.GetReadiness()).Should(Equal(false))
		})

		By("status file should be updated when set ready", func() {
			st.SetReady("anykey", true, "")
			readSt, err := ReadStatusFile(f.Name())
			Expect(err).NotTo(HaveOccurred())

			Expect(readSt.Readiness).Should(HaveKeyWithValue("anykey",
				ConditionStatus{Ready: true, Reason: ""}))
			Expect(readSt.GetReadiness()).Should(Equal(true))
		})

		By("status file should not be updated when set ready a 2nd time", func() {
			prevStat, err := os.Stat(f.Name())
			Expect(err).NotTo(HaveOccurred())

			// Set ready again
			st.SetReady("anykey", true, "")

			// Check previous modification time to the time reported now
			nowStat, err := os.Stat(f.Name())
			Expect(err).NotTo(HaveOccurred())
			Expect(nowStat.ModTime()).To(Equal(prevStat.ModTime()))

			// Make sure the status value has not changed
			readSt, err := ReadStatusFile(f.Name())
			Expect(err).NotTo(HaveOccurred())
			Expect(readSt.Readiness).Should(HaveKeyWithValue("anykey",
				ConditionStatus{Ready: true, Reason: ""}))
			Expect(readSt.GetReadiness()).Should(Equal(true))
		})

		By("status file should be updated to not ready after being ready", func() {
			st.SetReady("anykey", false, "reason3")
			readSt, err := ReadStatusFile(f.Name())
			Expect(err).NotTo(HaveOccurred())

			Expect(readSt.Readiness).Should(HaveKeyWithValue("anykey",
				ConditionStatus{Ready: false, Reason: "reason3"}))
			Expect(readSt.GetReadiness()).Should(Equal(false))
		})
	})
})
