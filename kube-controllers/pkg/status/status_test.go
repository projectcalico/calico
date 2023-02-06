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
	"os"
	"strconv"
	"sync"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// This section contains unit tests for the Status pkg.
var _ = Describe("Status pkg UTs", func() {
	It("should report failed readiness with no condition statuses", func() {
		st := New("no-needed")
		Expect(st.GetReadiness()).To(BeFalse())
	})

	It("should update the status file when changes happen", func() {
		f, err := os.CreateTemp("", "test")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(f.Name())
		st := New(f.Name())

		By("status file should return proper Status object", func() {
			st.SetReady("anykey", false, "reason1")

			readSt, err := ReadStatusFile(f.Name())
			Expect(err).NotTo(HaveOccurred())

			Expect(readSt.Readiness).To(HaveKeyWithValue("anykey",
				ConditionStatus{Ready: false, Reason: "reason1"}))
			Expect(readSt.GetReadiness()).To(Equal(false))
		})

		By("status file should be updated when reason changes", func() {
			st.SetReady("anykey", false, "reason2")

			// File should be updated, check the data.
			readSt, err := ReadStatusFile(f.Name())
			Expect(err).NotTo(HaveOccurred())
			Expect(readSt.Readiness).To(HaveKeyWithValue("anykey",
				ConditionStatus{Ready: false, Reason: "reason2"}))
			Expect(readSt.GetReadiness()).To(Equal(false))
		})

		By("status file should be updated when set ready", func() {
			st.SetReady("anykey", true, "")

			// File should be updated, check the data.
			readSt, err := ReadStatusFile(f.Name())
			Expect(err).NotTo(HaveOccurred())
			Expect(readSt.Readiness).To(HaveKeyWithValue("anykey",
				ConditionStatus{Ready: true, Reason: ""}))
			Expect(readSt.GetReadiness()).To(Equal(true))
		})

		By("status file should not be updated when set ready a 2nd time", func() {
			prevStat, err := os.Stat(f.Name())
			Expect(err).NotTo(HaveOccurred())

			// Set read again.
			st.SetReady("anykey", true, "")

			// The file should remain unchanged.
			nowStat, err := os.Stat(f.Name())
			Expect(err).NotTo(HaveOccurred())
			Expect(nowStat.ModTime()).To(Equal(prevStat.ModTime()))

			// Make sure the status value has not changed
			readSt, err := ReadStatusFile(f.Name())
			Expect(err).NotTo(HaveOccurred())
			Expect(readSt.Readiness).To(HaveKeyWithValue("anykey",
				ConditionStatus{Ready: true, Reason: ""}))
			Expect(readSt.GetReadiness()).To(Equal(true))
		})

		By("status file should be updated to not ready after being ready", func() {
			st.SetReady("anykey", false, "reason3")

			// File should be updated, check the data.
			readSt, err := ReadStatusFile(f.Name())
			Expect(err).NotTo(HaveOccurred())
			Expect(readSt.Readiness).To(HaveKeyWithValue("anykey",
				ConditionStatus{Ready: false, Reason: "reason3"}))
			Expect(readSt.GetReadiness()).To(Equal(false))
		})

		By("status file should handle a lot of concurrent not-ready updates for a lot of keys", func() {
			wg := sync.WaitGroup{}
			wg.Add(100)
			for i := 0; i < 100; i++ {
				go func(j int) {
					st.SetReady("anykey"+strconv.Itoa(j), false, "reason"+strconv.Itoa(j))
					wg.Done()
				}(i)
			}
			wg.Wait()
			Expect(st.Readiness).To(HaveLen(101))

			// File should be updated, check the data.
			readSt, err := ReadStatusFile(f.Name())
			Expect(err).NotTo(HaveOccurred())
			Expect(readSt.Readiness).To(HaveLen(101))
			Expect(readSt.Readiness).To(HaveKeyWithValue("anykey99",
				ConditionStatus{Ready: false, Reason: "reason99"}))
			Expect(readSt.Readiness).To(HaveKeyWithValue("anykey50",
				ConditionStatus{Ready: false, Reason: "reason50"}))
			Expect(readSt.Readiness).To(HaveKeyWithValue("anykey1",
				ConditionStatus{Ready: false, Reason: "reason1"}))
			Expect(readSt.GetReadiness()).To(Equal(false))
		})

		By("status file should handle a lot of concurrent ready updates for all of the keys (plus more)", func() {
			wg := sync.WaitGroup{}
			wg.Add(200)
			go st.SetReady("anykey", true, "reason")
			for i := 0; i < 200; i++ {
				go func(j int) {
					st.SetReady("anykey"+strconv.Itoa(j), true, "reason"+strconv.Itoa(j))
					wg.Done()
				}(i)
			}
			wg.Wait()
			Expect(st.Readiness).To(HaveLen(201))

			// File should be updated, check the data.
			readSt, err := ReadStatusFile(f.Name())
			Expect(err).NotTo(HaveOccurred())
			Expect(readSt.Readiness).To(HaveLen(201))
			Expect(readSt.Readiness).To(HaveKeyWithValue("anykey199",
				ConditionStatus{Ready: true, Reason: "reason199"}))
			Expect(readSt.Readiness).To(HaveKeyWithValue("anykey150",
				ConditionStatus{Ready: true, Reason: "reason150"}))
			Expect(readSt.Readiness).To(HaveKeyWithValue("anykey100",
				ConditionStatus{Ready: true, Reason: "reason100"}))
			Expect(readSt.GetReadiness()).To(Equal(true))
		})
	})
})
