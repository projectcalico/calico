// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package usagerep

import (
	"net/url"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/buildinfo"
	"github.com/projectcalico/felix/calc"
)

var _ = Describe("Usagerep", func() {
	It("should calculate correct URL mainline", func() {
		rawURL := calculateURL("theguid", "atype", calc.StatsUpdate{
			NumHostEndpoints:     123,
			NumWorkloadEndpoints: 234,
			NumHosts:             10,
		})
		url, err := url.Parse(rawURL)
		Expect(err).NotTo(HaveOccurred())
		q := url.Query()
		Expect(len(q)).To(Equal(7))
		Expect(q.Get("guid")).To(Equal("theguid"))
		Expect(q.Get("type")).To(Equal("atype"))
		Expect(q.Get("size")).To(Equal("10"))
		Expect(q.Get("weps")).To(Equal("234"))
		Expect(q.Get("heps")).To(Equal("123"))
		Expect(q.Get("version")).To(Equal(buildinfo.GitVersion))
		Expect(q.Get("rev")).To(Equal(buildinfo.GitRevision))

		Expect(url.Host).To(Equal("usage.projectcalico.org"))
		Expect(url.Scheme).To(Equal("https"))
		Expect(url.Path).To(Equal("/UsageCheck/calicoVersionCheck"))
	})
	It("should default cluster type and GUID", func() {
		rawURL := calculateURL("", "", calc.StatsUpdate{
			NumHostEndpoints:     123,
			NumWorkloadEndpoints: 234,
			NumHosts:             10,
		})
		url, err := url.Parse(rawURL)
		Expect(err).NotTo(HaveOccurred())
		q := url.Query()
		Expect(len(q)).To(Equal(7))
		Expect(q.Get("guid")).To(Equal("baddecaf"))
		Expect(q.Get("type")).To(Equal("unknown"))
	})
	It("should delay at least 5 minutes", func() {
		Expect(calculateInitialDelay(0)).To(BeNumerically(">=", 5*time.Minute))
		Expect(calculateInitialDelay(1)).To(BeNumerically(">=", 5*time.Minute))
		Expect(calculateInitialDelay(1000)).To(BeNumerically(">=", 5*time.Minute))
	})
	It("should delay at most 10000 seconds", func() {
		Expect(calculateInitialDelay(10000)).To(BeNumerically("<=", 5*time.Minute+10000*time.Second))
		Expect(calculateInitialDelay(100000)).To(BeNumerically("<=", 5*time.Minute+10000*time.Second))
		Expect(calculateInitialDelay(1000000)).To(BeNumerically("<=", 5*time.Minute+10000*time.Second))
		Expect(calculateInitialDelay(10000000)).To(BeNumerically("<=", 5*time.Minute+10000*time.Second))
	})
	It("should have a random component", func() {
		firstDelay := calculateInitialDelay(1000)
		for i := 0; i < 10; i++ {
			if calculateInitialDelay(1000) != firstDelay {
				return // Success
			}
		}
		Fail("Generated 10 delays but they were all the same")
	})
	It("should have an average close to expected value", func() {
		var total time.Duration
		// Give it a high but bounded number of iterations to converge.
		for i := int64(0); i < 100000; i++ {
			total += calculateInitialDelay(60)
			if i > 100 {
				average := time.Duration(int64(total) / (i + 1))
				// Delay should an average of 0.5s per host so the average should
				// be close to 5min30s.
				if average > (5*time.Minute+20*time.Second) &&
					average < (5*time.Minute+40*time.Second) {
					// Pass!
					return
				}
			}
		}
		Fail("Average of initial delay failed to converge after many iterations")
	})
})
