// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/go/felix/buildinfo"
	"github.com/projectcalico/felix/go/felix/calc"
	"net/url"
)

var _ = Describe("Usagerep", func() {
	It("should caluculate correct URL mainline", func() {
		rawURL := calculateURL("myhost", "theguid", "atype", calc.StatsUpdate{
			NumHostEndpoints:     123,
			NumWorkloadEndpoints: 234,
			NumHosts:             10,
		})
		url, err := url.Parse(rawURL)
		Expect(err).NotTo(HaveOccurred())
		q := url.Query()
		Expect(len(q)).To(Equal(9))
		Expect(q.Get("hostname")).To(Equal("myhost"))
		Expect(q.Get("guid")).To(Equal("theguid"))
		Expect(q.Get("cluster_type")).To(Equal("atype"))
		Expect(q.Get("size")).To(Equal("10"))
		Expect(q.Get("num_wl_endpoints")).To(Equal("234"))
		Expect(q.Get("num_host_endpoints")).To(Equal("123"))
		Expect(q.Get("version")).To(Equal(buildinfo.Version))
		Expect(q.Get("git_revision")).To(Equal(buildinfo.GitRevision))
		Expect(q.Get("felix_type")).To(Equal("go"))

		Expect(url.Host).To(Equal("usage.projectcalico.org"))
		Expect(url.Scheme).To(Equal("https"))
		Expect(url.Path).To(Equal("/UsageCheck/calicoVersionCheck"))
	})
	It("should default cluster type and GUID", func() {
		rawURL := calculateURL("myhost", "", "", calc.StatsUpdate{
			NumHostEndpoints:     123,
			NumWorkloadEndpoints: 234,
			NumHosts:             10,
		})
		url, err := url.Parse(rawURL)
		Expect(err).NotTo(HaveOccurred())
		q := url.Query()
		Expect(len(q)).To(Equal(9))
		Expect(q.Get("guid")).To(Equal("baddecaf"))
		Expect(q.Get("cluster_type")).To(Equal("unknown"))
	})
})
