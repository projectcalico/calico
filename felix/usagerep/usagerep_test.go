// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.
//
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
package usagerep

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/buildinfo"
	"github.com/projectcalico/calico/felix/calc"
)

const expectedNumberOfURLParams = 13

// These tests start a local HTTP server on a random port and tell the usage reporter to
// connect to it.  Then we can check that it correctly makes HTTP requests at the right times.
var _ = Describe("UsageReporter with mocked URL and short interval", func() {
	var u *UsageReporter
	var tcpListener net.Listener
	var httpHandler *requestRecorder
	var ctx context.Context
	var cancel context.CancelFunc
	var statsUpdateC chan calc.StatsUpdate
	var configUpdateC chan map[string]string

	BeforeEach(func() {
		// Open a listener on a random local port.
		var err error
		tcpListener, err = net.Listen("tcp", "localhost:0")
		Expect(err).NotTo(HaveOccurred())
		httpHandler = &requestRecorder{}
		go func() {
			defer GinkgoRecover()
			// TODO: Investigate why this call sometimes returns an error.
			err = http.Serve(tcpListener, httpHandler)
			if err != nil {
				log.WithError(err).Error("Failed to start HTTP server.")
			}
		}()

		// Channels to send data to the UsageReporter.
		statsUpdateC = make(chan calc.StatsUpdate)
		configUpdateC = make(chan map[string]string)

		// Create a usage reporter and override its base URL and initial interval.
		u = New(StaticItems{KubernetesVersion: "v1.23.2"}, 500*time.Millisecond, 1*time.Second, statsUpdateC, configUpdateC)
		port := tcpListener.Addr().(*net.TCPAddr).Port
		u.BaseURL = fmt.Sprintf("http://localhost:%d/UsageCheck/calicoVersionCheck?", port)

		ctx, cancel = context.WithCancel(context.Background())
		go u.PeriodicallyReportUsage(ctx)
	})

	AfterEach(func() {
		cancel()
		tcpListener.Close()
	})

	It("should not check in before receiving config/stats", func() {
		Consistently(httpHandler.GetRequestURIs, "2s").Should(BeEmpty())
	})

	Context("after sending config", func() {
		sendConfig := func() {
			configUpdateC <- map[string]string{
				"ClusterGUID":   "someguid",
				"ClusterType":   "openstack,k8s,kdd",
				"CalicoVersion": "v2.6.3",
				"BPFEnabled":    "false",
			}
		}

		BeforeEach(func() {
			sendConfig()
		})

		It("should not check in before receiving stats", func() {
			Consistently(httpHandler.GetRequestURIs, "2s").Should(BeEmpty())
		})

		Context("after sending stats", func() {
			sendStats := func() {
				statsUpdateC <- calc.StatsUpdate{
					NumHosts:             1,
					NumHostEndpoints:     2,
					NumWorkloadEndpoints: 3,
					NumPolicies:          4,
					NumProfiles:          5,
					NumALPPolicies:       6,
				}
			}

			BeforeEach(func() {
				sendStats()
			})

			It("should do first check ins correctly", func() {
				By("checking in within 2s")
				startTime := time.Now()
				Eventually(httpHandler.GetRequestURIs, "2s", "100ms").Should(HaveLen(1))
				By("waiting until after the initial delay")
				Expect(time.Since(startTime)).To(BeNumerically(">=", 500*time.Millisecond))

				By("including correct URL parameters")
				uri := httpHandler.GetRequestURIs()[0]
				url, err := url.Parse(uri)
				Expect(err).NotTo(HaveOccurred())
				Expect(url.Path).To(Equal("/UsageCheck/calicoVersionCheck"))
				q := url.Query()
				Expect(q).To(HaveLen(expectedNumberOfURLParams), "unexpected number of URL parameters")
				Expect(q.Get("guid")).To(Equal("someguid"))
				Expect(q.Get("type")).To(Equal("openstack,k8s,kdd"))
				Expect(q.Get("cal_ver")).To(Equal("v2.6.3"))
				Expect(q.Get("k8s_ver")).To(Equal("v1.23.2"))
				Expect(q.Get("alp")).To(Equal("false"))
				Expect(q.Get("size")).To(Equal("1"))
				Expect(q.Get("heps")).To(Equal("2"))
				Expect(q.Get("weps")).To(Equal("3"))
				Expect(q.Get("policies")).To(Equal("4"))
				Expect(q.Get("profiles")).To(Equal("5"))
				Expect(q.Get("alp_policies")).To(Equal("6"))

				By("checking in again")
				Eventually(httpHandler.GetRequestURIs, "2s", "100ms").Should(HaveLen(2))
				By("waiting until at least initial delay + 90% (due to jitter) of interval for second check in")
				Expect(time.Since(startTime)).To(BeNumerically(">=", 1400*time.Millisecond))
			})

			It("should not block the channels while doing initial delay", func() {
				startTime := time.Now()
				// We created the channel as a blocking channel so, if we can send a few updates,
				// we know that the main loop is processing them
				sendStats()
				sendStats()
				sendStats()
				sendConfig()
				sendConfig()
				sendConfig()
				Expect(time.Since(startTime)).To(BeNumerically("<", 100*time.Millisecond))
			})

			Context("after first report, and sending in config and stat updates", func() {
				BeforeEach(func() {
					Eventually(httpHandler.GetRequestURIs, "2s", "100ms").Should(HaveLen(1))
					statsUpdateC <- calc.StatsUpdate{
						NumHosts:             10,
						NumHostEndpoints:     20,
						NumWorkloadEndpoints: 30,
						NumPolicies:          40,
						NumProfiles:          50,
						NumALPPolicies:       60,
					}
					configUpdateC <- map[string]string{
						"ClusterGUID":          "someguid2",
						"ClusterType":          "openstack,k8s,kdd,typha",
						"CalicoVersion":        "v3.0.0",
						"PolicySyncPathPrefix": "/var/run/nodeagent",
						"BPFEnabled":           "true",
					}
				})

				It("should do second check in correctly", func() {
					By("checking in within 2s")
					Eventually(httpHandler.GetRequestURIs, "2s", "100ms").Should(HaveLen(2))

					By("including correct URL parameters")
					uri := httpHandler.GetRequestURIs()[1]
					url, err := url.Parse(uri)
					Expect(err).NotTo(HaveOccurred())
					q := url.Query()
					Expect(q).To(HaveLen(expectedNumberOfURLParams), "unexpected number of URL parameters")
					Expect(q.Get("guid")).To(Equal("someguid2"))
					Expect(q.Get("type")).To(Equal("openstack,k8s,kdd,typha,bpf"))
					Expect(q.Get("cal_ver")).To(Equal("v3.0.0"))
					Expect(q.Get("k8s_ver")).To(Equal("v1.23.2"))
					Expect(q.Get("alp")).To(Equal("true"))
					Expect(q.Get("size")).To(Equal("10"))
					Expect(q.Get("heps")).To(Equal("20"))
					Expect(q.Get("weps")).To(Equal("30"))
					Expect(q.Get("policies")).To(Equal("40"))
					Expect(q.Get("profiles")).To(Equal("50"))
					Expect(q.Get("alp_policies")).To(Equal("60"))
				})
			})
		})
	})
})

type requestRecorder struct {
	lock             sync.Mutex
	requestsReceived []string
}

func (h *requestRecorder) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.requestsReceived = append(h.requestsReceived, req.RequestURI)

	_, err := resp.Write([]byte(`{"usage_warning": "Warning!"}`))
	Expect(err).NotTo(HaveOccurred())
}

func (h *requestRecorder) GetRequestURIs() []string {
	h.lock.Lock()
	defer h.lock.Unlock()
	var result []string
	result = append(result, h.requestsReceived...)
	return result
}

// These tests create a usage reporter but they don't start it.  Instead they validate its
// internal calculation methods and the default configuration.
var _ = Describe("UsageReporter with default URL", func() {
	var u *UsageReporter

	BeforeEach(func() {
		u = New(StaticItems{KubernetesVersion: ""}, 5*time.Minute, 24*time.Hour, nil, nil)
	})

	It("should calculate correct URL mainline", func() {
		rawURL := u.calculateURL("theguid", "atype", "testVer", true, false, calc.StatsUpdate{
			NumHostEndpoints:     123,
			NumWorkloadEndpoints: 234,
			NumHosts:             10,
		})
		url, err := url.Parse(rawURL)
		Expect(err).NotTo(HaveOccurred())
		q := url.Query()
		Expect(q).To(HaveLen(expectedNumberOfURLParams), "unexpected number of URL parameters")
		Expect(q.Get("guid")).To(Equal("theguid"))
		Expect(q.Get("type")).To(Equal("atype"))
		Expect(q.Get("cal_ver")).To(Equal("testVer"))
		Expect(q.Get("k8s_ver")).To(Equal("unknown"))
		Expect(q.Get("alp")).To(Equal("true"))
		Expect(q.Get("size")).To(Equal("10"))
		Expect(q.Get("weps")).To(Equal("234"))
		Expect(q.Get("heps")).To(Equal("123"))
		Expect(q.Get("version")).To(Equal(buildinfo.GitVersion))
		Expect(q.Get("rev")).To(Equal(buildinfo.GitRevision))

		Expect(url.Host).To(Equal("usage.projectcalico.org"))
		Expect(url.Scheme).To(Equal("https"))
		Expect(url.Path).To(Equal("/UsageCheck/calicoVersionCheck"))
	})
	It("should default cluster type, GUID, and Calico Version", func() {
		rawURL := u.calculateURL("", "", "", false, false, calc.StatsUpdate{
			NumHostEndpoints:     123,
			NumWorkloadEndpoints: 234,
			NumHosts:             10,
		})
		url, err := url.Parse(rawURL)
		Expect(err).NotTo(HaveOccurred())
		q := url.Query()
		Expect(q).To(HaveLen(expectedNumberOfURLParams), "unexpected number of URL parameters")
		Expect(q.Get("guid")).To(Equal("baddecaf"))
		Expect(q.Get("type")).To(Equal("unknown"))
		Expect(q.Get("cal_ver")).To(Equal("unknown"))
		Expect(q.Get("k8s_ver")).To(Equal("unknown"))
		Expect(q.Get("alp")).To(Equal("false"))
	})
	It("should delay at least 5 minutes", func() {
		Expect(u.calculateInitialDelay(0)).To(BeNumerically(">=", 5*time.Minute))
		Expect(u.calculateInitialDelay(1)).To(BeNumerically(">=", 5*time.Minute))
		Expect(u.calculateInitialDelay(1000)).To(BeNumerically(">=", 5*time.Minute))
	})
	It("should delay at most 10000 seconds", func() {
		Expect(u.calculateInitialDelay(10000)).To(BeNumerically("<=", 5*time.Minute+10000*time.Second))
		Expect(u.calculateInitialDelay(100000)).To(BeNumerically("<=", 5*time.Minute+10000*time.Second))
		Expect(u.calculateInitialDelay(1000000)).To(BeNumerically("<=", 5*time.Minute+10000*time.Second))
		Expect(u.calculateInitialDelay(10000000)).To(BeNumerically("<=", 5*time.Minute+10000*time.Second))
	})
	It("should have a random component", func() {
		firstDelay := u.calculateInitialDelay(1000)
		for i := 0; i < 10; i++ {
			if u.calculateInitialDelay(1000) != firstDelay {
				return // Success
			}
		}
		Fail("Generated 10 delays but they were all the same")
	})
	It("should have an average close to expected value", func() {
		var total time.Duration
		// Give it a high but bounded number of iterations to converge.
		for i := int64(0); i < 100000; i++ {
			total += u.calculateInitialDelay(60)
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
