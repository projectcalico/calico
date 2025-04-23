// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flowlog

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"

	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

var (
	logGroupName  = "test-group"
	logStreamName = "test-stream"
	flushInterval = 500 * time.Millisecond
	includeLabels = false
)

var (
	pvtMeta = endpoint.Metadata{Type: endpoint.Net, Namespace: "-", Name: "-", AggregatedName: "pvt"}
	pubMeta = endpoint.Metadata{Type: endpoint.Net, Namespace: "-", Name: "-", AggregatedName: "pub"}
)

type testFlowLogReporter struct {
	mutex    sync.Mutex
	logs     []*FlowLog
	failInit bool
}

// Mock time helper.
type mockTime struct {
	val int64
}

func (mt *mockTime) getMockTime() time.Duration {
	val := atomic.LoadInt64(&mt.val)
	return time.Duration(val)
}
func (mt *mockTime) incMockTime(inc time.Duration) {
	atomic.AddInt64(&mt.val, int64(inc))
}

func (d *testFlowLogReporter) Start() error {
	if d.failInit {
		return errors.New("failed to initialize testFlowLogReporter")
	}
	return nil
}

func (d *testFlowLogReporter) Report(logSlice interface{}) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	log.Info("In dispatch")
	fl := logSlice.([]*FlowLog)
	d.logs = append(d.logs, fl...)
	return nil
}

func (d *testFlowLogReporter) getLogs() []*FlowLog {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return d.logs
}

var _ = Describe("Flowlog Reporter health verification", func() {
	var (
		cr         *FlowLogReporter
		hr         *health.HealthAggregator
		dispatcher *testFlowLogReporter
	)

	mt := &mockTime{}
	Context("Test with no errors", func() {
		BeforeEach(func() {
			dispatcherMap := map[string]types.Reporter{}
			dispatcher = &testFlowLogReporter{}
			dispatcherMap["testFlowLog"] = dispatcher
			hr = health.NewHealthAggregator()
			cr = NewReporter(dispatcherMap, flushInterval, hr)
			cr.timeNowFn = mt.getMockTime
			Expect(cr.Start()).NotTo(HaveOccurred())
		})
		It("verify health reporting.", func() {
			By("checking the Readiness flag in health aggregator")
			expectedReport := health.HealthReport{Live: true, Ready: true}
			Eventually(func() bool { return hr.Summary().Live }, 15, 1).Should(Equal(expectedReport.Live))
			Eventually(func() bool { return hr.Summary().Ready }, 15, 1).Should(Equal(expectedReport.Ready))
		})
	})
	Context("Test with dispatcher that fails to initialize", func() {
		BeforeEach(func() {
			dispatcherMap := map[string]types.Reporter{}
			dispatcher = &testFlowLogReporter{failInit: true}
			dispatcherMap["testFlowLog"] = dispatcher
			hr = health.NewHealthAggregator()
			cr = NewReporter(dispatcherMap, flushInterval, hr)
			cr.timeNowFn = mt.getMockTime
			Expect(cr.Start()).NotTo(HaveOccurred())
		})
		It("verify health reporting.", func() {
			By("checking the Readiness flag in health aggregator")
			expectedReport := health.HealthReport{Live: true, Ready: false}
			Eventually(func() bool { return hr.Summary().Live }, 15, 1).Should(Equal(expectedReport.Live))
			Eventually(func() bool { return hr.Summary().Ready }, 15, 1).Should(Equal(expectedReport.Ready))
		})
	})
})

var _ = Describe("FlowLog per minute verification", func() {
	var (
		cr         *FlowLogReporter
		ca         *Aggregator
		dispatcher *testFlowLogReporter
	)

	mt := &mockTime{}

	Context("Flow logs per minute verification", func() {
		It("Usage report is triggered before flushIntervalDuration", func() {
			By("Triggering report right away before flushIntervalDuration")
			ca = NewAggregator()
			dispatcherMap := map[string]types.Reporter{}
			dispatcher = &testFlowLogReporter{}
			dispatcherMap["testFlowLog"] = dispatcher
			mockFlushInterval := 600 * time.Second
			cr = NewReporter(dispatcherMap, mockFlushInterval, nil)
			cr.AddAggregator(ca, []string{"testFlowLog"})
			cr.timeNowFn = mt.getMockTime
			Expect(cr.Start()).NotTo(HaveOccurred())

			Expect(cr.GetAndResetFlowLogsAvgPerMinute()).Should(Equal(0.0))
		})
		It("Usage report is triggered post flushIntervalDuration", func() {
			By("Triggering report post flushIntervalDuration by mocking flushInterval")
			ca = NewAggregator()
			ca.IncludePolicies(true)
			dispatcherMap := map[string]types.Reporter{}
			dispatcher = &testFlowLogReporter{}
			dispatcherMap["testFlowLog"] = dispatcher
			cr = NewReporter(dispatcherMap, flushInterval, nil)
			cr.AddAggregator(ca, []string{"testFlowLog"})
			cr.timeNowFn = mt.getMockTime
			Expect(cr.Start()).NotTo(HaveOccurred())

			Expect(cr.Report(muNoConn1Rule1AllowUpdate)).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)

			Expect(cr.GetAndResetFlowLogsAvgPerMinute()).Should(BeNumerically(">", 0))
		})
	})
})

var _ = Describe("FlowLogAvg reporting for a Reporter", func() {
	var (
		cr         *FlowLogReporter
		ca         *Aggregator
		dispatcher *testFlowLogReporter
	)

	BeforeEach(func() {
		ca = NewAggregator()
		ca.IncludePolicies(true)
		dispatcherMap := map[string]types.Reporter{}
		dispatcher = &testFlowLogReporter{}
		dispatcherMap["testFlowLog"] = dispatcher

		cr = NewReporter(dispatcherMap, flushInterval, nil)
	})

	It("updateFlowLogsAvg does not cause a data race contention  with resetFlowLogsAvg", func() {
		previousTotal := 10
		newTotal := previousTotal + 5

		cr.updateFlowLogsAvg(previousTotal)

		var timeResetStart time.Time
		var timeResetEnd time.Time

		time.AfterFunc(2*time.Second, func() {
			timeResetStart = time.Now()
			cr.resetFlowLogsAvg()
			timeResetEnd = time.Now()
		})

		// Update is a little after resetFlowLogsAvg because feedupdate has some preprocesssing
		// before it accesses flowAvg
		time.AfterFunc(2*time.Second+10*time.Millisecond, func() {
			cr.updateFlowLogsAvg(newTotal)
		})

		Eventually(func() int { return cr.flowLogAvg.totalFlows }, "6s", "2s").Should(Equal(newTotal))
		Expect(cr.flowLogAvg.lastReportTime.Before(timeResetEnd)).To(BeTrue())
		Expect(cr.flowLogAvg.lastReportTime.After(timeResetStart)).To(BeTrue())
	})
})

type mockDispatcher struct {
	mock.Mock
	iteration    int
	maxIteration int
	collector    chan []*FlowLog
	started      atomic.Bool
}

func newMockDispatcher(maxIterations int) *mockDispatcher {
	return &mockDispatcher{
		collector:    make(chan []*FlowLog),
		maxIteration: maxIterations,
	}
}

func (m *mockDispatcher) Start() error {
	m.started.Store(true)
	return nil
}

func (m *mockDispatcher) Report(logSlice interface{}) error {
	m.iteration++
	log.Infof("Mocked dispatcher was called %d times ", m.iteration)
	logs := logSlice.([]*FlowLog)
	log.Infof("Reporting num=%d of logs", len(logs))
	if m.iteration <= m.maxIteration {
		m.collector <- logs
	}
	return nil
}

func (m *mockDispatcher) Started() bool {
	return m.started.Load()
}

func (m *mockDispatcher) Close() {
	close(m.collector)
}

type mockTicker struct {
	mock.Mock
	tick chan time.Time
	stop chan bool
}

func newMockTicker() *mockTicker {
	return &mockTicker{
		tick: make(chan time.Time),
		stop: make(chan bool),
	}
}

func (m *mockTicker) invokeTick(x time.Time) {
	m.tick <- x
}

func (m *mockTicker) Channel() <-chan time.Time {
	return m.tick
}

func (m *mockTicker) Stop() {
	close(m.tick)
	close(m.stop)
}

func (m *mockTicker) Done() chan bool {
	return m.stop
}

func newExpectedFlowLog(t tuple.Tuple, nf, nfs, nfc int, a Action, fr ReporterType, pi, po, bi, bo int, srcMeta, dstMeta endpoint.Metadata, dstService FlowService, srcLabels, dstLabels map[string]string, fep, fpp FlowPolicySet) FlowLog {
	return FlowLog{
		FlowMeta: FlowMeta{
			Tuple:      t,
			Action:     a,
			Reporter:   fr,
			SrcMeta:    srcMeta,
			DstMeta:    dstMeta,
			DstService: dstService,
		},
		FlowLabels: FlowLabels{
			SrcLabels: uniquelabels.Make(srcLabels),
			DstLabels: uniquelabels.Make(dstLabels),
		},
		FlowEnforcedPolicySet: fep,
		FlowPendingPolicySet:  fpp,
		FlowProcessReportedStats: FlowProcessReportedStats{
			FlowReportedStats: FlowReportedStats{
				NumFlows:          nf,
				NumFlowsStarted:   nfs,
				NumFlowsCompleted: nfc,
				PacketsIn:         pi,
				PacketsOut:        po,
				BytesIn:           bi,
				BytesOut:          bo,
			},
		},
	}
}
