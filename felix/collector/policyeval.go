// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package collector

// Pending-policy evaluation off the collector's main goroutine. See "Off-main-loop evaluation"
// in felix/design/flow-logs-policy-evaluation.md.
//
// The main loop owns epStats and every field of every Data; no worker touches either. Where a
// flow needs evaluation the main loop builds a request holding copies of what the evaluation
// needs (the tuple, the endpoint data it resolved, a sequence number) and hands it to a worker.
// The worker evaluates under the policy store's read lock, exactly as the main loop used to, and
// sends the traces back. The main loop applies a result only if the Data is still the current
// entry for its tuple, the result is the flow's latest request, and the endpoints have not moved
// since the request was made; anything else is stale and dropped.
//
// New flows and re-evaluation sweeps use separate queues and the workers serve new flows first.
// A new flow whose queue is full is evaluated on the main loop as before, so it is never dropped;
// a sweep whose queue is full pauses until a result comes back, so it never floods the workers
// and never drops a flow either. With no workers configured everything runs inline, which is the
// behaviour before this file existed.

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/gavv/monotime"
	"github.com/projectcalico/calico/app-policy/checker"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/rules"
)

var (
	gaugePolicyEvalWorkers = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_collector_policy_eval_workers",
		Help: "Number of goroutines evaluating pending policy off the collector's main loop; 0 when evaluation is inline.",
	})
	gaugePolicyEvalBacklog = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_collector_policy_eval_backlog",
		Help: "Pending policy evaluation requests waiting for a worker, by queue.",
	}, []string{"queue"})
	counterPolicyEvalInline = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_collector_policy_eval_inline_total",
		Help: "Total number of new flows evaluated on the collector's main loop because the workers' new-flow queue was full.",
	})
	counterPolicyEvalDeferred = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_collector_policy_eval_deferred_total",
		Help: "Total number of times a re-evaluation sweep paused because the workers' recalc queue was full.",
	})
	counterPolicyEvalStale = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_collector_policy_eval_stale_results_total",
		Help: "Total number of pending policy evaluation results dropped because the flow was gone, re-requested or had changed endpoints by the time they came back.",
	})
	histogramPolicyEvalLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "felix_collector_policy_eval_latency_seconds",
		Help:    "Time from a pending policy evaluation being requested to its result being applied to the flow.",
		Buckets: prometheus.ExponentialBuckets(0.00001, 4, 10),
	}, []string{"reason"})
)

func init() {
	prometheus.MustRegister(gaugePolicyEvalWorkers)
	prometheus.MustRegister(gaugePolicyEvalBacklog)
	prometheus.MustRegister(counterPolicyEvalInline)
	prometheus.MustRegister(counterPolicyEvalDeferred)
	prometheus.MustRegister(counterPolicyEvalStale)
	prometheus.MustRegister(histogramPolicyEvalLatency)
}

// policyEvalRequest is what the main loop hands a worker: copies of everything the evaluation
// needs. data is identity only; the worker never dereferences it.
type policyEvalRequest struct {
	data     *Data
	tuple    tuple.Tuple
	srcEp    calc.EndpointData
	dstEp    calc.EndpointData
	seq      uint64
	reason   policyEvalReason
	queuedAt time.Time
}

// policyEvalResult is the request plus the traces. A trace is only meaningful when its ok flag
// is set; an evaluation that failed, or an endpoint the store does not know yet, leaves the
// flow's previous trace in place, as it always has.
type policyEvalResult struct {
	policyEvalRequest
	ingress, egress     []*calc.RuleID
	ingressOK, egressOK bool
}

// policyEvalPool is the worker pool and its queues.
type policyEvalPool struct {
	newFlows chan policyEvalRequest
	recalcs  chan policyEvalRequest
	results  chan policyEvalResult
	stop     chan struct{}
	wg       sync.WaitGroup
}

func newPolicyEvalPool(backlog int) *policyEvalPool {
	return &policyEvalPool{
		newFlows: make(chan policyEvalRequest, backlog),
		recalcs:  make(chan policyEvalRequest, backlog),
		results:  make(chan policyEvalResult, backlog),
		stop:     make(chan struct{}),
	}
}

// start launches the workers. Separate from construction so that tests can drive the queues by
// hand.
func (p *policyEvalPool) start(c *collector, workers int) {
	gaugePolicyEvalWorkers.Set(float64(workers))
	for i := 0; i < workers; i++ {
		p.wg.Go(func() { c.policyEvalWorker(p) })
	}
}

// stopAndWait stops the workers. Requests left in the queues are abandoned; the collector is
// only stopped when the process is.
func (p *policyEvalPool) stopAndWait() {
	close(p.stop)
	p.wg.Wait()
	gaugePolicyEvalWorkers.Set(0)
}

// policyEvalWorker serves new-flow requests ahead of recalc requests: a new flow's first export
// is waiting on its verdict, a live flow already has one.
func (c *collector) policyEvalWorker(p *policyEvalPool) {
	for {
		var req policyEvalRequest
		select {
		case <-p.stop:
			return
		case req = <-p.newFlows:
		default:
			select {
			case <-p.stop:
				return
			case req = <-p.newFlows:
			case req = <-p.recalcs:
			}
		}
		select {
		case p.results <- c.computePendingTraces(req):
		case <-p.stop:
			return
		}
	}
}

// requestPolicyEval evaluates a flow's pending traces: on the workers when the collector has
// them, on the main loop otherwise. It returns false only for a recalc request that could not be
// queued, which tells the sweep to pause.
func (c *collector) requestPolicyEval(data *Data, reason policyEvalReason) bool {
	srcEp, dstEp := c.findEndpointBestMatch(data.Tuple)
	// Endpoints changed mid-flight; leave lastPolicyEvalAt unset so the next sweep retries.
	if endpointChanged(data.SrcEp, srcEp) || endpointChanged(data.DstEp, dstEp) {
		return true
	}
	req := policyEvalRequest{
		data:     data,
		tuple:    data.Tuple,
		srcEp:    srcEp,
		dstEp:    dstEp,
		seq:      data.evalSeq + 1,
		reason:   reason,
		queuedAt: time.Now(),
	}
	if p := c.evalPool; p != nil {
		if reason == policyEvalRecalc {
			if data.evalInFlight {
				// The evaluation already queued will be at least as fresh as this one.
				return true
			}
			select {
			case p.recalcs <- req:
				data.evalSeq, data.evalInFlight = req.seq, true
				return true
			default:
				counterPolicyEvalDeferred.Inc()
				return false
			}
		}
		select {
		case p.newFlows <- req:
			data.evalSeq, data.evalInFlight = req.seq, true
			return true
		default:
			// Never drop a new flow: its first export is waiting on this.
			counterPolicyEvalInline.Inc()
		}
	}
	data.evalSeq = req.seq
	c.applyPolicyEvalResult(c.computePendingTraces(req))
	return true
}

// computePendingTraces is the evaluation itself. It runs on a worker or, inline, on the main
// loop; either way it reads only the request and the policy store.
func (c *collector) computePendingTraces(req policyEvalRequest) policyEvalResult {
	res := policyEvalResult{policyEvalRequest: req}
	flow := TupleAsFlow(req.tuple)
	c.policyStoreManager.DoWithReadLock(func(ps *policystore.PolicyStore) {
		// Evaluate ingress if destination is local workload endpoint
		if req.dstEp != nil && !req.dstEp.IsHostEndpoint() && req.dstEp.IsLocal() {
			res.ingress, res.ingressOK = c.computePendingTrace(rules.RuleDirIngress, ps, req.dstEp, &flow)
		}
		// Evaluate egress if source is local workload endpoint
		if req.srcEp != nil && !req.srcEp.IsHostEndpoint() && req.srcEp.IsLocal() {
			res.egress, res.egressOK = c.computePendingTrace(rules.RuleDirEgress, ps, req.srcEp, &flow)
		}
	})
	return res
}

// computePendingTrace evaluates one direction. The trace it returns may be shared with the
// store's verdict cache and must be treated as read-only; applyPolicyEvalResult copies it.
func (c *collector) computePendingTrace(direction rules.RuleDir, store *policystore.PolicyStore, ep calc.EndpointData, flow *TupleAsFlow) ([]*calc.RuleID, bool) {
	protoEp := c.lookupProtoWorkloadEndpoint(store, ep.Key())
	if protoEp == nil {
		log.WithField("endpoint", ep.Key()).Trace("The endpoint is not yet tracked by the PolicyStore")
		return nil, false
	}
	trace, err := checker.Evaluate(checker.StagedAsEnforced, direction, store, protoEp, flow)
	if err != nil {
		// Keep the trace we worked out last time: reporting no pending policy at all would be a
		// stronger claim than we are in a position to make. The checker logs the reason, rate
		// limited, so this one stays at trace level.
		log.WithError(err).Tracef("Pending %s evaluation failed, tuple: %v", direction, flow)
		return nil, false
	}
	return trace, true
}

// applyPolicyEvalResult stores a result on its flow. Main loop only.
func (c *collector) applyPolicyEvalResult(res policyEvalResult) {
	data := res.data
	if cur, ok := c.epStats[res.tuple]; !ok || cur != data {
		// Expired, deleted, or the tuple was reused since the request.
		counterPolicyEvalStale.Inc()
		return
	}
	if res.seq != data.evalSeq {
		// A newer request for this flow is queued or in flight; its result supersedes this one.
		counterPolicyEvalStale.Inc()
		return
	}
	data.evalInFlight = false
	if endpointChanged(data.SrcEp, res.srcEp) || endpointChanged(data.DstEp, res.dstEp) {
		// The flow's endpoints moved while the evaluation was in flight; the sweep retries.
		counterPolicyEvalStale.Inc()
		return
	}
	histogramPolicyEvalLatency.WithLabelValues(string(res.reason)).Observe(time.Since(res.queuedAt).Seconds())
	counterPolicyEvalFlows.WithLabelValues(string(res.reason)).Inc()
	data.lastPolicyEvalAt = monotime.Now()
	if res.ingressOK && !equal(data.IngressPendingRuleIDs, res.ingress) {
		data.IngressPendingRuleIDs = append([]*calc.RuleID(nil), res.ingress...)
		log.Tracef("Updated pending ingress, tuple: %v, rule trace: %v", res.tuple, data.IngressPendingRuleIDs)
	}
	if res.egressOK && !equal(data.EgressPendingRuleIDs, res.egress) {
		data.EgressPendingRuleIDs = append([]*calc.RuleID(nil), res.egress...)
		log.Tracef("Updated pending egress, tuple: %v, rule trace: %v", res.tuple, data.EgressPendingRuleIDs)
	}
}

// drainPolicyEvalResults applies every result that is ready without blocking, and reports how
// many it applied. Main loop only.
func (c *collector) drainPolicyEvalResults() int {
	if c.evalPool == nil {
		return 0
	}
	n := 0
	for {
		select {
		case res := <-c.evalPool.results:
			c.applyPolicyEvalResult(res)
			n++
		default:
			c.reportPolicyEvalBacklog()
			return n
		}
	}
}

// policyEvalResultsChan returns the results channel, or nil (blocks forever in a select) when
// evaluation is inline.
func (c *collector) policyEvalResultsChan() <-chan policyEvalResult {
	if c.evalPool == nil {
		return nil
	}
	return c.evalPool.results
}

func (c *collector) reportPolicyEvalBacklog() {
	if c.evalPool == nil {
		return
	}
	gaugePolicyEvalBacklog.WithLabelValues("new_flows").Set(float64(len(c.evalPool.newFlows)))
	gaugePolicyEvalBacklog.WithLabelValues("recalc").Set(float64(len(c.evalPool.recalcs)))
}
