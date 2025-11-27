// Copyright (c) 2012-2025 Tigera, Inc. All rights reserved.

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

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/gavv/monotime"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/checker"
	"github.com/projectcalico/calico/app-policy/policystore"
	bpfconntrack "github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/jitter"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	prototypes "github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

const (
	// perHostPolicySubscription is the subscription type for per-host-policy.
	perHostPolicySubscription = "per-host-policies"
)

var (
	// conntrack processing prometheus metrics
	histogramConntrackLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "felix_collector_conntrack_processing_latency_seconds",
		Help: "Histogram for measuring the latency of Conntrack processing.",
	})

	// TODO: find a way to track errors for conntrack processing as there are no
	// indicative method to track errors currently

	// dumpStats processing prometheus metrics
	histogramDumpStatsLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "felix_collector_dumpstats_latency_seconds",
		Help: "Histogram for measuring latency for processing cached stats to stats file in config.StatsDumpFilePath.",
	})

	// TODO: find a way to track errors for epStats dump processing as there are no
	// indicative method to track errors currently

	// dataplaneStatsUpdate processing prometheus metrics
	histogramDataplaneStatsUpdate = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "felix_collector_dataplanestats_update_processing_latency_seconds",
		Help: "Histogram for measuring latency for processing merging the proto.DataplaneStatistics to the current data cache.",
	})

	gaugeDataplaneStatsUpdateErrorsPerMinute = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_collector_dataplanestats_update_processing_errors_per_minute",
		Help: "Number of errors encountered when processing merging the proto.DataplaneStatistics to the current data cache.",
	})

	dataplaneStatsUpdateLastErrorReportTime time.Time
	dataplaneStatsUpdateErrorsInLastMinute  uint32

	// epStats cache prometheus metrics
	gaugeEpStatsCacheSizeLength = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_collector_epstats",
		Help: "Total number of entries currently residing in the epStats cache.",
	})
)

func init() {
	prometheus.MustRegister(histogramConntrackLatency)
	prometheus.MustRegister(histogramDumpStatsLatency)
	prometheus.MustRegister(gaugeEpStatsCacheSizeLength)
	prometheus.MustRegister(histogramDataplaneStatsUpdate)
	prometheus.MustRegister(gaugeDataplaneStatsUpdateErrorsPerMinute)
}

type Config struct {
	AgeTimeout            time.Duration
	InitialReportingDelay time.Duration
	ExportingInterval     time.Duration
	EnableNetworkSets     bool
	EnableServices        bool
	PolicyEvaluationMode  string
	FlowLogsFlushInterval time.Duration

	IsBPFDataplane bool

	DisplayDebugTraceLogs bool

	BPFConntrackTimeouts bpfconntrack.Timeouts

	PolicyStoreManager policystore.PolicyStoreManager
}

// A collector (a StatsManager really) collects StatUpdates from data sources
// and stores them as a Data object in a map keyed by Tuple.
//
// Note that the dataplane statistics channel (ds) is currently just used for the
// policy syncer but will eventually also include NFLOG stats as well.
type collector struct {
	dataplaneInfoReader   types.DataplaneInfoReader
	packetInfoReader      types.PacketInfoReader
	conntrackInfoReader   types.ConntrackInfoReader
	luc                   *calc.LookupsCache
	epStats               map[tuple.Tuple]*Data
	ticker                jitter.TickerInterface
	tickerPolicyEval      jitter.TickerInterface
	config                *Config
	dumpLog               *log.Logger
	ds                    chan *proto.DataplaneStats
	metricReporters       []types.Reporter
	policyStoreManager    policystore.PolicyStoreManager
	displayDebugTraceLogs bool
}

// newCollector instantiates a new collector. The StartDataplaneStatsCollector function is the only public
// function for collector instantiation.
func newCollector(lc *calc.LookupsCache, cfg *Config) Collector {
	c := &collector{
		luc:                   lc,
		epStats:               make(map[tuple.Tuple]*Data),
		ticker:                jitter.NewTicker(cfg.ExportingInterval, cfg.ExportingInterval/10),
		tickerPolicyEval:      jitter.NewTicker(cfg.FlowLogsFlushInterval*8/10, cfg.FlowLogsFlushInterval*1/10),
		config:                cfg,
		dumpLog:               log.New(),
		ds:                    make(chan *proto.DataplaneStats, 1000),
		displayDebugTraceLogs: cfg.DisplayDebugTraceLogs,
		policyStoreManager:    cfg.PolicyStoreManager,
	}

	if c.policyStoreManager == nil {
		c.policyStoreManager = policystore.NewPolicyStoreManager()
	}

	if apiv3.FlowLogsPolicyEvaluationModeType(cfg.PolicyEvaluationMode) == apiv3.FlowLogsPolicyEvaluationModeContinuous {
		log.Infof("Pending policies enabled, initiating pending policy evaluation ticker")
		c.tickerPolicyEval = jitter.NewTicker(cfg.FlowLogsFlushInterval*8/10, cfg.FlowLogsFlushInterval*1/10)
	} else {
		log.Infof("Pending policies disabled")
	}

	return c
}

// ReportingChannel returns the channel used to report dataplane statistics.
func (c *collector) ReportingChannel() chan<- *proto.DataplaneStats {
	return c.ds
}

func (c *collector) Start() error {
	// The packet and conntrack info readers are essential for flow logs, but it still makes
	// sense for the collector to start without them, in order to handle DNS logs.
	if c.packetInfoReader == nil {
		log.Warning("missing PacketInfoReader")
	} else if err := c.packetInfoReader.Start(); err != nil {
		return fmt.Errorf("PacketInfoReader failed to start: %w", err)
	}
	if c.conntrackInfoReader == nil {
		log.Warning("missing ConntrackInfoReader")
	} else if err := c.conntrackInfoReader.Start(); err != nil {
		return fmt.Errorf("ConntrackInfoReader failed to start: %w", err)
	}

	go c.startStatsCollectionAndReporting()

	if apiv3.FlowLogsPolicyEvaluationModeType(c.config.PolicyEvaluationMode) == apiv3.FlowLogsPolicyEvaluationModeContinuous {
		// Processes dataplane updates into the PolicyStore.
		if c.dataplaneInfoReader != nil {
			if err := c.dataplaneInfoReader.Start(); err != nil {
				return fmt.Errorf("DataplaneInfoReader failed to start: %w", err)
			}

			go c.loopProcessingDataplaneInfoUpdates(c.dataplaneInfoReader.DataplaneInfoChan())
		} else {
			log.Warning("missing DataplaneInfoReader")
		}
	}

	// init prometheus metrics timings
	dataplaneStatsUpdateLastErrorReportTime = time.Now()

	// Start all metric reporters
	for _, r := range c.metricReporters {
		if err := r.Start(); err != nil {
			return err
		}
	}

	return nil
}

func (c *collector) RegisterMetricsReporter(mr types.Reporter) {
	c.metricReporters = append(c.metricReporters, mr)
}

func (c *collector) LogMetrics(mu metric.Update) {
	log.Tracef("Received metric update %v", mu)
	for _, r := range c.metricReporters {
		if err := r.Report(mu); err != nil {
			log.WithError(err).Debug("failed to report metric update")
		}
	}
}

func (c *collector) SetDataplaneInfoReader(dir types.DataplaneInfoReader) {
	c.dataplaneInfoReader = dir
}

func (c *collector) SetPacketInfoReader(pir types.PacketInfoReader) {
	c.packetInfoReader = pir
}

func (c *collector) SetConntrackInfoReader(cir types.ConntrackInfoReader) {
	c.conntrackInfoReader = cir
}

func (c *collector) startStatsCollectionAndReporting() {
	var (
		pktInfoC <-chan types.PacketInfo
		ctInfoC  <-chan []types.ConntrackInfo
	)

	if c.packetInfoReader != nil {
		pktInfoC = c.packetInfoReader.PacketInfoChan()
	}
	if c.conntrackInfoReader != nil {
		ctInfoC = c.conntrackInfoReader.ConntrackInfoChan()
	}

	// When a collector is started, we respond to the following events:
	// 1. StatUpdates for incoming datasources (chan c.mux).
	// 2. A signal handler that will dump logs on receiving SIGUSR2.
	// 3. A done channel for stopping and cleaning up collector (TODO).
	for {
		select {
		case ctInfos := <-ctInfoC:
			conntrackProcessStart := time.Now()
			for _, ctInfo := range ctInfos {
				log.Tracef("Collector event: %v", ctInfo)
				c.handleCtInfo(ctInfo)
			}
			histogramConntrackLatency.Observe(float64(time.Since(conntrackProcessStart).Seconds()))
		case pktInfo := <-pktInfoC:
			log.WithField("PacketInfo", pktInfo).Trace("collector event")
			c.applyPacketInfo(pktInfo)
		case <-c.ticker.Channel():
			c.checkEpStats()
		case ds := <-c.ds:
			dataplaneStatsUpdateStart := time.Now()
			c.convertDataplaneStatsAndApplyUpdate(ds)
			histogramDataplaneStatsUpdate.Observe(float64(time.Since(dataplaneStatsUpdateStart).Seconds()))
		case <-c.tickerPolicyEval.Channel():
			c.updatePendingRuleTraces()
		}
	}
}

// loopProcessingDataplaneInfoUpdates processes the dataplane info updates. The dataplaneInfoReader
// is expected to be started before calling this function.
func (c *collector) loopProcessingDataplaneInfoUpdates(dpInfoC <-chan *proto.ToDataplane) {
	for dpInfo := range dpInfoC {
		c.policyStoreManager.DoWithLock(func(ps *policystore.PolicyStore) {
			log.Debugf("Dataplane payload: %+v and sequenceNumber: %d, ", dpInfo.Payload, dpInfo.SequenceNumber)
			// Get the data and update the endpoints.
			ps.ProcessUpdate(perHostPolicySubscription, dpInfo, true)
		})
		if _, ok := dpInfo.Payload.(*proto.ToDataplane_InSync); ok {
			// Sync the policy store. This will swap the pending store to the active store. Setting the
			// pending store to nil will route the next writes to the current store.
			c.policyStoreManager.OnInSync()
		}
	}
}

// getDataAndUpdateEndpoints returns a pointer to the data structure keyed off the supplied tuple.
// If there is no entry and the tuple is for an active flow then an entry is created.
//
// This may return nil if the endpoint data does not match up with the requested data type.
//
// This method also updates the endpoint data from the cache, so beware - it is not as lightweight as a
// simple map lookup.
func (c *collector) getDataAndUpdateEndpoints(t tuple.Tuple, expired bool, packetinfo bool) *Data {
	data, exists := c.epStats[t]
	if expired {
		// If the connection has expired then return the data as is. If there is no entry, that's fine too.
		return data
	}

	// Get the source endpoint. Set the clientIP to an empty value, as it is not used for to get
	// the source endpoint.
	srcEp := c.lookupEndpoint([16]byte{}, t.Src)
	srcEpIsNotLocal := srcEp == nil || !srcEp.IsLocal()

	// Get the destination endpoint. If the source is local then we can use egress domain lookups if required.
	dstEp := c.lookupEndpoint(t.Src, t.Dst)
	dstEpIsNotLocal := dstEp == nil || !dstEp.IsLocal()

	if !exists {
		// For new entries, check that at least one of the endpoints is local.
		if srcEpIsNotLocal && dstEpIsNotLocal {
			return nil
		}

		// Ignore HEP reporters.
		if (srcEp != nil && srcEp.IsLocal() && srcEp.IsHostEndpoint()) ||
			(dstEp != nil && dstEp.IsLocal() && dstEp.IsHostEndpoint()) {
			return nil
		}

		// The entry does not exist. Go ahead and create a new one and add it to the map.
		data = NewData(t, srcEp, dstEp)
		c.updateEpStatsCache(t, data)

		// Perform an initial evaluation of pending rule traces.
		c.evaluatePendingRuleTraceForLocalEp(data)
	} else if data.Reported {
		if !data.UnreportedPacketInfo && !packetinfo {
			// Data has been reported.  If the request has not come from a packet info update (e.g. nflog) and we do not
			// have an unreported packetinfo then the endpoint data should be considered frozen.
			return data
		}

		// If the endpoints have changed then we'll need to expire the current data and possibly delete the entry if
		// if not longer represents local endpoints.
		if endpointChanged(data.SrcEp, srcEp) || endpointChanged(data.DstEp, dstEp) {
			// The endpoint information has now changed. Handle the endpoint changes.
			c.handleDataEndpointOrRulesChanged(data)

			// For updated entries, check that at least one of the endpoints is still local. If not delete the entry.
			if srcEpIsNotLocal && dstEpIsNotLocal {
				c.deleteDataFromEpStats(data)
				return nil
			}
		}

		// Update the source and dest data. We do this even if the endpoints haven't changed because the labels on the
		// endpoints may have changed and so our matches might be different.
		data.SrcEp, data.DstEp = srcEp, dstEp
	} else {
		// Data has not been reported. Don't downgrade found endpoints (in case the endpoint is deleted prior to being
		// reported).
		if srcEp != nil {
			data.SrcEp = srcEp
		}
		if dstEp != nil {
			data.DstEp = dstEp
		}
	}

	// At this point data has either not been reported or was reported and expired. If this was a packetinfo update then
	// we now have unreported packet info data. We can also update the Domains if there are any - ideally we wouldn't do
	// this for every packet update, but we need to do it early as we know some customers have DNS TTLs lower than the
	// export interval so we need to do this before we export.
	if packetinfo {
		data.UnreportedPacketInfo = true
	}

	return data
}

// endpointChanged determines if the endpoint has changed.
func endpointChanged(ep1, ep2 calc.EndpointData) bool {
	if ep1 == ep2 {
		return false
	} else if ep1 == nil {
		return ep2 != nil
	} else if ep2 == nil {
		return true
	}
	return ep1.Key() != ep2.Key()
}

func (c *collector) lookupEndpoint(clientIPBytes, ip [16]byte) calc.EndpointData {
	// Get the endpoint data for this entry.
	if ep, ok := c.luc.GetEndpoint(ip); ok {
		return ep
	}

	// No matching endpoint. If NetworkSets are enabled for flows then check if the IP matches a NetworkSet and
	// return that.
	if c.config.EnableNetworkSets {
		if ep, ok := c.luc.GetNetworkSet(ip); ok {
			return ep
		}
	}
	return nil
}

// updateEpStatsCache updates/add entry to the epStats cache (map[Tuple]*Data) and update the
// prometheus reporting
func (c *collector) updateEpStatsCache(t tuple.Tuple, data *Data) {
	c.epStats[t] = data
	c.reportEpStatsCacheMetrics()
}

// reportEpStatsCacheMetrics reports of current epStats cache status to Prometheus
func (c *collector) reportEpStatsCacheMetrics() {
	gaugeEpStatsCacheSizeLength.Set(float64(len(c.epStats)))
}

// applyConntrackStatUpdate applies a stats update from a conn track poll.
// If entryExpired is set then, this means that the update is for a recently
// expired entry. One of the following will be done:
//   - If we already track the tuple, then the stats will be updated and will
//     then be expired from epStats.
//   - If we don't track the tuple, this call will be a no-op as this update
//     is just waiting for the conntrack entry to timeout.
func (c *collector) applyConntrackStatUpdate(
	data *Data,
	packets int,
	bytes int,
	reversePackets int,
	reverseBytes int,
	entryExpired bool,
) {
	if data != nil {
		data.SetConntrackCounters(packets, bytes)
		data.SetConntrackCountersReverse(reversePackets, reverseBytes)

		if entryExpired {
			// The connection has expired. if the metrics can be reported then report and expire them now.
			// Otherwise, flag as expired and allow the export timer to process the connection - this allows additional
			// time for asynchronous meta data to be gathered (such as service info and process info).
			if c.reportMetrics(data, false) {
				c.expireMetrics(data)
				c.deleteDataFromEpStats(data)
			} else {
				data.SetExpired()
			}
		}
	}
}

// applyNflogStatUpdate applies a stats update from an NFLOG.
func (c *collector) applyNflogStatUpdate(data *Data, ruleID *calc.RuleID, matchIdx, numPkts, numBytes int) {
	var ru RuleMatch
	if ru = data.AddRuleID(ruleID, matchIdx, numPkts, numBytes); ru == RuleMatchIsDifferent {
		c.handleDataEndpointOrRulesChanged(data)
		data.ReplaceRuleID(ruleID, matchIdx, numPkts, numBytes)
	}
}

func (c *collector) handleDataEndpointOrRulesChanged(data *Data) {
	// The endpoints or rule matched have changed. If reported then expire the metrics and update the
	// endpoint data.
	if c.reportMetrics(data, false) {
		// We only need to expire metric entries that've probably been reported
		// in the first place.
		c.expireMetrics(data)

		// Reset counters and replace the rule.
		data.ResetConntrackCounters()
		// Set reported to false so the data can be updated without further reports.
		data.Reported = false
	}
}

func (c *collector) checkEpStats() {
	// We report stats at initial reporting delay after the last rule update. This aims to ensure we have the full set
	// of data before we report the stats. As a minor finesse, pre-calculate the latest update time to consider reporting.
	minLastRuleUpdatedAt := monotime.Now() - c.config.InitialReportingDelay

	now := monotime.Now()
	minExpirationAt := now - c.config.AgeTimeout

	// For each entry
	// - report metrics.  Metrics reported through the ticker processing will wait for the initial reporting delay
	//   before reporting.  Note that this may be short-circuited by conntrack events or nflog events that inidicate
	//   the flow is terminated or has changed.
	// - check age and expire the entry if needed.
	for _, data := range c.epStats {
		if c.config.IsBPFDataplane {
			switch data.Tuple.Proto {
			case 6 /* TCP */ :
				// We use reset because likely already cleaned it up as an expired
				// connection if we haven't seen any update this long.
				minExpirationAt = now - c.config.BPFConntrackTimeouts.TCPResetSeen
			case 17 /* UDP */ :
				minExpirationAt = now - c.config.BPFConntrackTimeouts.UDPTimeout
			case 1 /* ICMP */, 58 /* ICMPv6 */ :
				minExpirationAt = now - c.config.BPFConntrackTimeouts.ICMPTimeout
			default:
				minExpirationAt = now - c.config.BPFConntrackTimeouts.GenericTimeout
			}
			if minExpirationAt < 2*bpfconntrack.ScanPeriod {
				minExpirationAt = now - 2*bpfconntrack.ScanPeriod
			}
		}

		if data.IsDirty() && (data.Reported || data.RuleUpdatedAt() < minLastRuleUpdatedAt) {
			c.checkPreDNATTuple(data)
			c.reportMetrics(data, true)
		}
		if data.UpdatedAt() < minExpirationAt {
			c.expireMetrics(data)
			c.deleteDataFromEpStats(data)
		}
	}
}

func (c *collector) checkPreDNATTuple(data *Data) {
	preDNATTuple, err := data.PreDNATTuple()
	if err != nil {
		return
	}
	preDNATData, ok := c.epStats[preDNATTuple]
	if !ok {
		return
	}
	log.Debugf("Found data that resembles PreDNAT connection data->%+v, preDNATData->%+v", data, preDNATData)

	// If we are tracking a denied connection attempt that has the same tuple as the
	// pre-DNAT tuple of a similar allowed connection then make sure that we expire the
	// tuple that looks like the pre-DNAT tuple. This guards us against a scenario where
	// the first tracked tuple that looks like the preDNAT tuple of a long running connection
	// never expires when TCP stats are enabled.
	// We don't worry about a allowed connection becoming denied because we don't currently
	// delete an already established connection.
	// We only try to report a metric when
	// - the tuple that looks like the pre DNAT tuple is not a connection i.e, we only received NFLOGs.
	// - Both ingress and egress rule trace is not dirty. Otherwise we want to let the usual report metrics
	//   go ahead first as this cleanup here is a last resort.
	if !preDNATData.IsConnection && !preDNATData.EgressRuleTrace.IsDirty() && !preDNATData.IngressRuleTrace.IsDirty() {
		c.reportMetrics(preDNATData, true)
		c.expireMetrics(preDNATData)
		c.deleteDataFromEpStats(preDNATData)
	}
}

// reportMetrics reports the metrics if all required data is present, or returns false if not reported.
// Set the force flag to true if the data should be reported before all asynchronous data is collected.
func (c *collector) reportMetrics(data *Data, force bool) bool {
	foundService := true

	if !data.Reported {
		// Check if the destination was accessed via a service. Once reported, this will not be updated again.
		if data.DstSvc.Name == "" {
			if data.IsDNAT {
				// Destination is NATed, look up service from the pre-DNAT record.
				data.DstSvc, foundService = c.luc.GetServiceFromPreDNATDest(data.PreDNATAddr, data.PreDNATPort, data.Tuple.Proto)
			} else if _, ok := c.luc.GetNode(data.Tuple.Dst); ok {
				// Destination is a node, so could be a node port service.
				data.DstSvc, foundService = c.luc.GetNodePortService(data.Tuple.L4Dst, data.Tuple.Proto)
			}
		}
		if !force {
			// If not forcing then return if:
			// - There may be a service to report
			// - The verdict rules have not been found for the local endpoints
			// - The remote endpoint is not known (which could potentially resolve to a DNS name or NetworkSet).
			// In this case data will be reported later during ticker processing.
			if !foundService || !data.VerdictFound() || data.DstEp == nil {
				log.Debug("Service not found - delay statistics reporting until normal flush processing")
				return false
			}
		}
	}

	// Send the metrics.
	c.sendMetrics(data, false)
	data.Reported = true
	return true
}

func (c *collector) expireMetrics(data *Data) {
	if data.Reported {
		c.sendMetrics(data, true)
	}
}

func (c *collector) deleteDataFromEpStats(data *Data) {
	delete(c.epStats, data.Tuple)

	c.reportEpStatsCacheMetrics()
}

func (c *collector) sendMetrics(data *Data, expired bool) {
	ut := metric.UpdateTypeReport
	if expired {
		ut = metric.UpdateTypeExpire
	}
	// For connections and non-connections, we only send ingress and egress updates if:
	// -  There is something to report, i.e.
	//    -  flow is expired, or
	//    -  associated stats are dirty
	// -  The policy verdict rule has been determined. Note that for connections the policy verdict may be "Deny" due
	//    to DropActionOverride setting (e.g. if set to ALLOW, then we'll get connection stats, but the metrics will
	//    indicate Denied).
	// Only clear the associated stats and dirty flag once the metrics are reported.
	if data.IsConnection {
		// Report connection stats.
		if expired || data.IsDirty() {
			// Track if we need to send a separate expire metric update. This is required when we are only
			// reporting Original IP metric updates and want to send a corresponding expiration metric update.
			// When they are correlated with regular metric updates and connection metrics, we don't need to
			// send this.
			if data.EgressRuleTrace.FoundVerdict() {
				c.LogMetrics(data.MetricUpdateEgressConn(ut))
			}
			if data.IngressRuleTrace.FoundVerdict() {
				c.LogMetrics(data.MetricUpdateIngressConn(ut))
			}

			// Clear the connection dirty flag once the stats have been reported. Note that we also clear the
			// rule trace stats here too since any data stored in them has been superceded by the connection
			// stats.
			data.ClearConnDirtyFlag()
			data.EgressRuleTrace.ClearDirtyFlag()
			data.IngressRuleTrace.ClearDirtyFlag()
		}
	} else {
		// Report rule trace stats.
		if (expired || data.EgressRuleTrace.IsDirty()) && data.EgressRuleTrace.FoundVerdict() {
			c.LogMetrics(data.MetricUpdateEgressNoConn(ut))
			data.EgressRuleTrace.ClearDirtyFlag()
		}
		if (expired || data.IngressRuleTrace.IsDirty()) && data.IngressRuleTrace.FoundVerdict() {
			c.LogMetrics(data.MetricUpdateIngressNoConn(ut))
			data.IngressRuleTrace.ClearDirtyFlag()
		}

		// We do not need to clear the connection stats here. Connection stats are fully reset if the Data moves
		// from a connection to non-connection state.
	}
	data.UnreportedPacketInfo = false
}

// handleCtInfo handles an update from conntrack
// We expect and process connections (conntrack entries) of 3 different flavors.
//
// - Connections that *neither* begin *nor* terminate locally.
// - Connections that either begin or terminate locally.
// - Connections that begin *and* terminate locally.
//
// When processing these, we also check if the connection is flagged as a
// destination NAT (DNAT) connection. If it is a DNAT-ed connection, we
// process the conntrack entry after we figure out the DNAT-ed destination and port.
// This is important for services where the connection will have the cluster IP as the
// pre-DNAT-ed destination, but we want the post-DNAT workload IP and port.
// The pre-DNAT entry will also be used to lookup service related information.
func (c *collector) handleCtInfo(ctInfo types.ConntrackInfo) {
	// Get or create a data entry and update the counters. If no entry is returned then neither source nor dest are
	// calico managed endpoints. A relevant conntrack entry requires at least one of the endpoints to be a local
	// Calico managed endpoint.

	if data := c.getDataAndUpdateEndpoints(ctInfo.Tuple, ctInfo.Expired, false); data != nil {

		if !data.IsDNAT && ctInfo.IsDNAT {
			originalTuple := ctInfo.PreDNATTuple
			data.IsDNAT = true
			data.PreDNATAddr = originalTuple.Dst
			data.PreDNATPort = originalTuple.L4Dst
		}
		data.NatOutgoingPort = ctInfo.NatOutgoingPort

		c.applyConntrackStatUpdate(data,
			ctInfo.Counters.Packets, ctInfo.Counters.Bytes,
			ctInfo.ReplyCounters.Packets, ctInfo.ReplyCounters.Bytes,
			ctInfo.Expired)
	}
}

func (c *collector) applyPacketInfo(pktInfo types.PacketInfo) {
	var (
		localEp        calc.EndpointData
		localMatchData *calc.MatchData
		data           *Data
	)

	t := pktInfo.Tuple

	if data = c.getDataAndUpdateEndpoints(t, false, true); data == nil {
		// Data is nil, so the destination endpoint cannot be managed by local Calico.
		return
	}

	if !data.IsDNAT && pktInfo.IsDNAT {
		originalTuple := pktInfo.PreDNATTuple
		data.IsDNAT = true
		data.PreDNATAddr = originalTuple.Dst
		data.PreDNATPort = originalTuple.L4Dst
	}

	// Determine the local endpoint for this update.
	switch pktInfo.Direction {
	case rules.RuleDirIngress:
		// The local destination should be local.
		if localEp = data.DstEp; localEp == nil || !localEp.IsLocal() {
			return
		}
		localMatchData = localEp.IngressMatchData()
	case rules.RuleDirEgress:
		// The cache will return nil for egress if the source endpoint is not local.
		if localEp = data.SrcEp; localEp == nil || !localEp.IsLocal() {
			return
		}
		localMatchData = localEp.EgressMatchData()
	default:
		return
	}

	for _, rule := range pktInfo.RuleHits {
		ruleID := rule.RuleID
		if ruleID == nil {
			continue
		}
		if ruleID.IsProfile() {
			// This is a profile verdict. Apply the rule unchanged, but at the profile match index (which is at the
			// very end of the match slice).
			c.applyNflogStatUpdate(data, ruleID, localMatchData.ProfileMatchIndex, rule.Hits, rule.Bytes)
			continue
		}

		if ruleID.IsEndOfTier() {
			// This is an end-of-tier action.
			// -  For deny convert the ruleID to the implicit drop rule
			// -  For pass leave the rule unchanged. We never return this to the user, but instead use it to determine
			//    whether we add staged policy end-of-tier denies.
			// For both deny and pass, add the rule at the end of tier match index.
			tier, ok := localMatchData.TierData[ruleID.Tier]
			if !ok {
				continue
			}

			switch ruleID.Action {
			case rules.RuleActionDeny:
				c.applyNflogStatUpdate(
					data, tier.TierDefaultActionRuleID, tier.EndOfTierMatchIndex,
					rule.Hits, rule.Bytes,
				)
			case rules.RuleActionPass:
				// If TierDefaultActionRuleID is nil, then endpoint is unmatched, and is hitting tier default Pass action.
				// We do not generate flow log for this case.
				// If TierDefaultActionRuleID is not nil, then endpoint is matched, and is hitting tier default Pass action.
				// A flow log is generated for it.
				if tier.TierDefaultActionRuleID == nil {
					c.applyNflogStatUpdate(
						data, ruleID, tier.EndOfTierMatchIndex,
						rule.Hits, rule.Bytes,
					)
				} else {
					c.applyNflogStatUpdate(
						data, tier.TierDefaultActionRuleID, tier.EndOfTierMatchIndex,
						rule.Hits, rule.Bytes,
					)
				}
			}
			continue
		}

		// This is one of:
		// -  An enforced rule match
		// -  A staged policy match
		// -  A staged policy miss
		// -  An end-of-tier pass (from tiers only containing staged policies)
		//
		// For all these cases simply add the unchanged ruleID using the match index reserved for that policy.
		// Extract the policy data from the ruleID.
		policyIdx, ok := localMatchData.PolicyMatches[ruleID.PolicyID]
		if !ok {
			continue
		}

		c.applyNflogStatUpdate(data, ruleID, policyIdx, rule.Hits, rule.Bytes)
	}

	if data.Expired && c.reportMetrics(data, false) {
		// If the data is expired then attempt to report it now so that we can remove the connection entry. If reported
		// the data can be expired and deleted immediately, otherwise it will get exported during ticker processing.
		c.expireMetrics(data)
		c.deleteDataFromEpStats(data)
	}
}

// convertDataplaneStatsAndApplyUpdate merges the proto.DataplaneStatistics into the current
// data stored for the specific connection tuple.
func (c *collector) convertDataplaneStatsAndApplyUpdate(d *proto.DataplaneStats) {
	log.Tracef("Received dataplane stats update %+v", d)
	// Create a Tuple representing the DataplaneStats.
	t, err := extractTupleFromDataplaneStats(d)
	if err != nil {
		log.Errorf("unable to extract 5-tuple from DataplaneStats: %v", err)
		reportDataplaneStatsUpdateErrorMetrics(1)
		return
	}

	// Locate the data for this connection, creating if not yet available (it's possible to get an update
	// from the dataplane before nflogs or conntrack).
	_ = c.getDataAndUpdateEndpoints(t, false, false)
}

// updatePendingRuleTraces evaluates each flow of epStats against the policies in the PolicyStore
// to get the latest pending rule trace. It replaces the Data's copy if they are different.
func (c *collector) updatePendingRuleTraces() {
	// The epStats map may be quite large, so we chose to lock each entry individually to avoid
	// locking the entire map.
	for _, data := range c.epStats {
		if data == nil {
			continue
		}
		c.evaluatePendingRuleTraceForLocalEp(data)
	}
}

func (c *collector) evaluatePendingRuleTraceForLocalEp(data *Data) {
	flow := TupleAsFlow(data.Tuple)

	srcEp := c.lookupEndpoint([16]byte{}, data.Tuple.Src)
	srcEpIsNotLocal := srcEp == nil || !srcEp.IsLocal()

	dstEp := c.lookupEndpoint(data.Tuple.Src, data.Tuple.Dst)
	dstEpIsNotLocal := dstEp == nil || !dstEp.IsLocal()

	// If neither endpoint is local, skip evaluation.
	if srcEpIsNotLocal && dstEpIsNotLocal {
		return
	}
	// If endpoints have changed compared to what Data currently holds, skip evaluation.
	if endpointChanged(data.SrcEp, srcEp) || endpointChanged(data.DstEp, dstEp) {
		return
	}

	c.policyStoreManager.DoWithReadLock(func(ps *policystore.PolicyStore) {
		// Evaluate ingress if destination is local workload endpoint
		if data.DstEp != nil && !data.DstEp.IsHostEndpoint() && data.DstEp.IsLocal() {
			c.evaluatePendingRuleTrace(rules.RuleDirIngress, ps, data.DstEp, flow, &data.IngressPendingRuleIDs)
		}

		// Evaluate egress if source is local workload endpoint
		if data.SrcEp != nil && !data.SrcEp.IsHostEndpoint() && data.SrcEp.IsLocal() {
			c.evaluatePendingRuleTrace(rules.RuleDirEgress, ps, data.SrcEp, flow, &data.EgressPendingRuleIDs)
		}
	})
}

// evaluatePendingRuleTrace evaluates the pending rule trace for the given direction and endpoint,
// and updates the ruleIDs if they are different.
func (c *collector) evaluatePendingRuleTrace(direction rules.RuleDir, store *policystore.PolicyStore, ep calc.EndpointData, flow TupleAsFlow, ruleIDs *[]*calc.RuleID) {
	// Get the proto.WorkloadEndpoint, needed for the evaluation, from the policy store.
	if protoEp := c.lookupProtoWorkloadEndpoint(store, ep.Key()); protoEp != nil {
		trace := checker.Evaluate(direction, store, protoEp, &flow)
		if !equal(*ruleIDs, trace) {
			*ruleIDs = append([]*calc.RuleID(nil), trace...)
			log.Tracef("Updated pending %s, tuple: %v, rule trace: %v", direction, flow, ruleIDs)
		}
	} else {
		log.WithField("endpoint", ep.Key()).Trace("The endpoint is not yet tracked by the PolicyStore")
	}
}

// lookupProtoWorkloadEndpoint returns the proto.WorkloadEndpoint from the policy store. Must be
// called with the read lock on the policy store.
func (c *collector) lookupProtoWorkloadEndpoint(store *policystore.PolicyStore, key model.Key) *proto.WorkloadEndpoint {
	if store == nil || store.Endpoints == nil {
		return nil
	}
	epKey := prototypes.WorkloadEndpointID{
		OrchestratorId: getOrchestratorIDFromKey(key),
		WorkloadId:     getWorkloadIDFromKey(key),
		EndpointId:     getEndpointIDFromKey(key),
	}
	return store.Endpoints[epKey]
}

func extractTupleFromDataplaneStats(d *proto.DataplaneStats) (tuple.Tuple, error) {
	var protocol int32
	switch n := d.Protocol.GetNumberOrName().(type) {
	case *proto.Protocol_Number:
		protocol = n.Number
	case *proto.Protocol_Name:
		switch strings.ToLower(n.Name) {
		case "tcp":
			protocol = 6
		case "udp":
			protocol = 17
		default:
			reportDataplaneStatsUpdateErrorMetrics(1)
			return tuple.Tuple{}, fmt.Errorf("unhandled protocol: %s", n)
		}
	}

	// Use the standard go net library to parse the IP since this always returns IPs as 16 bytes.
	srcIP, ok := ip.ParseIPAs16Byte(d.SrcIp)
	if !ok {
		reportDataplaneStatsUpdateErrorMetrics(1)
		return tuple.Tuple{}, fmt.Errorf("bad source IP: %s", d.SrcIp)
	}
	dstIP, ok := ip.ParseIPAs16Byte(d.DstIp)
	if !ok {
		reportDataplaneStatsUpdateErrorMetrics(1)
		return tuple.Tuple{}, fmt.Errorf("bad destination IP: %s", d.DstIp)
	}

	// Locate the data for this connection, creating if not yet available (it's possible to get an update
	// before nflogs or conntrack).
	return tuple.Make(srcIP, dstIP, int(protocol), int(d.SrcPort), int(d.DstPort)), nil
}

// reportDataplaneStatsUpdateErrorMetrics reports error statistics encoutered when updating Dataplane stats
func reportDataplaneStatsUpdateErrorMetrics(dataplaneErrorDelta uint32) {
	if dataplaneStatsUpdateLastErrorReportTime.Before(time.Now().Add(-1 * time.Minute)) {
		dataplaneStatsUpdateErrorsInLastMinute = dataplaneErrorDelta
	} else {
		dataplaneStatsUpdateErrorsInLastMinute += dataplaneErrorDelta
	}
	dataplaneStatsUpdateErrorsInLastMinute += dataplaneErrorDelta
	gaugeDataplaneStatsUpdateErrorsPerMinute.Set(float64(dataplaneStatsUpdateErrorsInLastMinute))
}

// Logrus Formatter that strips the log entry of formatting such as time, log
// level and simply outputs *only* the message.
type MessageOnlyFormatter struct{}

func (f *MessageOnlyFormatter) Format(entry *log.Entry) ([]byte, error) {
	b := &bytes.Buffer{}
	b.WriteString(entry.Message)
	b.WriteByte('\n')
	return b.Bytes(), nil
}

// equal returns true if the rule IDs are equal. The order of the content should also the same for
// equal to return true.
func equal(a, b []*calc.RuleID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equals(b[i]) {
			return false
		}
	}
	return true
}

// getEndpointIDFromKey returns the endpoint ID from the given key.
func getEndpointIDFromKey(key model.Key) string {
	switch k := key.(type) {
	case model.WorkloadEndpointKey:
		return k.EndpointID
	default:
		return ""
	}
}

// getOrchestratorIDFromKey returns the orchestrator ID from the given key.
func getOrchestratorIDFromKey(key model.Key) string {
	switch k := key.(type) {
	case model.WorkloadEndpointKey:
		return k.OrchestratorID
	default:
		return ""
	}
}

// getWorkloadIDFromKey returns the workload ID from the given key.
func getWorkloadIDFromKey(key model.Key) string {
	switch k := key.(type) {
	case model.WorkloadEndpointKey:
		return k.WorkloadID
	default:
		return ""
	}
}
