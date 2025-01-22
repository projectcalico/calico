// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector/types/boundedset"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	logutil "github.com/projectcalico/calico/felix/logutils"
)

const (
	unsetIntField = -1
)

type empty struct{}

var emptyValue = empty{}

var (
	emptyService = FlowService{"-", "-", "-", 0}
	emptyIP      = [16]byte{}
)

type (
	Action       string
	ReporterType string
)

type FlowService struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	PortName  string `json:"port_name"`
	PortNum   int    `json:"port_num"`
}

type FlowMeta struct {
	Tuple      tuple.Tuple       `json:"tuple"`
	SrcMeta    endpoint.Metadata `json:"sourceMeta"`
	DstMeta    endpoint.Metadata `json:"destinationMeta"`
	DstService FlowService       `json:"destinationService"`
	Action     Action            `json:"action"`
	Reporter   ReporterType      `json:"flowReporter"`
}

func newFlowMeta(mu metric.Update, includeService bool) (FlowMeta, error) {
	f := FlowMeta{}

	// Extract Tuple Info
	f.Tuple = mu.Tuple

	// Extract EndpointMetadata info
	srcMeta, err := endpoint.GetMetadata(mu.SrcEp, mu.Tuple.Src)
	if err != nil {
		return FlowMeta{}, fmt.Errorf("could not extract metadata for source %v", mu.SrcEp)
	}
	dstMeta, err := endpoint.GetMetadata(mu.DstEp, mu.Tuple.Dst)
	if err != nil {
		return FlowMeta{}, fmt.Errorf("could not extract metadata for destination %v", mu.DstEp)
	}

	f.SrcMeta = srcMeta
	f.DstMeta = dstMeta

	if includeService {
		f.DstService = getService(mu.DstService)
	} else {
		f.DstService = emptyService
	}

	lastRuleID := mu.GetLastRuleID()
	if lastRuleID == nil {
		log.WithField("metric update", mu).Error("no rule id present")
		return f, fmt.Errorf("invalid metric update")
	}

	action, direction := getActionAndReporterFromRuleID(lastRuleID)
	f.Action = action
	f.Reporter = direction
	return f, nil
}

func newFlowMetaWithPrefixNameAggregation(mu metric.Update, includeService bool) (FlowMeta, error) {
	f, err := newFlowMeta(mu, includeService)
	if err != nil {
		return FlowMeta{}, err
	}
	f.Tuple.Src = emptyIP
	f.Tuple.L4Src = unsetIntField
	f.Tuple.Dst = emptyIP
	f.SrcMeta.Name = FieldNotIncluded
	f.DstMeta.Name = FieldNotIncluded
	return f, nil
}

func NewFlowMeta(mu metric.Update, _ AggregationKind, includeService bool) (FlowMeta, error) {
	return newFlowMetaWithPrefixNameAggregation(mu, includeService)
}

type FlowSpec struct {
	FlowStatsByProcess
	flowExtrasRef
	FlowLabels
	FlowPolicySets

	// Reset aggregated data on the next metric update to ensure we clear out obsolete labels, policies and Domains for
	// connections that are not actively part of the flow during the export interval.
	resetAggrData bool
}

func NewFlowSpec(mu *metric.Update, maxOriginalIPsSize int, displayDebugTraceLogs bool, natOutgoingPortLimit int) *FlowSpec {
	// NewFlowStatsByProcess potentially needs to update fields in mu *metric.Update hence passing it by pointer
	// TODO: reconsider/refactor the inner functions called in NewFlowStatsByProcess to avoid above scenario
	return &FlowSpec{
		FlowLabels:         NewFlowLabels(*mu),
		FlowPolicySets:     NewFlowPolicySets(*mu),
		FlowStatsByProcess: NewFlowStatsByProcess(mu, displayDebugTraceLogs, natOutgoingPortLimit),
		flowExtrasRef:      NewFlowExtrasRef(*mu, maxOriginalIPsSize),
	}
}

func (f *FlowSpec) ContainsActiveRefs(mu *metric.Update) bool {
	return f.FlowStatsByProcess.containsActiveRefs(mu)
}

func (f *FlowSpec) ToFlowLogs(fm FlowMeta, startTime, endTime time.Time, includeLabels bool, includePolicies bool) []*FlowLog {
	stats := f.FlowStatsByProcess.toFlowProcessReportedStats()

	flogs := make([]*FlowLog, 0, len(stats))
	for _, stat := range stats {
		fl := &FlowLog{
			FlowMeta:                 fm,
			StartTime:                startTime,
			EndTime:                  endTime,
			FlowProcessReportedStats: stat,
		}
		if f.flowExtrasRef.originalSourceIPs != nil {
			fe := FlowExtras{
				OriginalSourceIPs:    f.flowExtrasRef.originalSourceIPs.ToIPSlice(),
				NumOriginalSourceIPs: f.flowExtrasRef.originalSourceIPs.TotalCount(),
			}
			fl.FlowExtras = fe
		}

		if includeLabels {
			fl.FlowLabels = f.FlowLabels
		}

		if !includePolicies {
			fl.FlowPolicySet = nil
			flogs = append(flogs, fl)
		} else {
			if len(f.FlowPolicySets) > 1 {
				log.WithField("FlowLog", fl).Warning("Flow was split into multiple flow logs since multiple policy sets were observed for the same flow. Possible causes: policy updates during log aggregation or NFLOG buffer overruns.")
			}
			for _, fp := range f.FlowPolicySets {
				cpfl := *fl
				cpfl.FlowPolicySet = fp
				flogs = append(flogs, &cpfl)
			}
		}

	}
	return flogs
}

func (f *FlowSpec) AggregateMetricUpdate(mu *metric.Update) {
	if f.resetAggrData {
		// Reset the aggregated data from this metric update.
		f.FlowPolicySets = make(FlowPolicySets, 0)
		f.FlowLabels.SrcLabels = nil
		f.FlowLabels.DstLabels = nil
		f.resetAggrData = false
	}
	f.aggregateFlowLabels(*mu)
	f.aggregateFlowPolicySets(*mu)
	f.aggregateFlowExtrasRef(*mu)
	f.aggregateFlowStatsByProcess(mu)
}

// MergeWith merges two flow specs. This means copying the flowRefsActive that contains a reference
// to the original tuple that identifies the traffic. This help keeping the same numFlows counts while
// changing aggregation levels
func (f *FlowSpec) MergeWith(mu metric.Update, other *FlowSpec) {
	if stats, ok := f.statsByProcessName[FieldNotIncluded]; ok {
		if otherStats, ok := other.statsByProcessName[FieldNotIncluded]; ok {
			for tuple := range otherStats.flowsRefsActive {
				stats.flowsRefsActive.AddWithValue(tuple, mu.NatOutgoingPort)
				stats.flowsRefs.AddWithValue(tuple, mu.NatOutgoingPort)
			}
			stats.NumFlows = stats.flowsRefs.Len()
		}
	}
}

// FlowSpec has FlowStats that are stats assocated with a given FlowMeta
// These stats are to be refreshed everytime the FlowData
// {FlowMeta->FlowStats} is published so as to account
// for correct no. of started flows in a given aggregation
// interval.
//
// This also resets policy and label data which will be re-populated from metric updates for the still active
// flows.
func (f *FlowSpec) Reset() {
	f.FlowStatsByProcess.reset()
	f.flowExtrasRef.reset()

	// Set the reset flag. We'll reset the aggregated data on the next metric update - that way we don't completely
	// zero out the labels and policies if there is no traffic for an export interval.
	f.resetAggrData = true
}

func (f *FlowSpec) GetActiveFlowsCount() int {
	return f.FlowStatsByProcess.getActiveFlowsCount()
}

// GarbageCollect provides a chance to remove process names and corresponding stats that don't have
// any active flows being tracked.
// As an added optimization, we also return the remaining active flows so that we don't have to
// iterate over all the flow stats grouped by processes a second time.
func (f *FlowSpec) GarbageCollect() int {
	return f.FlowStatsByProcess.gc()
}

type FlowLabels struct {
	SrcLabels map[string]string
	DstLabels map[string]string
}

func NewFlowLabels(mu metric.Update) FlowLabels {
	return FlowLabels{
		SrcLabels: endpoint.GetLabels(mu.SrcEp),
		DstLabels: endpoint.GetLabels(mu.DstEp),
	}
}

func (f *FlowLabels) aggregateFlowLabels(mu metric.Update) {
	srcLabels := endpoint.GetLabels(mu.SrcEp)
	dstLabels := endpoint.GetLabels(mu.DstEp)

	// The flow labels are reset on calibration, so either copy the labels or intersect them.
	if f.SrcLabels == nil {
		f.SrcLabels = srcLabels
	} else {
		f.SrcLabels = utils.IntersectLabels(srcLabels, f.SrcLabels)
	}

	if f.DstLabels == nil {
		f.DstLabels = dstLabels
	} else {
		f.DstLabels = utils.IntersectLabels(dstLabels, f.DstLabels)
	}
}

type FlowPolicySet map[string]empty

func newFlowPolicySet(mu metric.Update) FlowPolicySet {
	fp := make(FlowPolicySet)
	if mu.RuleIDs == nil {
		return fp
	}
	for idx, rid := range mu.RuleIDs {
		if rid == nil {
			continue
		}
		fp[fmt.Sprintf("%d|%s|%s", idx, rid.GetFlowLogPolicyName(), rid.IndexStr)] = emptyValue
	}
	return fp
}

// FlowPolicySets is used to keep track of multiple policy traces that are associated with a flow.
// This is useful when a flow is associated with multiple policy sets.
type FlowPolicySets []FlowPolicySet

func NewFlowPolicySets(mu metric.Update) FlowPolicySets {
	fp := newFlowPolicySet(mu)

	fpl := FlowPolicySets{}
	fpl = append(fpl, fp)

	return fpl
}

func (fpl *FlowPolicySets) aggregateFlowPolicySets(mu metric.Update) {
	fp := newFlowPolicySet(mu)

	for _, p := range *fpl {
		if reflect.DeepEqual(p, fp) {
			return
		}
	}

	*fpl = append(*fpl, fp)
}

type flowExtrasRef struct {
	originalSourceIPs *boundedset.BoundedSet
}

func NewFlowExtrasRef(mu metric.Update, maxOriginalIPsSize int) flowExtrasRef {
	var osip *boundedset.BoundedSet
	if mu.OrigSourceIPs != nil {
		osip = boundedset.NewFromSliceWithTotalCount(maxOriginalIPsSize, mu.OrigSourceIPs.ToIPSlice(), mu.OrigSourceIPs.TotalCount())
	} else {
		osip = boundedset.New(maxOriginalIPsSize)
	}
	return flowExtrasRef{originalSourceIPs: osip}
}

func (fer *flowExtrasRef) aggregateFlowExtrasRef(mu metric.Update) {
	if mu.OrigSourceIPs != nil {
		fer.originalSourceIPs.Combine(mu.OrigSourceIPs)
	}
}

func (fer *flowExtrasRef) reset() {
	if fer.originalSourceIPs != nil {
		fer.originalSourceIPs.Reset()
	}
}

// FlowExtras contains some additional useful information for flows.
type FlowExtras struct {
	OriginalSourceIPs    []net.IP `json:"originalSourceIPs"`
	NumOriginalSourceIPs int      `json:"numOriginalSourceIPs"`
}

// flowReferences are internal only stats used for computing numbers of flows
type flowReferences struct {
	// The set of unique flows that were started within the reporting interval. This is added to when a new flow
	// (i.e. one that is not currently active) is reported during the reporting interval. It is reset when the
	// flow data is reported.
	flowsStartedRefs tuple.Set
	// The set of unique flows that were completed within the reporting interval. This is added to when a flow
	// termination is reported during the reporting interval. It is reset when the flow data is reported.
	flowsCompletedRefs tuple.Set
	// The current set of active flows. The set may increase and decrease during the reporting interval.
	flowsRefsActive tuple.Set
	// The set of unique flows that have been active at any point during the reporting interval. This is added
	// to during the reporting interval, and is reset to the set of active flows when the flow data is reported.
	flowsRefs tuple.Set
}

// FlowReportedStats are the statistics we actually report out in flow logs.
type FlowReportedStats struct {
	PacketsIn         int `json:"packetsIn"`
	PacketsOut        int `json:"packetsOut"`
	BytesIn           int `json:"bytesIn"`
	BytesOut          int `json:"bytesOut"`
	NumFlows          int `json:"numFlows"`
	NumFlowsStarted   int `json:"numFlowsStarted"`
	NumFlowsCompleted int `json:"numFlowsCompleted"`
}

func (f *FlowReportedStats) Add(other FlowReportedStats) {
	f.PacketsIn += other.PacketsIn
	f.PacketsOut += other.PacketsOut
	f.BytesIn += other.BytesIn
	f.BytesOut += other.BytesOut
	f.NumFlows += other.NumFlows
	f.NumFlowsStarted += other.NumFlowsStarted
	f.NumFlowsCompleted += other.NumFlowsCompleted
}

// FlowStats captures stats associated with a given FlowMeta.
type FlowStats struct {
	FlowReportedStats
	flowReferences
}

func NewFlowStats(mu metric.Update) FlowStats {
	flowsRefs := tuple.NewSet()
	flowsRefs.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
	flowsStartedRefs := tuple.NewSet()
	flowsCompletedRefs := tuple.NewSet()
	flowsRefsActive := tuple.NewSet()

	switch mu.UpdateType {
	case metric.UpdateTypeReport:
		flowsStartedRefs.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
		flowsRefsActive.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
	case metric.UpdateTypeExpire:
		flowsCompletedRefs.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
	}

	flowStats := FlowStats{
		FlowReportedStats: FlowReportedStats{
			NumFlows:          flowsRefs.Len(),
			NumFlowsStarted:   flowsStartedRefs.Len(),
			NumFlowsCompleted: flowsCompletedRefs.Len(),
			PacketsIn:         mu.InMetric.DeltaPackets,
			BytesIn:           mu.InMetric.DeltaBytes,
			PacketsOut:        mu.OutMetric.DeltaPackets,
			BytesOut:          mu.OutMetric.DeltaBytes,
		},
		flowReferences: flowReferences{
			// flowsRefs track the flows that were tracked
			// in the give interval
			flowsRefs:          flowsRefs,
			flowsStartedRefs:   flowsStartedRefs,
			flowsCompletedRefs: flowsCompletedRefs,
			// flowsRefsActive tracks the active (non-completed)
			// flows associated with the flowMeta
			flowsRefsActive: flowsRefsActive,
		},
	}
	return flowStats
}

func (f *FlowStats) aggregateFlowStats(mu metric.Update, displayDebugTraceLogs bool) {
	switch {
	case mu.UpdateType == metric.UpdateTypeReport:
		// Add / update the flowStartedRefs if we either haven't seen this tuple before OR the tuple is already in the
		// flowStartRefs (we may have an updated value).
		if !f.flowsRefsActive.Contains(mu.Tuple) || f.flowsStartedRefs.Contains(mu.Tuple) {
			f.flowsStartedRefs.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
		}

		f.flowsRefsActive.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
	case mu.UpdateType == metric.UpdateTypeExpire:
		f.flowsCompletedRefs.AddWithValue(mu.Tuple, mu.NatOutgoingPort)
		f.flowsRefsActive.Discard(mu.Tuple)
	}
	f.flowsRefs.AddWithValue(mu.Tuple, mu.NatOutgoingPort)

	f.NumFlows = f.flowsRefs.Len()
	f.NumFlowsStarted = f.flowsStartedRefs.Len()
	f.NumFlowsCompleted = f.flowsCompletedRefs.Len()
	f.PacketsIn += mu.InMetric.DeltaPackets
	f.BytesIn += mu.InMetric.DeltaBytes
	f.PacketsOut += mu.OutMetric.DeltaPackets
	f.BytesOut += mu.OutMetric.DeltaBytes
}

func (f *FlowStats) getActiveFlowsCount() int {
	return len(f.flowsRefsActive)
}

func (f *FlowStats) reset() {
	f.flowsStartedRefs = tuple.NewSet()
	f.flowsCompletedRefs = tuple.NewSet()
	f.flowsRefs = f.flowsRefsActive.Copy()
	f.FlowReportedStats = FlowReportedStats{
		NumFlows: f.flowsRefs.Len(),
	}
}

// FlowStatsByProcess collects statistics organized by process names. When process information is not enabled
// this stores the stats in a single entry keyed by a "-".
// Flow logs should be constructed by calling toFlowProcessReportedStats and then flattening the resulting
// slice with FlowMeta and other FlowLog information such as policies and labels.
type FlowStatsByProcess struct {
	// statsByProcessName stores aggregated flow statistics grouped by a process name.
	statsByProcessName    map[string]*FlowStats
	displayDebugTraceLogs bool
	natOutgoingPortLimit  int
	// TODO(doublek): Track the most significant stats and show them as part
	// of the flows that are included in the process limit. Current processNames
	// only tracks insertion order.
}

func NewFlowStatsByProcess(
	mu *metric.Update,
	displayDebugTraceLogs bool,
	natOutgoingPortLimit int,
) FlowStatsByProcess {
	f := FlowStatsByProcess{
		displayDebugTraceLogs: displayDebugTraceLogs,
		statsByProcessName:    make(map[string]*FlowStats),
		natOutgoingPortLimit:  natOutgoingPortLimit,
	}
	f.aggregateFlowStatsByProcess(mu)
	return f
}

func (f *FlowStatsByProcess) aggregateFlowStatsByProcess(mu *metric.Update) {
	if stats, ok := f.statsByProcessName[FieldNotIncluded]; ok {
		logutil.Tracef(f.displayDebugTraceLogs, "Process stats found %+v for metric update %+v", stats, mu)
		stats.aggregateFlowStats(*mu, f.displayDebugTraceLogs)
		logutil.Tracef(f.displayDebugTraceLogs, "Aggregated stats %+v after processing metric update %+v", stats, mu)
		f.statsByProcessName[FieldNotIncluded] = stats
	} else {
		logutil.Tracef(f.displayDebugTraceLogs, "Process stats not found for metric update %+v", mu)
		stats := NewFlowStats(*mu)
		f.statsByProcessName[FieldNotIncluded] = &stats
	}
}

func (f *FlowStatsByProcess) getActiveFlowsCount() int {
	activeCount := 0
	for _, stats := range f.statsByProcessName {
		activeCount += stats.getActiveFlowsCount()
	}
	return activeCount
}

func (f *FlowStatsByProcess) containsActiveRefs(mu *metric.Update) bool {
	if stats, ok := f.statsByProcessName[FieldNotIncluded]; ok {
		return stats.flowsRefsActive.Contains(mu.Tuple)
	}
	return false
}

func (f *FlowStatsByProcess) reset() {
	for name, stats := range f.statsByProcessName {
		stats.reset()
		f.statsByProcessName[name] = stats
	}
}

// gc garbage collects any process names and corresponding stats that don't have any active flows.
// This should only be called after stats have been reported.
func (f *FlowStatsByProcess) gc() int {
	remainingActiveFlowsCount := 0
	name := FieldNotIncluded
	stats, exists := f.statsByProcessName[name]
	if !exists {
		return remainingActiveFlowsCount
	}
	afc := stats.getActiveFlowsCount()
	if afc == 0 {
		delete(f.statsByProcessName, name)
	}
	remainingActiveFlowsCount += afc
	return remainingActiveFlowsCount
}

// toFlowProcessReportedStats returns atmost processLimit + 1 entry slice containing
// flow stats grouped by process information.
func (f *FlowStatsByProcess) toFlowProcessReportedStats() []FlowProcessReportedStats {
	// If we are not configured to include process information then
	// we expect to only have a single entry with no process information
	// and all stats are already aggregated into a single value.
	reportedStats := make([]FlowProcessReportedStats, 0, 1)
	if stats, ok := f.statsByProcessName[FieldNotIncluded]; ok {
		s := FlowProcessReportedStats{
			FlowReportedStats: stats.FlowReportedStats,
			NatOutgoingPorts:  f.getNatOutGoingPortsFromStats(stats),
		}
		reportedStats = append(reportedStats, s)
	} else {
		log.Warnf("No flow log status recorded %+v", f)
	}
	return reportedStats
}

func (f *FlowStatsByProcess) getNatOutGoingPortsFromStats(stats *FlowStats) []int {
	var natOutGoingPorts []int

	numNatOutgoingPorts := 0
	for _, value := range stats.flowsRefsActive {
		if numNatOutgoingPorts >= f.natOutgoingPortLimit {
			break
		}

		if value != 0 {
			natOutGoingPorts = append(natOutGoingPorts, value)
			numNatOutgoingPorts++
		}
	}

	for _, value := range stats.flowsCompletedRefs {
		if numNatOutgoingPorts >= f.natOutgoingPortLimit {
			break
		}

		if value != 0 {
			natOutGoingPorts = append(natOutGoingPorts, value)
			numNatOutgoingPorts++
		}
	}

	return natOutGoingPorts
}

// FlowProcessReportedStats contains FlowReportedStats along with process information.
type FlowProcessReportedStats struct {
	NatOutgoingPorts []int
	FlowReportedStats
}

// FlowLog is a record of flow data (metadata & reported stats) including
// timestamps. A FlowLog is ready to be serialized to an output format.
type FlowLog struct {
	StartTime, EndTime time.Time
	FlowMeta
	FlowLabels
	FlowPolicySet
	FlowExtras
	FlowProcessReportedStats
}

func (f *FlowLog) Deserialize(fl string) error {
	// Format is
	// startTime endTime srcType srcNamespace srcName srcLabels dstType dstNamespace dstName dstLabels srcIP dstIP proto srcPort dstPort numFlows numFlowsStarted numFlowsCompleted flowReporter packetsIn packetsOut bytesIn bytesOut action policies originalSourceIPs numOriginalSourceIPs destServiceNamespace dstServiceName dstServicePort
	// Sample entry with no aggregation and no labels.
	// 1529529591 1529529892 wep policy-demo nginx-7d98456675-2mcs4 nginx-7d98456675-* - wep kube-system kube-dns-7cc87d595-pxvxb kube-dns-7cc87d595-* - 192.168.224.225 192.168.135.53 17 36486 53 1 1 1 in 1 1 73 119 allow ["0|tier|namespace/tier.policy|allow|0"] [1.0.0.1] 1 kube-system kube-dns dig 23033 0

	var srcType, dstType endpoint.Type

	parts := strings.Split(fl, " ")
	if len(parts) < 32 {
		return fmt.Errorf("log %v can't be processed", fl)
	}

	switch parts[2] {
	case "wep":
		srcType = endpoint.Wep
	case "hep":
		srcType = endpoint.Hep
	case "ns":
		srcType = endpoint.Ns
	case "net":
		srcType = endpoint.Net
	}

	f.SrcMeta = endpoint.Metadata{
		Type:           srcType,
		Namespace:      parts[3],
		Name:           parts[4],
		AggregatedName: parts[5],
	}
	f.SrcLabels = stringToLabels(parts[6])
	if srcType == endpoint.Ns {
		namespace, name := utils.ExtractNamespaceFromNetworkSet(f.SrcMeta.AggregatedName)
		f.SrcMeta.Namespace = namespace
		f.SrcMeta.AggregatedName = name
	}

	switch parts[7] {
	case "wep":
		dstType = endpoint.Wep
	case "hep":
		dstType = endpoint.Hep
	case "ns":
		dstType = endpoint.Ns
	case "net":
		dstType = endpoint.Net
	}

	f.DstMeta = endpoint.Metadata{
		Type:           dstType,
		Namespace:      parts[8],
		Name:           parts[9],
		AggregatedName: parts[10],
	}
	f.DstLabels = stringToLabels(parts[11])
	if dstType == endpoint.Ns {
		namespace, name := utils.ExtractNamespaceFromNetworkSet(f.DstMeta.AggregatedName)
		f.DstMeta.Namespace = namespace
		f.DstMeta.AggregatedName = name
	}

	var sip, dip [16]byte
	if parts[12] != "-" {
		sip = utils.IpStrTo16Byte(parts[12])
	}
	if parts[13] != "-" {
		dip = utils.IpStrTo16Byte(parts[13])
	}
	p, _ := strconv.Atoi(parts[14])
	sp, _ := strconv.Atoi(parts[15])
	dp, _ := strconv.Atoi(parts[16])
	f.Tuple = tuple.Make(sip, dip, p, sp, dp)

	f.NumFlows, _ = strconv.Atoi(parts[17])
	f.NumFlowsStarted, _ = strconv.Atoi(parts[18])
	f.NumFlowsCompleted, _ = strconv.Atoi(parts[19])

	switch parts[20] {
	case "src":
		f.Reporter = ReporterSrc
	case "dst":
		f.Reporter = ReporterDst
	}

	f.PacketsIn, _ = strconv.Atoi(parts[21])
	f.PacketsOut, _ = strconv.Atoi(parts[22])
	f.BytesIn, _ = strconv.Atoi(parts[23])
	f.BytesOut, _ = strconv.Atoi(parts[24])

	switch parts[25] {
	case "allow":
		f.Action = ActionAllow
	case "deny":
		f.Action = ActionDeny
	}

	// Parse policies, empty ones are just -
	if parts[26] == "-" {
		f.FlowPolicySet = make(FlowPolicySet)
	} else if len(parts[26]) > 1 {
		f.FlowPolicySet = make(FlowPolicySet)
		polParts := strings.Split(parts[26][1:len(parts[26])-1], ",")
		for _, p := range polParts {
			f.FlowPolicySet[p] = emptyValue
		}
	}

	// Parse original source IPs, empty ones are just -
	if parts[27] == "-" {
		f.FlowExtras = FlowExtras{}
	} else if len(parts[27]) > 1 {
		ips := []net.IP{}
		exParts := strings.Split(parts[27][1:len(parts[27])-1], ",")
		for _, ipStr := range exParts {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			ips = append(ips, ip)
		}
		f.FlowExtras = FlowExtras{
			OriginalSourceIPs: ips,
		}
		f.FlowExtras.NumOriginalSourceIPs, _ = strconv.Atoi(parts[28])
	}

	svcPortNum, err := strconv.Atoi(parts[32])
	if err != nil {
		svcPortNum = 0
	}

	f.DstService = FlowService{
		Namespace: parts[29],
		Name:      parts[30],
		PortName:  parts[31],
		PortNum:   svcPortNum,
	}
	return nil
}
