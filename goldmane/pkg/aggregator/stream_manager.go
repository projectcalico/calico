package aggregator

import (
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

type Stream struct {
	id    string
	flows chan *proto.Flow
	done  chan<- string
	req   streamRequest

	// Keep track of the current flow set relevant to this stream.
	// Each stream may have requested aggregation across a different number of buckets, so the individual stream
	// objects are responsible for tracking their own state - whether or not it is ready to emit data, and how many buckets
	// back it wants to go.
	diachronics        map[types.FlowKey]*types.DiachronicFlow
	bucketsToAggregate int
	rolloverCounter    int
	start              int64
	end                int64
}

func (s *Stream) Close() {
	s.done <- s.id
}

func (s *Stream) Flows() <-chan *proto.Flow {
	return s.flows
}

func (s *Stream) Send(f *proto.Flow) {
	select {
	case s.flows <- f:
	case <-time.After(5 * time.Second):
		logrus.WithField("id", s.id).Warn("Timed out sending flow to stream")
	}
}

func (s *Stream) receiveFlow(f *types.DiachronicFlow, start, end int64) {
	if s.start == 0 || start < s.start {
		s.start = start
	}
	if s.end == 0 || end > s.end {
		s.end = end
	}
	s.diachronics[f.Key] = f
}

// rollover is called on global rollover, and is responsible for determining if the stream should emit data.
func (s *Stream) rollover() {
	defer s.inc()
	if !s.shouldEmit() {
		return
	}
	logrus.WithFields(logrus.Fields{
		"numFlows": len(s.diachronics),
		"id":       s.id,
		"start":    s.start,
		"end":      s.end,
	}).Debug("Emitting flows to stream")

	// For each diachronic we have stored, render it and send it.
	for _, d := range s.diachronics {
		f := d.Aggregate(s.start, s.end)
		s.Send(types.FlowToProto(f))
	}

	// Clear internal state needed to build the next set of flows.
	s.diachronics = make(map[types.FlowKey]*types.DiachronicFlow)
	s.start = 0
	s.end = 0
}

func (s *Stream) inc() {
	s.rolloverCounter++
}

func (s *Stream) shouldEmit() bool {
	return s.rolloverCounter%s.bucketsToAggregate == 0
}

func NewStreamManager() *streamManager {
	maxStreams := 100
	return &streamManager{
		streams:         make(map[string]*Stream),
		closedStreamsCh: make(chan string, maxStreams),
		maxStreams:      maxStreams,
	}
}

type streamManager struct {
	// streams is a registry of active streams being served by the aggregator. Stream data
	// is published to these streams on rollover.
	streams map[string]*Stream

	// maxStreams configured the maximum number of concurrent streams that can be active.
	// If this limit is reached, new streams will be rejected.
	maxStreams int

	// closedStreamsCh is a channel on which to receive UUIDs of streams that have been closed.
	closedStreamsCh chan string
}

// ReceiveFlow tells the stream manager about a new DiachronicFlow that has rolled over. The manager
// informs all streams about the new flow, so they can decide to include it in their output.
func (m *streamManager) ReceiveFlow(f *types.DiachronicFlow, start, end int64) {
	for _, s := range m.streams {
		s.receiveFlow(f, start, end)
	}
}

func (m *streamManager) closedStreams() chan string {
	return m.closedStreamsCh
}

func (m *streamManager) register(req streamRequest) *Stream {
	if m.maxStreams > 0 && len(m.streams) >= m.maxStreams {
		logrus.WithField("max", m.maxStreams).Warn("Max streams reached, rejecting new stream")
		return nil
	}

	stream := &Stream{
		id:                 uuid.NewString(),
		flows:              make(chan *proto.Flow, 100),
		done:               m.closedStreamsCh,
		req:                req,
		diachronics:        make(map[types.FlowKey]*types.DiachronicFlow),
		bucketsToAggregate: 1,
	}
	m.streams[stream.id] = stream

	logrus.WithField("id", stream.id).Debug("Registered new stream")
	return stream
}

func (m *streamManager) close(id string) {
	s, ok := m.streams[id]
	if !ok {
		logrus.WithField("id", id).Warn("Asked to close unknown stream")
		return
	}
	logrus.WithField("id", id).Debug("Closing stream")
	close(s.flows)
	delete(m.streams, id)
}

func (m *streamManager) rollover() {
	logrus.Debug("Checking if any stream should emit data")
	for _, s := range m.streams {
		s.rollover()
	}
}
