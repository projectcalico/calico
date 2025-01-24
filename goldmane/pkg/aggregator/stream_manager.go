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

	bucketsToAggregate int
	rolloverCounter    int
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

func (s *Stream) inc() {
	s.rolloverCounter++
}

func (s *Stream) shouldEmit() bool {
	return s.rolloverCounter%s.bucketsToAggregate == 0
}

func NewStreamManager() *streamManager {
	return &streamManager{
		streams:    make(map[string]*Stream),
		done:       make(chan string),
		maxStreams: 100,
	}
}

// streamManager is a struct that manages stream of data to clients.
type streamManager struct {
	// streams is a registry of active streams being served by the aggregator. Stream data
	// is published to these streams on rollover.
	streams map[string]*Stream

	// maxStreams configured the maximum number of concurrent streams that can be active.
	// If this limit is reached, new streams will be rejected.
	maxStreams int

	// done is a channel on which to receive UUIDs of streams that have been closed.
	done chan string
}

func (m *streamManager) streamClosed() chan string {
	return m.done
}

func (m *streamManager) register(req streamRequest) *Stream {
	if m.maxStreams > 0 && len(m.streams) >= m.maxStreams {
		logrus.WithField("max", m.maxStreams).Warn("Max streams reached, rejecting new stream")
		return nil
	}

	stream := &Stream{
		id:                 uuid.NewString(),
		flows:              make(chan *proto.Flow, 100),
		done:               m.done,
		req:                req,
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

func (m *streamManager) rollover(ring *BucketRing, diachronics map[types.FlowKey]*types.DiachronicFlow) {
	// Each stream may have requested aggregation across a different number of buckets, so the individual stream
	// objects are responsible for tracking their own state - whether or not it is ready to emit data, and how many buckets
	// back it wants to go.
	logrus.Debug("Checking if any stream should emit data")
	for _, s := range m.streams {
		if s.shouldEmit() {
			// Get the flows from the last N buckets.
			keys, start, end := ring.LastNFlows(s.bucketsToAggregate)
			logrus.WithFields(logrus.Fields{
				"numFlows": keys.Len(),
				"id":       s.id,
				"start":    start,
				"end":      end,
			}).Debug("Emitting flows to stream")

			keys.Iter(func(key types.FlowKey) error {
				d, ok := diachronics[key]
				if !ok {
					logrus.WithField("key", key).Warn("Failed to find diachronic data")
					return nil
				}
				f := d.Aggregate(start, end)
				s.Send(types.FlowToProto(f))
				return nil
			})
		} else {
			logrus.WithField("id", s.id).Debug("Stream not ready to emit")
		}

		// Tell the stream a rollover has occurred. It uses this to track when it has enough data
		// to emit a new set of flows.
		s.inc()
	}
}
