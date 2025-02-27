package aggregator

import (
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator/bucketing"
	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

type Stream struct {
	id   string
	out  chan *proto.FlowResult
	in   chan bucketing.FlowBuilder
	done chan<- string
	req  streamRequest
}

func (s *Stream) Close() {
	s.done <- s.id
}

func (s *Stream) Flows() <-chan *proto.FlowResult {
	return s.out
}

// Receive tells the Stream about a newly learned Flow to consider for output.
// The Stream will decide whether to include the Flow in its output based on its configuration.
// Note that emission of the Flow to the Stream's output channel is asynchronous.
func (s *Stream) Receive(f bucketing.FlowBuilder) {
	select {
	case s.in <- f:
	case <-time.After(5 * time.Second):
		logrus.WithField("id", s.id).Warn("Timed out sending flow to stream")
	}
}

// recv is the main loop for the Stream. It listens for new Flows to be sent to the Stream
// and handles them.
func (s *Stream) recv() {
	// Ensure the output channel is closed when we're done, and only after
	// we've finished processing all incoming Flows.
	defer close(s.out)

	// Loop, handling incoming Flows.
	for f := range s.in {
		s.handle(f)
	}
}

// handle decides whether to include a Flow in the Stream's output based on the Stream's configuration,
// and sends it to the Stream's output channel if appropriate.
func (s *Stream) handle(f bucketing.FlowBuilder) {
	flow, id := f.Build(s.req.req.Filter)
	if flow != nil {
		res := &proto.FlowResult{
			Flow: types.FlowToProto(flow),
			Id:   id,
		}
		s.send(res)
	}
}

func (s *Stream) send(f *proto.FlowResult) {
	logrus.WithFields(logrus.Fields{
		"id":   s.id,
		"flow": f.Id,
	}).Debug("Sending flow to stream")

	select {
	case s.out <- f:
	case <-time.After(5 * time.Second):
		logrus.WithField("id", s.id).Warn("Timed out sending flow to stream")
	}
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

// Receive tells the stream manager about a new DiachronicFlow that has rolled over. The manager
// informs all streams about the new flow, so they can decide to include it in their output.
func (m *streamManager) Receive(b bucketing.FlowBuilder) {
	for _, s := range m.streams {
		s.Receive(b)
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
		id:   uuid.NewString(),
		out:  make(chan *proto.FlowResult, 100),
		in:   make(chan bucketing.FlowBuilder, 100),
		done: m.closedStreamsCh,
		req:  req,
	}
	m.streams[stream.id] = stream

	// Start the stream's receive loop.
	go stream.recv()

	logrus.WithField("id", stream.id).Debug("Registered new stream")
	return stream
}

// close cleans up the stream with the given ID.
// Note: close terminates the stream's receive and output channels, so it should only be called from the
// aggregator's main loop.
func (m *streamManager) close(id string) {
	s, ok := m.streams[id]
	if !ok {
		logrus.WithField("id", id).Warn("Asked to close unknown stream")
		return
	}
	logrus.WithField("id", id).Debug("Closing stream")
	close(s.in)
	delete(m.streams, id)
}
