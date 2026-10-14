package stream

import (
	"context"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/logrusr"
	"github.com/projectcalico/calico/lib/std/time"
)

var numStreams = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "goldmane_num_streams",
	Help: "Number of active streams",
})

func init() {
	prometheus.MustRegister(numStreams)
}

// StreamManager tracks active streams. Its methods run on the Goldmane main loop, so a stream
// is subscribed to rollovers in the same step that queues its backfill.
type StreamManager interface {
	Register(*proto.FlowStreamRequest, int) Stream
	Receive(storage.FlowProvider, string)
}

var _ StreamManager = &streamManager{}

func NewStreamManager() *streamManager {
	return &streamManager{
		streams:    make(map[string]*stream),
		maxStreams: 100,
	}
}

type streamManager struct {
	// streams is a registry of active streams being served by the aggregator. Stream data
	// is published to these streams on rollover.
	streams map[string]*stream

	// maxStreams configured the maximum number of concurrent streams that can be active.
	// If this limit is reached, new streams will be rejected.
	maxStreams int
}

// Register creates a stream, or returns nil if the stream limit has been reached.
func (m *streamManager) Register(req *proto.FlowStreamRequest, channelSize int) Stream {
	m.prune()
	if m.maxStreams > 0 && len(m.streams) >= m.maxStreams {
		logrus.WithField("max", m.maxStreams).Warn("Max streams reached, rejecting new stream")
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	newStream := &stream{
		Req:    req,
		id:     uuid.NewString(),
		in:     make(chan storage.FlowProvider, 500),
		out:    make(chan storage.FlowBuilder, channelSize),
		ctx:    ctx,
		cancel: cancel,
		rl: logrusr.NewRateLimitedLogger(
			logrusr.OptBurst(1),
			logrusr.OptInterval(15*time.Second),
		),
	}
	go newStream.run()

	m.streams[newStream.id] = newStream
	numStreams.Inc()

	logrus.WithField("id", newStream.id).Debug("Registered new stream")
	return newStream
}

// Receive queues provider for the stream with the given ID, or for every stream if the ID is empty.
func (m *streamManager) Receive(provider storage.FlowProvider, id string) {
	if id != "" {
		if s, ok := m.streams[id]; ok {
			m.send(s, provider)
		}
		return
	}
	for _, s := range m.streams {
		m.send(s, provider)
	}
}

// send never blocks the main loop. A stream whose queue is full has fallen hours behind, so we
// close it, and its client gets Aborted.
func (m *streamManager) send(s *stream, provider storage.FlowProvider) {
	// This only prunes early. A Close racing past it leaves one provider in s.in, which nothing
	// reads, since run exits on the canceled context.
	if s.ctx.Err() != nil {
		delete(m.streams, s.id)
		return
	}
	select {
	case s.in <- provider:
	default:
		s.rl.WithField("id", s.id).Warn("Stream queue full, closing stream")
		s.Close()
		delete(m.streams, s.id)
	}
}

// prune drops streams that their clients have closed.
func (m *streamManager) prune() {
	for id, s := range m.streams {
		if s.ctx.Err() != nil {
			delete(m.streams, id)
		}
	}
}
