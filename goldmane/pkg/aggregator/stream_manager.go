package aggregator

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator/bucketing"
	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var numStreams = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "goldmane_num_streams",
	Help: "Number of active streams",
})

func init() {
	prometheus.MustRegister(numStreams)
}

func NewStreamManager() *streamManager {
	maxStreams := 100
	return &streamManager{
		streams:          make(map[string]*Stream),
		flowCh:           make(chan bucketing.FlowBuilder, 5000),
		closedStreamsCh:  make(chan string, maxStreams),
		streamRequests:   make(chan *streamRequest, 10),
		backfillRequests: make(chan *Stream, 10),
		maxStreams:       maxStreams,
		rl: logutils.NewRateLimitedLogger(
			logutils.OptBurst(1),
			logutils.OptInterval(15*time.Second),
		),
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

	// streamRequests is the channel to receive requests for new streams.
	streamRequests chan *streamRequest

	// backfillRequests is a channel to send backfill requests on to the log aggregator.
	backfillRequests chan *Stream

	// flowCh queues incoming flows to be processed by worker threads and emitted to streams.
	flowCh chan bucketing.FlowBuilder

	// rl is used to rate limit log messages that may happen frequently.
	rl *logutils.RateLimitedLogger
}

func (m *streamManager) Run(ctx context.Context) {
	go m.processIncomingFlows(ctx)

	for {
		select {
		case req := <-m.streamRequests:
			stream := m.register(req)
			req.respCh <- stream
			m.backfillRequests <- stream
		case id := <-m.closedStreamsCh:
			logrus.WithField("id", id).Debug("Stream closed")
			m.close(id)
		case <-ctx.Done():
			logrus.Debug("Stream manager exiting")
			return
		}
	}
}

func (m *streamManager) Register(req *streamRequest) {
	// Register a new stream request. The request will be processed in the stream manager's
	// main loop - Run().
	m.streamRequests <- req
}

// Receive tells the stream manager about a new DiachronicFlow that has rolled over. The manager
// informs all streams about the new flow, so they can decide to include it in their output.
//
// Note: Receive may block if the flow channel is full. This is expected to be a rare event, but care
// should be taken to avoid calling this function from the main loop.
func (m *streamManager) Receive(b bucketing.FlowBuilder) {
	if err := chanutil.WriteWithDeadline(context.TODO(), m.flowCh, b, 30*time.Second); err != nil {
		m.rl.WithError(err).Error("stream manager failed to handle flow(s), dropping")
	}
}

// backfillChannel returns a channel containing backfill requests. This channel filled when new
// streams are registered, and the backfill is handled asynchronously by the log aggregator.
func (m *streamManager) backfillChannel() <-chan *Stream {
	return m.backfillRequests
}

// processIncomingFlows reads incoming flows from the stream manager and fans them to active streams.
// Each stream is responsible for deciding whether to include the flow in its output.
func (m *streamManager) processIncomingFlows(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			logrus.Debug("stream manager worker exiting")
			return
		case b := <-m.flowCh:
			for _, s := range m.streams {
				select {
				case <-s.ctx.Done():
					logrus.WithField("id", s.id).Debug("Stream closed, skipping")
					continue
				default:
					s.Receive(b)
				}
			}
		}
	}
}

func (m *streamManager) register(req *streamRequest) *Stream {
	if m.maxStreams > 0 && len(m.streams) >= m.maxStreams {
		logrus.WithField("max", m.maxStreams).Warn("Max streams reached, rejecting new stream")
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	stream := &Stream{
		id:     uuid.NewString(),
		out:    make(chan bucketing.FlowBuilder, req.channelSize),
		done:   m.closedStreamsCh,
		req:    req,
		ctx:    ctx,
		cancel: cancel,
		rl: logutils.NewRateLimitedLogger(
			logutils.OptBurst(1),
			logutils.OptInterval(15*time.Second),
		),
	}
	m.streams[stream.id] = stream
	numStreams.Set(float64(len(m.streams)))

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

	// Close the stream's output channel.
	close(s.out)
	delete(m.streams, id)
	numStreams.Set(float64(len(m.streams)))
}
