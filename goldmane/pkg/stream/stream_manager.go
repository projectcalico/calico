package stream

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/proto"
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

type streamRequest struct {
	respCh chan Stream
	req    *proto.FlowStreamRequest

	// channel size allows configuration of the size of the channel to use for this stream.
	// This is to avoid overloading the channel with too many flows at once.
	// Note; This is a quick fix to avoid having to properly decouple streaming from the main loop.
	// long term, we should do away with this and use a proper backpressure mechanism.
	channelSize int
}

type StreamManager interface {
	Run(ctx context.Context)
	Register(*proto.FlowStreamRequest, int) chan Stream
	Backfills() <-chan Stream
	Receive(storage.FlowProvider, string)
}

func NewStreamManager() *streamManager {
	maxStreams := 100
	return &streamManager{
		streams:          streamCache{streams: make(map[string]*stream)},
		in:               make(chan storage.FlowProvider, 500),
		closedStreamsCh:  make(chan string, maxStreams),
		streamRequests:   make(chan *streamRequest, 10),
		backfillRequests: make(chan Stream, 10),
		maxStreams:       maxStreams,
		rl: logutils.NewRateLimitedLogger(
			logutils.OptBurst(1),
			logutils.OptInterval(15*time.Second),
		),
	}
}

// We use a mutex to protect the cache of active Streams, as they are accessed from multiple
// goroutines. The cache is a map of stream IDs to Stream objects.
type streamCache struct {
	sync.Mutex
	streams map[string]*stream
}

func (c *streamCache) add(s *stream) {
	c.Lock()
	defer c.Unlock()
	c.streams[s.id] = s
}

func (c *streamCache) remove(id string) {
	c.Lock()
	defer c.Unlock()
	s, ok := c.streams[id]
	if !ok {
		logrus.WithField("id", id).Warn("Asked to close unknown stream")
		return
	}

	// Close the stream's input channel. It is important that we do this here while holding the lock,
	// allowing an atomic closure and removal from the cache. This ensures that no other goroutine
	// can access the stream after its input channel is closed.
	close(s.in)
	delete(c.streams, id)
}

// sendToStream directs the given flow provider to the stream with the given ID if it exists.
// It does this atomically, to ensure the input channel isn't closed.
// Note that writing to a stream can theoretically block, but this is expected to be exceedingly rare.
func (c *streamCache) sendToStream(id string, p storage.FlowProvider) {
	c.Lock()
	defer c.Unlock()
	s, ok := c.streams[id]
	if !ok {
		logrus.WithField("id", id).Warn("Send to unknown stream")
		return
	}
	s.receive(p)
}

func (c *streamCache) size() int {
	c.Lock()
	defer c.Unlock()
	return len(c.streams)
}

func (c *streamCache) iter(f func(*stream)) {
	c.Lock()
	defer c.Unlock()
	for _, s := range c.streams {
		select {
		case <-s.ctx.Done():
			logrus.WithField("id", s.id).Debug("Stream closed, skipping")
		default:
			f(s)
		}
	}
}

type streamManager struct {
	// streams is a registry of active streams being served by the aggregator. Stream data
	// is published to these streams on rollover.
	streams streamCache

	// maxStreams configured the maximum number of concurrent streams that can be active.
	// If this limit is reached, new streams will be rejected.
	maxStreams int

	// closedStreamsCh is a channel on which to receive the UUID of streams that have been closed.
	closedStreamsCh chan string

	// streamRequests is the channel to receive requests for new streams.
	streamRequests chan *streamRequest

	// backfillRequests is a channel to send backfill requests on to the log aggregator.
	backfillRequests chan Stream

	// in queues incoming data to be processed by worker threads and emitted to streams.
	in chan storage.FlowProvider

	// rl is used to rate limit log messages that may happen frequently.
	rl *logutils.RateLimitedLogger
}

func (m *streamManager) Run(ctx context.Context) {
	go m.processIncoming(ctx)

	for {
		select {
		case req := <-m.streamRequests:
			stream := m.register(req)
			req.respCh <- stream
			m.backfillRequests <- stream
		case id := <-m.closedStreamsCh:
			m.unregister(id)
		case <-ctx.Done():
			logrus.Debug("Stream manager exiting")
			return
		}
	}
}

func (m *streamManager) Register(req *proto.FlowStreamRequest, size int) chan Stream {
	sr := &streamRequest{
		respCh:      make(chan Stream, 1),
		req:         req,
		channelSize: size,
	}
	// Register a new stream request. The request will be processed in the stream manager's
	// main loop - Run().
	m.streamRequests <- sr
	return sr.respCh
}

// Receive tells the stream manager about a new flow provider.
//
// If an ID is provided, the manager sends the update to the stream with that ID.
// If no ID is provided, the manager informs all streams about update, so they can decide to include it in their output.
func (m *streamManager) Receive(b storage.FlowProvider, id string) {
	if id != "" {
		// An explicit ID was given. Send to the stream with that ID.
		m.streams.sendToStream(id, b)
		return
	}

	// No ID was given - send to all streams.
	if err := chanutil.WriteWithDeadline(context.TODO(), m.in, b, 30*time.Second); err != nil {
		m.rl.WithError(err).Error("stream manager failed to handle flow(s), dropping")
	}
}

// Backfills returns a channel containing backfill requests. This channel filled when new
// streams are registered, and the backfill is handled asynchronously by the log aggregator.
func (m *streamManager) Backfills() <-chan Stream {
	return m.backfillRequests
}

// processIncoming reads incoming updates and fans them to registered streams.
func (m *streamManager) processIncoming(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			logrus.Debug("stream manager worker exiting")
			return
		case b := <-m.in:
			m.streams.iter(func(s *stream) {
				s.receive(b)
			})
		}
	}
}

func (m *streamManager) register(req *streamRequest) *stream {
	if m.maxStreams > 0 && m.streams.size() >= m.maxStreams {
		logrus.WithField("max", m.maxStreams).Warn("Max streams reached, rejecting new stream")
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	stream := &stream{
		Req:    req.req,
		id:     uuid.NewString(),
		in:     make(chan storage.FlowProvider, 500),
		out:    make(chan storage.FlowBuilder, req.channelSize),
		done:   m.closedStreamsCh,
		ctx:    ctx,
		cancel: cancel,
		rl: logutils.NewRateLimitedLogger(
			logutils.OptBurst(1),
			logutils.OptInterval(15*time.Second),
		),
	}
	go stream.run()

	m.streams.add(stream)
	numStreams.Set(float64(m.streams.size()))

	logrus.WithField("id", stream.id).Debug("Registered new stream")
	return stream
}

// unregister removes a stream from the stream manager.
func (m *streamManager) unregister(id string) {
	logrus.WithField("id", id).Debug("Closing stream")
	m.streams.remove(id)
	numStreams.Set(float64(m.streams.size()))
	logrus.WithField("id", id).Debug("Stream closed")
}
