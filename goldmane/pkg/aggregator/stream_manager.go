package aggregator

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator/bucketing"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/chanutil"
)

func NewStreamManager() *streamManager {
	maxStreams := 100
	return &streamManager{
		streams:          make(map[string]*Stream),
		flowCh:           make(chan bucketing.FlowBuilder, 5000),
		closedStreamsCh:  make(chan string, maxStreams),
		streamRequests:   make(chan *streamRequest, 10),
		backfillRequests: make(chan *Stream, 10),
		maxStreams:       maxStreams,
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
}

func (m *streamManager) Run(ctx context.Context, numWorkers int) {
	for range numWorkers {
		go m.processIncomingFlows(ctx)
	}

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
func (m *streamManager) Receive(b bucketing.FlowBuilder) {
	// It's important that the stream manager Receive function not block, as it's called from the
	// main thread.
	go func() {
		if err := chanutil.WriteWithDeadline(context.TODO(), m.flowCh, b, 30*time.Second); err != nil {
			logrus.WithError(err).Error("stream manager failed to handle flow")
		}
	}()
}

// backfillChannel returns a channel containing backfill requests. This channel filled when new
// streams are registered, and the backfill is handled asynchronously by the log aggregator.
func (m *streamManager) backfillChannel() <-chan *Stream {
	return m.backfillRequests
}

// processIncomingFlows reads incoming flows from the stream manager and fans them out to the relevant streams.
func (m *streamManager) processIncomingFlows(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			logrus.Debug("stream manager worker exiting")
			return
		case b := <-m.flowCh:
			for _, s := range m.streams {
				// Build the flow, checking if the flow matches the stream's filter.
				if f, id := b.Build(s.req.req.Filter); f != nil {
					select {
					case <-s.ctx.Done():
						logrus.WithField("id", s.id).Debug("Stream closed, skipping")
						continue
					default:
						s.Receive(&proto.FlowResult{
							Id:   id,
							Flow: types.FlowToProto(f),
						})
					}
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
		out:    make(chan *proto.FlowResult, 5000),
		in:     make(chan *proto.FlowResult, 5000),
		done:   m.closedStreamsCh,
		req:    req,
		ctx:    ctx,
		cancel: cancel,
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

	// Cancel the stream's context, which will stop any further processing of incoming flows
	// via the Receive() method.
	s.cancel()

	// Closing the input channel will the recv() loop to finish processing any queued flows
	// and exit, closing the output channel.
	close(s.in)
	delete(m.streams, id)
}
