package aggregator

import (
	"context"
	"errors"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

type Stream struct {
	id     string
	out    chan *proto.FlowResult
	in     chan *proto.FlowResult
	done   chan<- string
	req    *streamRequest
	ctx    context.Context
	cancel context.CancelFunc

	// rl is used to rate limit log messages that may happen frequently.
	rl *logutils.RateLimitedLogger
}

// Close signals to the stream manager that this stream is done and should be closed.
func (s *Stream) Close() {
	s.done <- s.id
}

// Flows returns a channel that contains the output stream of FlowResults.
func (s *Stream) Flows() <-chan *proto.FlowResult {
	return s.out
}

// Receive tells the Stream about a newly learned Flow that matches the Stream's filter and
// queues it for processing. Note that emission of the Flow to the Stream's output channel is asynchronous.
func (s *Stream) Receive(f *proto.FlowResult) error {
	// It's important that the Stream Receive function not block, as it's called from the main loop
	// when backfilling flows for a newly connected Stream.
	go func() {
		if err := chanutil.WriteWithDeadline(s.ctx, s.in, f, 30*time.Second); err != nil {
			if !errors.Is(err, context.Canceled) {
				s.rl.WithField("id", s.id).WithError(err).Error("error writing to stream input channel")
			}
		}
	}()
	return nil
}

// recv is the main loop for the Stream. It listens for new Flows to be sent to the Stream
// and handles them.
func (s *Stream) recv() {
	// Ensure the output channel is closed when we're done, and only after
	// we've finished processing all incoming Flows.
	defer close(s.out)

	// Loop, handling incoming Flows.
	for f := range s.in {
		s.send(f)
	}
}

func (s *Stream) send(f *proto.FlowResult) {
	logrus.WithFields(logrus.Fields{
		"id":   s.id,
		"flow": f.Id,
	}).Debug("Sending flow to stream")

	// Send the flow to the output channel. If the channel is full, wait for a bit before giving up.
	if err := chanutil.WriteWithDeadline(s.ctx, s.out, f, 30*time.Second); err != nil {
		if !errors.Is(err, context.Canceled) {
			s.rl.WithField("id", s.id).WithError(err).Error("error writing flow to stream output")
		}
	}
}
