package aggregator

import (
	"context"
	"errors"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator/bucketing"
	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

type Stream struct {
	id     string
	out    chan bucketing.FlowBuilder
	done   chan<- string
	req    *streamRequest
	ctx    context.Context
	cancel context.CancelFunc

	// rl is used to rate limit log messages that may happen frequently.
	rl *logutils.RateLimitedLogger
}

// Close signals to the stream manager that this stream is done and should be closed.
func (s *Stream) Close() {
	s.cancel()
	s.done <- s.id
}

// Flows returns a channel that contains the output from this stream.
func (s *Stream) Flows() <-chan bucketing.FlowBuilder {
	return s.out
}

// Receive tells the Stream about a newly learned Flow that matches the Stream's filter and
// queues it for processing. Note that emission of the Flow to the Stream's output channel is asynchronous.
func (s *Stream) Receive(b bucketing.FlowBuilder) {
	// It's important that we don't block here, as this is called from the main loop.
	logrus.WithFields(logrus.Fields{"id": s.id}).Debug("Sending flow to stream")

	// Send the flow to the output channel. If the channel is full, wait for a bit before giving up.
	if err := chanutil.WriteWithDeadline(s.ctx, s.out, b, 1*time.Second); err != nil {
		if !errors.Is(err, context.Canceled) {
			s.rl.WithField("id", s.id).WithError(err).Error("error writing flow to stream output")
		}
	}
}
