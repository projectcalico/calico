package stream

import (
	"context"
	"errors"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

type Stream interface {
	Flows() <-chan storage.FlowBuilder
	Close()
	Ctx() context.Context
	StartTimeGte() int64
	ID() string
}

type stream struct {
	// Public fields.
	Req *proto.FlowStreamRequest

	// Private fields.
	id     string
	in     chan storage.FlowProvider
	out    chan storage.FlowBuilder
	done   chan<- string
	ctx    context.Context
	cancel context.CancelFunc

	// rl is used to rate limit log messages that may happen frequently.
	rl *logutils.RateLimitedLogger
}

// Close signals to the stream manager that this stream is done and should be closed.
func (s *stream) Close() {
	// Cancel the stream context - this will trigger any clients writing to the stream to stop.
	s.cancel()

	// Queue unregistration of the stream, and cleanup of its resources.
	s.done <- s.id
}

func (s *stream) Ctx() context.Context {
	return s.ctx
}

// Flows returns a channel that contains the output from this stream.
func (s *stream) Flows() <-chan storage.FlowBuilder {
	return s.out
}

func (s *stream) StartTimeGte() int64 {
	return s.Req.StartTimeGte
}

func (s *stream) ID() string {
	return s.id
}

func (s *stream) run() {
	// Close the output channel when the stream is done. This ensures we don't try to
	// write to a closed channel.
	defer close(s.out)

	for {
		select {
		case <-s.ctx.Done():
			logrus.WithField("id", s.ID).Debug("Stream context done")
			return
		case b, ok := <-s.in:
			if !ok {
				logrus.WithField("id", s.ID).Debug("Stream input channel closed")
				return
			}

			b.Iter(func(f storage.FlowBuilder) bool {
				if err := chanutil.WriteWithDeadline(s.ctx, s.out, f, 60*time.Second); err != nil {
					// If we hit an error, indicate that we should stop iteration.
					s.rl.WithFields(logrus.Fields{"id": s.ID}).WithError(err).Debug("Error writing flow to stream output")
					return true
				}
				// If we didn't hit an error, continue iteration.
				return false
			})
		}
	}
}

// receive tells the Stream about a newly learned source of flows and queues it for processing.
// Note that emission of the individual Flow objects to the Stream's output channel is asynchronous.
func (s *stream) receive(b storage.FlowProvider) {
	// It's important that we don't block here, as this is called from the main loop.
	logrus.WithFields(logrus.Fields{"id": s.ID}).Debug("Sending FlowProvider to stream")

	// Send the flow to the output channel. If the channel is full, wait for a bit before giving up.
	if err := chanutil.WriteWithDeadline(s.ctx, s.in, b, 1*time.Second); err != nil {
		if !errors.Is(err, context.Canceled) {
			s.rl.WithField("id", s.ID).WithError(err).Error("error writing flow provider to stream input")
		}
	}
}
