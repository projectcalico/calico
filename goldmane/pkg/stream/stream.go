package stream

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/logrusr"
	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/lib/std/time"
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
	ctx    context.Context
	cancel context.CancelFunc

	// closeOnce makes Close idempotent, so numStreams drops once per stream however many
	// times the client and the manager close it.
	closeOnce sync.Once

	// rl is used to rate limit log messages that may happen frequently.
	rl *logrusr.RateLimitedLogger
}

// Close stops the stream and removes it from the numStreams gauge. The stream manager drops it
// from its registry on its next pass.
func (s *stream) Close() {
	s.closeOnce.Do(func() {
		s.cancel()
		numStreams.Dec()
	})
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
			logrus.WithField("id", s.id).Debug("Stream context done")
			return
		case b := <-s.in:
			b.Iter(func(f storage.FlowBuilder) bool {
				if err := chanutil.WriteWithDeadline(s.ctx, s.out, f, 60*time.Second); err != nil {
					// If we hit an error, indicate that we should stop iteration.
					s.rl.WithFields(logrus.Fields{"id": s.id}).WithError(err).Debug("Error writing flow to stream output")
					return true
				}
				// If we didn't hit an error, continue iteration.
				return false
			})
		}
	}
}
