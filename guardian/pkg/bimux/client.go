package bimux

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/chanutil"
)

type SessionPool interface {
	Start(ctx context.Context)
	Get() <-chan chanutil.Response[*ClientSession]
	WaitForClose() <-chan struct{}
}

type sessionPool struct {
	dialer     SessionDialer
	getSession chan chanutil.Request[any, *ClientSession]
	shutdownCh chan struct{}
}

func NewSessionPool(dialer SessionDialer) SessionPool {
	return &sessionPool{
		dialer:     dialer,
		getSession: make(chan chanutil.Request[any, *ClientSession], 20),
		shutdownCh: make(chan struct{}),
	}
}

func (mgr *sessionPool) Start(ctx context.Context) {
	go func() {
		var session *ClientSession
		var reqBacklog []chanutil.Request[any, *ClientSession]
		var dialing <-chan chanutil.Response[*ClientSession]

		defer close(mgr.shutdownCh)

		defer func() {
			if dialing != nil {
				// Wait for the dialer to complete what it's doing before exiting.
				log.Debug("Waiting for dialer to finish before exiting.")
				<-dialing
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case req := <-mgr.getSession:
				if session != nil && !session.IsClosed() {
					req.WriteResponse(session)
				} else {
					reqBacklog = append(reqBacklog, req)

					if ch, err := mgr.dialer.Dial(ctx); err != nil {
						log.WithError(err).Error("Failed to dial.")
						return
					} else {
						dialing = ch
					}
				}
			case response := <-dialing:
				if err := response.Err; err == nil {
					session = response.Value
					log.WithField("sessionAddress", session.Addr()).Debug("Setting session.")
					if len(reqBacklog) > 0 {
						log.Debugf("Sending session to %d backlogged requests.", len(reqBacklog))
					}
					for _, req := range reqBacklog {
						req.WriteResponse(session)
					}
				} else {
					for _, cmd := range reqBacklog {
						cmd.WriteError(err)
					}
				}

				reqBacklog = []chanutil.Request[any, *ClientSession]{}
				dialing = nil
			}
		}
	}()
}

func (mgr *sessionPool) Get() <-chan chanutil.Response[*ClientSession] {
	req := chanutil.NewRequestResponse[any, *ClientSession](nil)

	if !chanutil.WriteNonBlocking(mgr.getSession, req) {
		req.WriteError(errors.New("write channel full, skipping command"))
	}

	return req.ResponseChan()
}

func (mgr *sessionPool) WaitForClose() <-chan struct{} {
	return mgr.shutdownCh
}
