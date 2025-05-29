package server

import (
	"context"
	"github.com/projectcalico/calico/guardian/pkg/asyncutil"
	"github.com/projectcalico/calico/guardian/pkg/bimux"
)

type sessionManager struct {
	dialer     bimux.SessionDialer
	getSession chan asyncutil.Command[any, *bimux.ClientSideSession]
}

func NewSessionManager(dialer bimux.SessionDialer) *sessionManager {
	return &sessionManager{
		dialer:     dialer,
		getSession: make(chan asyncutil.Command[any, *bimux.ClientSideSession], 20),
	}
}

func (mgr *sessionManager) Start(ctx context.Context) {
	go func() {
		var session *bimux.ClientSideSession
		var backlog []asyncutil.Command[any, *bimux.ClientSideSession]
		for {
			select {
			case cmd := <-mgr.getSession:
				if session != nil && !session.IsClosed() {
					cmd.Return(session)
				} else {
					backlog = append(backlog, cmd)
					ch, err := mgr.dialer.Dial(ctx)
					if err != nil {
						return
					}
				}
			}
		}
	}()
}

func (mgr *sessionManager) Get() <-chan *bimux.ClientSideSession {

}
