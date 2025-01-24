package aggregator

import (
	"context"
	"github.com/google/uuid"
	_chan "github.com/projectcalico/calico/goldmane/pkg/chan"
	"github.com/sirupsen/logrus"
	"time"

	"github.com/projectcalico/calico/goldmane/proto"
)

type Listener struct {
	id     uuid.UUID
	ch     chan *proto.Flow
	doneCh chan *Listener
}

func (l *Listener) Listen() roFlowStream {
	return l.ch
}

func (l *Listener) Close() {
	l.doneCh <- l
}

type outPutter struct {
	ch                 chan *proto.Flow
	getListenerChan    chan *channelRequest[Listener]
	removeListenerChan chan *Listener
}

func newOutPutter() *outPutter {
	return &outPutter{
		ch:                 make(chan *proto.Flow, 20),
		getListenerChan:    make(chan *channelRequest[Listener], 20),
		removeListenerChan: make(chan *Listener, 20),
	}
}

type chanHandler struct {
	listeners map[uuid.UUID]Listener
}

// TODO use ctx not channnel.
func (o *outPutter) Run(done chan struct{}) {
	handler := chanHandler{listeners: make(map[uuid.UUID]Listener)}
	for {
		select {
		case req := <-o.ch:
			handler.sendFlow(req)
		case req := <-o.getListenerChan:
			handler.getListener(req, o.removeListenerChan)
		case req := <-o.removeListenerChan:
			handler.removeListener(req)
		case <-done:
			return
		}
	}
}

func (o *chanHandler) getListener(rsp *channelRequest[Listener], done chan *Listener) {
	listener := Listener{id: uuid.New(), ch: make(chan *proto.Flow), doneCh: done}

	logrus.WithField("id", listener.id).Debug("New listener created.")
	o.listeners[listener.id] = listener
	rsp.Return(listener)
}

func (o *chanHandler) sendFlow(flow *proto.Flow) {
	for _, listener := range o.listeners {
		logrus.WithField("id", listener.id).Debug("Sending flow to listener.")
		if _chan.WriteWithTimeout(context.Background(), 2*time.Second, listener.ch, flow) {
			logrus.Warn("Failed to write flow to listener, removing it.")
			close(listener.ch)
			delete(o.listeners, listener.id)
		}
		logrus.WithField("id", listener.id).Debug("Finished sending flow to listener.")
	}
}

func (o *chanHandler) removeListener(listener *Listener) {
	logrus.WithField("id", listener.id).Debug("server.go Removing Listener..")
	close(listener.ch)
	delete(o.listeners, listener.id)
}

func (o *outPutter) Put(f *proto.Flow) {
	// TODO propagate the ctx.
	if _chan.WriteWithTimeout(context.Background(), 5*time.Second, o.ch, f) {
		logrus.Warn("Failed to put flow.")
	}
}

func (o *outPutter) GetListener() Listener {
	return sendChan(o.getListenerChan)
}

func sendChan[E any](writeChan chan *channelRequest[E]) E {
	req := newChannelRequest[E]()
	writeChan <- req
	return req.Get()
}
