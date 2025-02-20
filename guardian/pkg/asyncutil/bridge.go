package asyncutil

type CommandBridge[Req any, Resp any] interface {
	Send(req Req) (Resp, error)
	Receive() <-chan Command[Req, Resp]
	Close()
}

type bridge[Req any, Resp any] struct {
	ch chan Command[Req, Resp]
}

func NewBridge[Req any, Resp any](bufferSize int) CommandBridge[Req, Resp] {
	return &bridge[Req, Resp]{ch: make(chan Command[Req, Resp], bufferSize)}
}

func (srv *bridge[Req, Resp]) Send(req Req) (Resp, error) {
	rspChan := make(chan Result[Resp])

	// TODO should we add the timeout back in?
	srv.ch <- Command[Req, Resp]{req: req, rspChan: rspChan}
	// TODO need to ensure some other kind of timeout... maybe??
	rsp := <-rspChan
	return rsp.resp, rsp.err
}

func (srv *bridge[Req, Resp]) Receive() <-chan Command[Req, Resp] {
	return srv.ch
}

func (srv *bridge[Req, Resp]) Close() {
	close(srv.ch)
}
