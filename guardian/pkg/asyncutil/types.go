package asyncutil

type Command[C any, R any] struct {
	req     C
	rspChan chan Result[R]
}

type Result[Resp any] struct {
	resp Resp
	err  error
}

func (c Command[C, R]) Get() C {
	return c.req
}

func (c Command[C, R]) Return(result R) {
	defer close(c.rspChan)
	c.rspChan <- Result[R]{resp: result}
}

func (c Command[C, R]) ReturnError(err error) {
	defer close(c.rspChan)
	c.rspChan <- Result[R]{err: err}
}

type Signaler interface {
	Send()
	Wait() <-chan struct{}
	Close()
}

type signaler struct {
	ch chan struct{}
}

func (s *signaler) Send() {
	WriteNoWait(s.ch, struct{}{})
}

func (s *signaler) Wait() <-chan struct{} {
	return s.ch
}

func (s *signaler) Close() {
	close(s.ch)
}

func NewSignaler() Signaler {
	return &signaler{ch: make(chan struct{}, 1)}
}
