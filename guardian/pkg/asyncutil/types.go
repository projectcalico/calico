package asyncutil

type Command[P any, R any] struct {
	params     P
	resultChan chan Result[R]
}

func NewCommand[P any, R any](params P) (Command[P, R], chan Result[R]) {
	resultChan := make(chan Result[R], 1)
	return Command[P, R]{params: params, resultChan: resultChan}, resultChan
}

type Result[V any] struct {
	value V
	err   error
}

func (r Result[V]) Result() (V, error) {
	return r.value, r.err
}

func (c Command[C, R]) Get() C {
	return c.params
}

func (c Command[C, R]) Return(result R) {
	defer close(c.resultChan)
	c.resultChan <- Result[R]{value: result}
}

func (c Command[C, R]) ReturnError(err error) {
	defer close(c.resultChan)

	select {
	case c.resultChan <- Result[R]{err: err}:
	default:
		panic("result channel is full, this should never happen since only one result should ever be written")
	}
}

type Signaler interface {
	Send()
	Receive() <-chan struct{}
	Close()
}

type signaler struct {
	ch chan struct{}
}

func (s *signaler) Send() {
	// If the channel is full we don't need to wait to send another signal, there's already an unprocessed signal.
	WriteNoWait(s.ch, struct{}{})
}

func (s *signaler) Receive() <-chan struct{} {
	return s.ch
}

func (s *signaler) Close() {
	close(s.ch)
}

func NewSignaler() Signaler {
	return &signaler{ch: make(chan struct{}, 1)}
}

type AsyncErrorBuffer interface {
	Write(err error)
	Receive() <-chan error
	Close()
	Clear()
}

type asyncErrorBuffer struct {
	clearing bool
	errs     chan error
}

func NewAsyncErrorBuffer() AsyncErrorBuffer {
	return &asyncErrorBuffer{errs: make(chan error, 1)}
}

// Write writes the error to the buffer. If the buffer is full the error is dropped.
func (b *asyncErrorBuffer) Write(err error) {
	WriteNoWait(b.errs, err)
}

func (b *asyncErrorBuffer) Receive() <-chan error {
	return b.errs
}

func (b *asyncErrorBuffer) Close() {
	close(b.errs)
}

// Clear drains the internal buffer and returns when there's nothing left.
// Not that writing to the error buffer should not be done while clearing, since if writing is happening as quick
// as clearing is then the buffer will never be cleared.
func (b *asyncErrorBuffer) Clear() {
	Clear(b.errs)
}
