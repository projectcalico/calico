package asyncutil

type SyncedError struct {
	errs  chan error
	pause chan bool
}

func NewSyncedError() *SyncedError {
	return &SyncedError{
		errs:  make(chan error, 1),
		pause: make(chan bool, 1),
	}
}

func (e *SyncedError) Error() <-chan error {
	return e.errs
}

func (e *SyncedError) Pause() {
	WriteNoWait(e.pause, true)
}

func (e *SyncedError) Resume() {
	ReadNoWait(e.pause)
}

func (e *SyncedError) Send(err error) {
	select {
	case e.pause <- true:
		WriteNoWait(e.errs, err)
		ReadNoWait(e.pause)
		return
	default:
	}
}

func (e *SyncedError) Close() {
	close(e.errs)
}
