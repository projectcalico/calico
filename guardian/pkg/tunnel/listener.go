package tunnel

import (
	"net"
	"sync"
)

// listener implements the net.Listener interface and is used by the Manager to allow components to listen for connections
// over the tunnel
type listener struct {
	conns     chan interface{}
	done      chan bool
	close     chan bool
	addr      net.Addr
	closeOnce sync.Once
}

// Accept waits for a connection to be opened from the other side of the connection and returns it.
func (l *listener) Accept() (net.Conn, error) {
	select {
	case inf, ok := <-l.conns:
		// a closed channel signals that the tunnel has been closed
		if !ok {
			return nil, ErrTunnelClosed
		}
		return InterfaceToConnOrError(inf)
	case <-l.close:
		return nil, ErrManagerClosed
	}
}

// Close closes the listener. A closed listener cannot be used again
func (l *listener) Close() error {
	l.closeOnce.Do(func() {
		if l.done != nil {
			close(l.done)
		}
	})

	return nil
}

func (l *listener) Addr() net.Addr {
	return l.addr
}
