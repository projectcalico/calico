package tunnel

import (
	"crypto/tls"
	"fmt"
	"net"
)

// InterfaceToError casts an interface to an error or nil, and panics otherwise
func InterfaceToError(i interface{}) error {
	switch t := i.(type) {
	case nil:
		return nil
	case error:
		return i.(error)
	default:
		panic(fmt.Sprintf("unexpected type %T", t))
	}
}

// InterfaceToConnOrError casts an interface to a net.Conn, and error, or nil, and panics otherwise. One of the two return
// types will be nil
func InterfaceToConnOrError(i interface{}) (net.Conn, error) {
	switch t := i.(type) {
	case nil:
		return nil, nil
	case error:
		return nil, i.(error)
	case net.Conn:
		return i.(net.Conn), nil
	default:
		panic(fmt.Sprintf("unexpected type %T", t))
	}
}

// InterfaceToListenerOrError casts an interface to a net.Listener, and error, or nil, and panics otherwise. One of the two return
// types will be nil
func InterfaceToListenerOrError(i interface{}) (net.Listener, error) {
	switch t := i.(type) {
	case nil:
		return nil, nil
	case error:
		return nil, i.(error)
	case net.Listener:
		return i.(net.Listener), nil
	default:
		panic(fmt.Sprintf("unexpected type %T", t))
	}
}

// InterfaceToErrorChan casts an interface to a chan error or nil, and panics otherwise
func InterfaceToErrorChan(i interface{}) chan error {
	switch t := i.(type) {
	case nil:
		return nil
	case chan error:
		return i.(chan error)
	default:
		panic(fmt.Sprintf("unexpected type %T", t))
	}
}

// InterfaceToTLSConfig casts an interface to a *tls.Config or nil, and panics otherwise
func InterfaceToTLSConfig(i interface{}) *tls.Config {
	switch t := i.(type) {
	case nil:
		return nil
	case *tls.Config:
		return i.(*tls.Config)
	default:
		panic(fmt.Sprintf("unexpected type %T", t))
	}
}

// InterfaceToTunnel casts an interface to a *Tunnel or nil, and panics otherwise
func InterfaceToTunnel(i interface{}) *Tunnel {
	switch t := i.(type) {
	case nil:
		return nil
	case *Tunnel:
		return i.(*Tunnel)
	default:
		panic(fmt.Sprintf("unexpected type %T", t))
	}
}

// InterfaceToDialer casts an interface to a Dialer or nil, and panics otherwise
func InterfaceToDialer(i interface{}) Dialer {
	switch t := i.(type) {
	case nil:
		return nil
	case Dialer:
		return i.(Dialer)
	default:
		panic(fmt.Sprintf("unexpected type %T", t))
	}
}
