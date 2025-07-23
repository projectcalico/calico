package bimux

import (
	"github.com/hashicorp/yamux"
	"net"
)

type Session interface {
	Addr() net.Addr
	Open() (net.Conn, error)
	Accept() (net.Conn, error)
	Close() error
}

type session struct {
	mux *yamux.Session
}

func (s *session) Addr() net.Addr {
	return s.mux.Addr()
}

func (s *session) Open() (net.Conn, error) {
	return s.mux.Open()
}

func (s *session) Accept() (net.Conn, error) {
	return s.mux.Accept()
}

func (s *session) Close() error {
	return s.mux.Close()
}

func (s *session) IsClosed() bool {
	return s.mux.IsClosed()
}

func (s *session) WaitForClose() {
	s.mux.CloseChan()
}

type ClientSession struct {
	session
}

func newClientSession(s *yamux.Session) *ClientSession {
	return &ClientSession{session: session{s}}
}

type ServerSession[T any] struct {
	session

	identity *T
}

func newServerSideSession[T any](mux *yamux.Session, identity *T) *ServerSession[T] {
	return &ServerSession[T]{identity: identity, session: session{mux: mux}}
}
