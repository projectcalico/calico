package conn

import (
	"errors"
	"net"
	"time"

	"github.com/projectcalico/calico/guardian/pkg/bytes"
)

var ErrAttemptedWrite = errors.New("attempted to write to the connection")

// ReadOnly implements the net.Conn interface, wraps another net.Conn, and only allows reads from the connection it's
// wrapping. The bytes readOnlyConn reads are stored and can be retrieved by a call to BytesRead. If a write is attempted
// then ErrAttemptedWrite is returned.
type ReadOnly interface {
	net.Conn
	BytesRead() []byte
}

type readOnlyConn struct {
	conn   net.Conn
	byteBB bytes.BucketBrigade
}

func NewReadOnly(conn net.Conn) ReadOnly {
	return &readOnlyConn{
		conn: conn,
	}
}

func (roc *readOnlyConn) Read(b []byte) (int, error) {
	i, err := roc.conn.Read(b)
	if i > 0 {
		roc.byteBB.Append(b[0:i])
	}

	return i, err
}

func (roc *readOnlyConn) Write(b []byte) (int, error) {
	return 0, ErrAttemptedWrite
}

func (roc *readOnlyConn) Close() error {
	return nil
}

func (roc *readOnlyConn) LocalAddr() net.Addr {
	return roc.conn.LocalAddr()
}

func (roc *readOnlyConn) RemoteAddr() net.Addr {
	return roc.conn.RemoteAddr()
}

func (roc *readOnlyConn) SetDeadline(t time.Time) error {
	return nil
}

func (roc *readOnlyConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (roc *readOnlyConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (roc *readOnlyConn) BytesRead() []byte {
	return roc.byteBB.Flatten()
}
