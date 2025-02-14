package tunnel_test

import (
	"context"
	"errors"
	. "github.com/onsi/gomega"
	netmocks "github.com/projectcalico/calico/guardian/pkg/thirdpartymocks/net"
	"io"
	"testing"

	"github.com/projectcalico/calico/guardian/pkg/tunnel"
	tunmocks "github.com/projectcalico/calico/guardian/pkg/tunnel/mocks"
)

func TestTunnelOpenConnection(t *testing.T) {
	setupTest(t)

	mockConn := new(netmocks.Conn)
	mockDialer := new(tunmocks.SessionDialer)
	mockSession := new(tunmocks.Session)
	mockDialer.On("Dial").Return(mockSession, nil)
	mockSession.On("Close").Return(nil)
	mockSession.On("Open").Return(mockConn, nil)

	tun, err := tunnel.NewTunnel(mockDialer)
	Expect(err).NotTo(HaveOccurred())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	Expect(tun.Connect(ctx)).ShouldNot(HaveOccurred())
	con, err := tun.Open(ctx)
	Expect(err).NotTo(HaveOccurred())
	Expect(con).NotTo(BeNil())
}

func TestTunnelOpenConnectionWithFailures(t *testing.T) {
	setupTest(t)

	mockConn := new(netmocks.Conn)
	mockDialer := new(tunmocks.SessionDialer)
	mockSession := new(tunmocks.Session)
	mockDialer.On("Dial").Return(mockSession, nil)
	mockSession.On("Close").Return(nil)
	mockSession.On("Open").Return(nil, io.EOF).Once()
	mockSession.On("Open").Return(mockConn, nil).Once()

	tun, err := tunnel.NewTunnel(mockDialer)
	Expect(err).NotTo(HaveOccurred())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	Expect(tun.Connect(ctx)).ShouldNot(HaveOccurred())
	con, err := tun.Open(ctx)
	Expect(err).NotTo(HaveOccurred())
	Expect(con).NotTo(BeNil())
}

func TestTunnelOpenConnectionWithFatalError(t *testing.T) {
	setupTest(t)

	mockConn := new(netmocks.Conn)
	mockDialer := new(tunmocks.SessionDialer)
	mockSession := new(tunmocks.Session)
	mockDialer.On("Dial").Return(mockSession, nil)
	mockSession.On("Close").Return(nil)
	mockSession.On("Open").Return(nil, errors.New("some error")).Once()
	mockSession.On("Open").Return(mockConn, nil).Once()

	tun, err := tunnel.NewTunnel(mockDialer)
	Expect(err).NotTo(HaveOccurred())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	Expect(tun.Connect(ctx)).ShouldNot(HaveOccurred())
	con, err := tun.Open(ctx)
	Expect(err).Should(HaveOccurred())
	Expect(con).Should(BeNil())
}

func TestTunnelAcceptConnection(t *testing.T) {
	setupTest(t)

	mockConn := new(netmocks.Conn)
	mockDialer := new(tunmocks.SessionDialer)
	mockSession := new(tunmocks.Session)
	mockDialer.On("Dial").Return(mockSession, nil)
	mockSession.On("Close").Return(nil)
	mockSession.On("Accept").Return(mockConn, nil)

	tun, err := tunnel.NewTunnel(mockDialer)
	Expect(err).NotTo(HaveOccurred())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	Expect(tun.Connect(ctx)).ShouldNot(HaveOccurred())
	listener, err := tun.Listener(ctx)
	Expect(err).NotTo(HaveOccurred())
	Expect(listener).NotTo(BeNil())

	conn, err := listener.Accept()
	Expect(err).NotTo(HaveOccurred())
	Expect(conn).NotTo(BeNil())
}
