// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

// Package tunnel defines an authenticated tunnel API, that allows creating byte
// pipes in both directions, initiated from either side of the tunnel.
package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http/httpproxy"

	calicoTLS "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/guardian/pkg/crypto"
)

// ErrTunnelClosed is used to notify a caller that an action can't proceed because the tunnel is closed
var ErrTunnelClosed = fmt.Errorf("tunnel closed")

// DialInRoutineWithTimeout calls dialer.Dial() in a routine and sends the result back on the given resultsChan. The
// timeout given is not the timeout for dialing (the implementation of the Dialer needs to take care of that), but used
// to timeout writing to the resultsChan in the event that the channel is blocked.
//
// The channel return is needed to signal the routine that we no longer need the result. This channel should be closed
// to send that signal, and is the responsibility of the caller to close that channel regardless.
func DialInRoutineWithTimeout(dialer Dialer, resultsChan chan interface{}, timeout time.Duration) chan struct{} {
	closeChan := make(chan struct{})

	go func() {
		defer close(resultsChan)

		logrus.Debug("Dialing tunnel")
		tun, err := dialer.Dial()

		var result interface{}
		if err != nil {
			result = err
		} else {
			result = tun
		}

		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case <-closeChan:
			logrus.Debug("Received signal to close, dropping dialing result.")
			return
		case resultsChan <- result:
		case <-timer.C:
			logrus.Error("Timed out trying to send the result over the results channel")
			return
		}

		logrus.Debug("Finished dialing tunnel.")
	}()

	return closeChan
}

// Dialer is an interface that supports dialing to create a *Tunnel
type Dialer interface {
	Dial() (*Tunnel, error)
	Timeout() time.Duration
}

type dialer struct {
	dialerFun     DialerFunc
	retryAttempts int
	retryInterval time.Duration
	timeout       time.Duration
}

// NewDialer creates a new Dialer.
func NewDialer(dialerFunc DialerFunc, retryAttempts int, retryInterval time.Duration, timeout time.Duration) Dialer {
	return &dialer{
		dialerFun:     dialerFunc,
		retryAttempts: retryAttempts,
		retryInterval: retryInterval,
		timeout:       timeout,
	}
}

func (d *dialer) Timeout() time.Duration {
	return d.timeout
}

func (d *dialer) Dial() (*Tunnel, error) {
	var err error
	for i := 0; i < d.retryAttempts; i++ {
		t, err := d.dialerFun()
		if err != nil {
			var xerr x509.UnknownAuthorityError
			if errors.As(err, &xerr) {
				logrus.WithError(err).Infof("TLS dial failed: %s. fingerprint='%s' issuerCommonName='%s' subjectCommonName='%s'", xerr.Error(), utils.GenerateFingerprint(xerr.Cert), xerr.Cert.Issuer.CommonName, xerr.Cert.Subject.CommonName)
			} else {
				logrus.WithError(err).Infof("TLS dial attempt %d failed, will retry in %s", i, d.retryInterval.String())
			}
			time.Sleep(d.retryInterval)
			continue
		}
		return t, nil
	}

	return nil, err
}

// DialerFunc is a function type used to create a tunnel
type DialerFunc func() (*Tunnel, error)

// Tunnel represents either side of the tunnel that allows waiting for,
// accepting and initiating creation of new BytePipes.
type Tunnel struct {
	stream io.ReadWriteCloser
	mux    *yamux.Session

	errOnce sync.Once
	errCh   chan struct{}
	LastErr error

	keepAliveEnable   bool
	keepAliveInterval time.Duration
	DialTimeout       time.Duration
}

type logrusWriter struct {
	log *logrus.Entry
}

func (l *logrusWriter) Write(p []byte) (n int, err error) {
	l.log.Info(string(p))
	return len(p), nil
}

func newTunnel(stream io.ReadWriteCloser, isServer bool, opts ...Option) (*Tunnel, error) {
	t := &Tunnel{
		stream: stream,
		errCh:  make(chan struct{}),
		// Defaults
		keepAliveEnable: true,

		keepAliveInterval: 100 * time.Millisecond,
		DialTimeout:       60 * time.Second,
	}

	var mux *yamux.Session
	var err error

	for _, o := range opts {
		if err := o(t); err != nil {
			return nil, errors.WithMessage(err, "applying option failed")
		}
	}

	// XXX all the config options should probably become options taken by New()
	// XXX that can override the defaults set here
	config := yamux.DefaultConfig()
	config.AcceptBacklog = 1000
	config.EnableKeepAlive = t.keepAliveEnable
	config.KeepAliveInterval = t.keepAliveInterval
	config.LogOutput = &logrusWriter{logrus.WithField("component", "tunnel-yamux")}

	if isServer {
		mux, err = yamux.Server(&serverCloser{
			ReadWriteCloser: stream,
			t:               t,
		},
			config)
	} else {
		mux, err = yamux.Client(stream, config)
	}

	if err != nil {
		return nil, fmt.Errorf("new failed creating muxer: %s", err)
	}

	t.mux = mux

	return t, nil
}

// NewServerTunnel returns a new tunnel that uses the provided stream as the
// carrier. The stream must be the server side of the stream
func NewServerTunnel(stream io.ReadWriteCloser, opts ...Option) (*Tunnel, error) {
	return newTunnel(stream, true, opts...)
}

// NewClientTunnel returns a new tunnel that uses the provided stream as the
// carrier. The stream must be the client side of the stream
func NewClientTunnel(stream io.ReadWriteCloser, opts ...Option) (*Tunnel, error) {
	return newTunnel(stream, false, opts...)
}

// Identity represents remote peer identity
// XXX the exact type TBD
type Identity = interface{}

type hasIdentity interface {
	Identity() Identity
}

// Close closes this end of the tunnel and so all existing connections
func (t *Tunnel) Close() error {
	defer logrus.Debugf("Tunnel: Closed")
	return convertYAMUXErr(t.mux.Close())
}

// IsClosed checks if the tunnel is closed. If it is true is returned, otherwise false is returned
func (t *Tunnel) IsClosed() bool {
	return t.mux.IsClosed()
}

// Accept waits for a new connection, returns net.Conn or an error
func (t *Tunnel) Accept() (net.Conn, error) {
	logrus.Debugf("Tunnel: Accepting connections")
	defer logrus.Debugf("Tunnel: Accepted connection")
	conn, err := t.mux.Accept()
	return conn, convertYAMUXErr(err)
}

// AcceptWithChannel takes a channel of ConnWithError, kicks of a go routine that starts accepting connection, and sends
// any connections received to the given channel. The channel returned from calling this function is used to signal that
// we're done accepting connections.
//
// If the tunnel hasn't been setup prior to calling this function it will panic.
func (t *Tunnel) AcceptWithChannel(acceptChan chan interface{}) chan bool {
	a := acceptChan
	done := make(chan bool)
	go func() {
		logrus.Debug("tunnel writing connections to new channel")
		defer func() {
			logrus.Debug("tunnel finished writing connections to new channel")
			close(a)
		}()

		for {
			conn, err := t.mux.Accept()
			select {
			case <-done:
				return
			default:
			}
			if err == nil {
				a <- conn
			} else {
				err = convertYAMUXErr(err)
				// if the tunnel is closed we're done
				if err == ErrTunnelClosed {
					return
				}

				a <- err
			}
		}
	}()

	return done
}

// AcceptStream waits for a new connection, returns io.ReadWriteCloser or an error
func (t *Tunnel) AcceptStream() (io.ReadWriteCloser, error) {
	logrus.Debugf("Tunnel: Accepting stream")
	defer logrus.Debugf("Tunnel: Accepted stream")
	rc, err := t.mux.AcceptStream()
	return rc, convertYAMUXErr(err)
}

// Addr returns the address of this tunnel sides endpoint.
func (t *Tunnel) Addr() net.Addr {
	a := addr{
		net: "voltron-tunnel",
	}

	if n, ok := t.stream.(net.Conn); ok {
		a.addr = n.LocalAddr().String()
	}

	return a
}

// Open opens a new net.Conn to the other side of the tunnel. Returns when
// the the new connection is set up
func (t *Tunnel) Open() (net.Conn, error) {
	c, err := t.mux.Open()
	err = convertYAMUXErr(err)
	t.checkErr(err)
	return c, err
}

// OpenStream returns, unlike NewConn, an io.ReadWriteCloser
func (t *Tunnel) OpenStream() (io.ReadWriteCloser, error) {
	s, err := t.mux.OpenStream()
	err = convertYAMUXErr(err)
	t.checkErr(err)
	return s, err
}

// Identity provides the identity of the remote side that initiated the tunnel
func (t *Tunnel) Identity() Identity {
	if id, ok := t.stream.(hasIdentity); ok {
		return id.Identity()
	}

	return nil
}

// WaitForError blocks as long as the tunnel exists and will return the reason
// why the tunnel exited
func (t *Tunnel) WaitForError() error {
	<-t.errCh
	return t.LastErr
}

// ErrChan returns the channel that's notified when an error occurs
func (t *Tunnel) ErrChan() chan struct{} {
	return t.errCh
}

func (t *Tunnel) checkErr(err error) {
	if err != nil {
		t.errOnce.Do(func() {
			t.LastErr = err
			close(t.errCh)
		})
	}
}

type serverCloser struct {
	io.ReadWriteCloser
	t *Tunnel
}

func (sc *serverCloser) Close() error {
	sc.t.checkErr(errors.New("closed by multiplexer"))
	return sc.ReadWriteCloser.Close()
}

type addr struct {
	net  string
	addr string
}

func (a addr) Network() string {
	return a.net
}

func (a addr) String() string {
	return a.addr
}

// Dial returns a client side Tunnel or an error
func Dial(target string, opts ...Option) (*Tunnel, error) {
	c, err := net.Dial("tcp", target)
	if err != nil {
		return nil, fmt.Errorf("tcp.Dial failed: %v", err)
	}

	return NewClientTunnel(c, opts...)
}

// DialTLS creates a TLS connection based on the config, must not be nil.
func DialTLS(target string, tunnelTLSConfig *tls.Config, timeout time.Duration, httpProxyURL *url.URL, opts ...Option) (*Tunnel, error) {
	if tunnelTLSConfig == nil {
		return nil, errors.New("nil config")
	}
	logrus.Infof("Starting TLS dial to %s with a timeout of %v", target, timeout)

	// First, establish the mTLS connection that serves as the basis of the tunnel.
	var c net.Conn
	var err error
	dialer := newDialer(timeout)
	if httpProxyURL != nil {
		// mTLS will be negotiated over a TCP connection to the proxy, which performs TCP passthrough to the target.
		logrus.Infof("Dialing to %s via HTTP proxy at %s", target, httpProxyURL)
		c, err = tlsDialViaHTTPProxy(dialer, target, httpProxyURL, tunnelTLSConfig, calicoTLS.NewTLSConfig())
		if err != nil {
			return nil, fmt.Errorf("TLS dial via HTTP proxy failed: %w", err)
		}
	} else {
		// mTLS will be negotiated over a TCP connection directly to the target.
		logrus.Infof("Dialing directly to %s", target)
		c, err = tls.DialWithDialer(dialer, "tcp", target, tunnelTLSConfig)
		if err != nil {
			return nil, fmt.Errorf("TLS dial failed: %w", err)
		}
	}
	logrus.Infof("TLS dial to %s succeeded: basis connection for the tunnel has been established", target)

	// Then, create the tunnel on top of the mTLS connection.
	return NewClientTunnel(c, append(opts, WithDialTimeout(timeout))...)
}

// GetHTTPProxyURL resolves the proxy URL that should be used for the tunnel target. It respects HTTPS_PROXY and NO_PROXY
// environment variables (case-insensitive).
func GetHTTPProxyURL(target string) (*url.URL, error) {
	targetURL := &url.URL{
		// The scheme should be HTTPS, as we are establishing an mTLS session with the target.
		Scheme: "https",

		// We expect `target` to be of the form host:port.
		Host: target,
	}

	proxyURL, err := httpproxy.FromEnvironment().ProxyFunc()(targetURL)
	if err != nil {
		return nil, err
	}

	if proxyURL == nil {
		return nil, nil
	}

	// Validate the URL scheme.
	if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
		return nil, fmt.Errorf("proxy URL had invalid scheme (%s) - must be http or https", proxyURL.Scheme)
	}

	// Update the host if we can infer a port number.
	if proxyURL.Port() == "" && proxyURL.Scheme == "http" {
		proxyURL.Host = net.JoinHostPort(proxyURL.Host, "80")
	} else if proxyURL.Port() == "" && proxyURL.Scheme == "https" {
		proxyURL.Host = net.JoinHostPort(proxyURL.Host, "443")
	}

	return proxyURL, nil
}

func newDialer(timeout time.Duration) *net.Dialer {
	// We need to explicitly set the timeout as it seems it's possible for this to hang indefinitely if we don't.
	return &net.Dialer{
		Timeout: timeout,
	}
}

func tlsDialViaHTTPProxy(d *net.Dialer, destination string, proxyTargetURL *url.URL, tunnelTLS *tls.Config, proxyTLS *tls.Config) (net.Conn, error) {
	// Establish the TCP connection to the proxy.
	var c net.Conn
	var err error
	if proxyTargetURL.Scheme == "https" {
		c, err = tls.DialWithDialer(d, "tcp", proxyTargetURL.Host, proxyTLS)
	} else {
		c, err = d.DialContext(context.Background(), "tcp", proxyTargetURL.Host)
	}
	if err != nil {
		return nil, fmt.Errorf("dialing proxy %q failed: %v", proxyTargetURL.Host, err)
	}

	// Build the HTTP CONNECT request.
	var requestBuilder strings.Builder
	requestBuilder.WriteString(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", destination, destination))
	if proxyTargetURL.User != nil {
		username := proxyTargetURL.User.Username()
		password, _ := proxyTargetURL.User.Password()
		encodedCredentials := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		requestBuilder.WriteString(fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", encodedCredentials))
	}
	requestBuilder.WriteString("\r\n")

	// Send the HTTP CONNECT request to the proxy.
	_, err = fmt.Fprint(c, requestBuilder.String())
	if err != nil {
		return nil, fmt.Errorf("writing HTTP CONNECT to proxy %s failed: %v", proxyTargetURL.Host, err)
	}
	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("reading HTTP response from CONNECT to %s via proxy %s failed: %v", destination, proxyTargetURL.Host, err)
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("proxy error from %s while dialing %s: %v", proxyTargetURL.Host, destination, res.Status)
	}
	if br.Buffered() > 0 {
		// After the CONNECT was handled by the server, the client should be the first to talk to initiate the TLS handshake.
		// If we reach this point, the server spoke before the client, so something went wrong.
		return nil, fmt.Errorf("unexpected %d bytes of buffered data from CONNECT proxy %q", br.Buffered(), proxyTargetURL.Host)
	}

	// When we've reached this point, the proxy should now passthrough any TCP segments written to our connection to the destination.
	// Any TCP segments sent by the destination should also be readable on our connection.

	// Negotiate mTLS on top of our passthrough connection.
	mtlsC := tls.Client(c, tunnelTLS)
	if err := mtlsC.HandshakeContext(context.Background()); err != nil {
		mtlsC.Close()
		return nil, err
	}
	return mtlsC, nil
}

// We don't want to / need to expose that we're using the yamux library
func convertYAMUXErr(err error) error {
	switch err {
	case yamux.ErrSessionShutdown:
		return ErrTunnelClosed
	case io.EOF:
		return ErrTunnelClosed
	}

	return err
}
