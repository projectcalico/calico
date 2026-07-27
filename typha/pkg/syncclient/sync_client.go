// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package syncclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/snappy"
	log "github.com/sirupsen/logrus"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/readlogger"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/jitter"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
	"github.com/projectcalico/calico/typha/pkg/tlsutils"
)

var nextID atomic.Uint64

func init() {
	// ID is used as a correlator in the Typha logs.  Put some entropy in
	// it so it's easy to grep for.
	nextID.Store(rand.Uint64() << 32)
}

func allocateConnID() uint64 {
	return nextID.Add(1)
}

const (
	defaultReadtimeout  = 30 * time.Second
	defaultWriteTimeout = 10 * time.Second

	// defaultRebalanceInterval is the base period between checks of whether the
	// client is connected to its preferred Typha.  It is deliberately long: the
	// goal is to migrate clients onto their preferred Typha slowly, over roughly
	// this timescale, so that topology changes don't cause a thundering herd of
	// reconnections.  The check timer is jittered to spread the load further.
	defaultRebalanceInterval = time.Hour

	// rebalanceGoodbyeReason is sent to the server (in MsgClientGoodbye) when we
	// disconnect to rebalance, so the server can log why the client left.
	rebalanceGoodbyeReason = "rebalancing to preferred Typha instance"
)

type Options struct {
	ReadTimeout    time.Duration
	ReadBufferSize int
	WriteTimeout   time.Duration
	KeyFile        string
	CertFile       string
	CAFile         string
	ServerCN       string
	ServerURISAN   string
	SyncerType     syncproto.SyncerType

	// RebalanceInterval controls how often the client re-evaluates whether it is
	// connected to its preferred Typha and, if not, deliberately disconnects so
	// that it reconnects onto the preferred instance.  The check runs on a
	// jittered timer; this is the base interval.  Zero selects the default
	// (defaultRebalanceInterval); a negative value disables rebalancing.
	// Rebalancing only happens for restart-aware clients (see
	// RestartAwareCallbacks) since it relies on the client reconnecting; for
	// other clients this is ignored.
	RebalanceInterval time.Duration

	// DisableDecoderRestart disables decoder restart and the features that depend on
	// it (such as compression).  Useful for simulating an older client in UT.
	DisableDecoderRestart bool

	// DebugLogReads tells the client to wrap each connection with a Reader that
	// logs every read.  Intended only for use in tests!
	DebugLogReads bool

	// DebugDiscardKVUpdates discards all KV updates from typha without decoding them.
	// Useful for load testing Typha without having to run a "full" client.
	DebugDiscardKVUpdates bool
}

func (o *Options) readTimeout() time.Duration {
	if o == nil || o.ReadTimeout <= 0 {
		return defaultReadtimeout
	}
	return o.ReadTimeout
}

func (o *Options) writeTimeout() time.Duration {
	if o == nil || o.WriteTimeout <= 0 {
		return defaultWriteTimeout
	}
	return o.WriteTimeout
}

// rebalanceInterval returns the configured base interval between rebalance
// checks.  Zero maps to the default; a negative value is returned as-is and
// signals (via rebalanceEnabled) that rebalancing is disabled.
func (o *Options) rebalanceInterval() time.Duration {
	if o == nil || o.RebalanceInterval == 0 {
		return defaultRebalanceInterval
	}
	return o.RebalanceInterval
}

func (o *Options) requiringTLS() bool {
	// True if any of the TLS parameters are set.
	requiringTLS := o != nil && o.KeyFile+o.CertFile+o.CAFile+o.ServerCN+o.ServerURISAN != ""
	log.WithField("requiringTLS", requiringTLS).Info("")
	return requiringTLS
}

func (o *Options) validate() (err error) {
	// If any client-side TLS options are specified, they _all_ must be - except that either
	// ServerCN or ServerURISAN may be left unset.
	if o.requiringTLS() {
		// Some TLS options specified.
		if o.KeyFile == "" ||
			o.CertFile == "" ||
			o.CAFile == "" ||
			(o.ServerCN == "" && o.ServerURISAN == "") {
			err = errors.New("if any Felix-Typha TLS options are specified," +
				" they _all_ must be" +
				" - except that either ServerCN or ServerURISAN may be left unset")
		}
	}
	return
}

func New(
	discoverer *discovery.Discoverer,
	myVersion, myHostname, myInfo string,
	cbs api.SyncerCallbacks,
	options *Options,
) *SyncerClient {
	if err := options.validate(); err != nil {
		log.WithField("options", options).WithError(err).Fatal("Invalid options")
	}
	if options == nil {
		options = &Options{}
	}
	sc := &SyncerClient{
		logCxt: log.WithFields(log.Fields{
			"type": options.SyncerType,
		}),
		callbacks:          cbs,
		discoverer:         discoverer,
		connAttemptTracker: discovery.NewConnAttemptTracker(discoverer),

		myVersion:  myVersion,
		myHostname: myHostname,
		myInfo:     myInfo,

		options: options,
	}
	sc.refreshConnID()
	return sc
}

func (s *SyncerClient) refreshConnID() {
	s.connID = allocateConnID()
	s.logCxt.Data["myID"] = s.connID
}

type SyncerClient struct {
	logCxt                        *log.Entry
	discoverer                    *discovery.Discoverer
	connAttemptTracker            *discovery.ConnectionAttemptTracker
	connInfo                      *discovery.Typha
	myHostname, myVersion, myInfo string
	options                       *Options

	connection net.Conn
	connID     uint64
	connR      io.Reader
	decoder    *gob.Decoder

	// writeLock serialises writes to the connection and guards the encoder and
	// writesClosed flag.  The read loop (pongs/acks) and the rebalance goroutine
	// (the goodbye message) can both write, so writes must be serialised.
	writeLock sync.Mutex
	encoder   *gob.Encoder
	// writesClosed is latched true once we've sent our goodbye message.  After
	// that, no further message is written, guaranteeing the goodbye is the last
	// thing on the wire before the socket closes.  Reset for each connection.
	writesClosed bool

	callbacks api.SyncerCallbacks
	Finished  sync.WaitGroup
}

type RestartAwareCallbacks interface {
	api.SyncerCallbacks
	OnTyphaConnectionRestarted()
}

func (s *SyncerClient) Start(cxt context.Context) error {
	// Connect synchronously so that we can return an error early if we can't connect at all.
	s.logCxt.Info("Starting Typha client...")

	var connectionFinishedWG sync.WaitGroup
	err := s.startOneConnection(cxt, &connectionFinishedWG)
	if err != nil {
		return err
	}

	// Start a background goroutine to try to restart the connection if it fails.
	// We can only do that if the client is restart-aware.
	s.Finished.Add(1)
	go func() {
		defer func() {
			s.logCxt.Info("Typha client shutting down.")
			s.Finished.Done()
		}()

		for cxt.Err() == nil {
			connectionFinishedWG.Wait()
			if rac, ok := s.callbacks.(RestartAwareCallbacks); ok {
				log.Info("Typha connection failed but client callback is restart-aware.  Restarting connection...")
				s.refreshConnID()
				rac.OnTyphaConnectionRestarted()
				s.callbacks.OnStatusUpdated(api.WaitForDatastore)
			} else {
				log.Info("Typha client callback is not restart-aware. Exiting...")
				return
			}
			err := s.startOneConnection(cxt, &connectionFinishedWG)
			if err != nil {
				log.WithError(err).Error("Failed to restart Typha client. Exiting...")
				return
			}
		}
	}()

	return nil
}

func (s *SyncerClient) startOneConnection(cxt context.Context, connFinished *sync.WaitGroup) error {
	// Defensive: in case there's a bug in NextAddr() and it never stops returning values,
	// set a sanity limit on the number of tries.
	startTime := time.Now()
	maxTries := s.calculateConnectionAttemptLimit(len(s.discoverer.CachedTyphaAddrs()))
	remainingTries := maxTries
	for {
		remainingTries--
		if remainingTries < 0 {
			return fmt.Errorf("failed to connect to Typha after %d tries", maxTries)
		}
		addr, err := s.connAttemptTracker.NextAddr()
		if err != nil {
			return fmt.Errorf("failed to load next Typha address to try: %w", err)
		}
		s.logCxt.Infof("Connecting to typha endpoint %s.", addr.Addr)
		err = s.connect(cxt, addr)
		if err != nil {
			s.logCxt.WithError(err).Warnf("Failed to connect to typha endpoint %s.  Will try another if available...", addr.Addr)
			time.Sleep(100 * time.Millisecond) // Avoid tight loop.
		} else {
			s.logCxt.Infof("Successfully connected to Typha at %s after %v.", addr.Addr, time.Since(startTime))
			break
		}
	}

	// Then start our background goroutines.  We start the main loop and a second goroutine to
	// manage shutdown.
	connCtx, cancelFn := context.WithCancel(cxt)
	connFinished.Add(1)
	go s.loop(connCtx, cancelFn, connFinished)

	connFinished.Go(func() {
		// Broadcast that we're finished.

		// Wait for the context to finish, either due to external cancel or our own loop
		// exiting.
		<-connCtx.Done()
		s.logCxt.Info("Typha client Context asked us to exit, closing connection...")
		// Close the connection.  This will trigger the main loop to exit if it hasn't
		// already.
		err := s.connection.Close()
		if err != nil {
			log.WithError(err).Warn("Ignoring error from Close during shut-down of client.")
		}
	})
	return nil
}

func (s *SyncerClient) calculateConnectionAttemptLimit(numDiscoveredTyphas int) int {
	expectedNumTyphas := max(numDiscoveredTyphas,
		// Most clusters have at least 3 Typha instances so, if we discovered fewer instances,
		// assume that there may be more starting up.
		3)
	// During upgrade, we expect all Typha instances to be replaced one by one so, for a safe
	// upper bound on the number of potential connection attempts, assume that we try to connect
	// to double the number of instances that we detected.
	maxTries := expectedNumTyphas * 2
	return maxTries
}

func (s *SyncerClient) connect(cxt context.Context, typhaAddr discovery.Typha) error {
	log.Info("Starting Typha client")
	var err error
	logCxt := s.logCxt.WithField("address", typhaAddr)

	var connFunc func(string) (net.Conn, error)
	if s.options.requiringTLS() {
		cert, err := tls.LoadX509KeyPair(s.options.CertFile, s.options.KeyFile)
		if err != nil {
			log.WithError(err).Error("Failed to load certificate and key")
			return err
		}
		tlsConfig, err := calicotls.NewTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to create TLS Config: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		// Typha API is a private binary API so we can enforce a recent TLS variant without
		// worrying about back-compatibility with old browsers (for example).
		tlsConfig.MinVersion = tls.VersionTLS12

		// Set InsecureSkipVerify true, because when it's false crypto/tls insists on
		// verifying the server's hostname or IP address against tlsConfig.ServerName, and
		// we don't always want that.  We will do certificate chain verification ourselves
		// inside CertificateVerifier.
		tlsConfig.InsecureSkipVerify = true
		caPEMBlock, err := os.ReadFile(s.options.CAFile)
		if err != nil {
			log.WithError(err).Error("Failed to read CA data")
			return err
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		ok := tlsConfig.RootCAs.AppendCertsFromPEM(caPEMBlock)
		if !ok {
			log.Error("Failed to add CA data to pool")
			return errors.New("failed to add CA data to pool")
		}
		tlsConfig.VerifyPeerCertificate = tlsutils.CertificateVerifier(
			logCxt,
			tlsConfig.RootCAs,
			s.options.ServerCN,
			s.options.ServerURISAN,
		)

		connFunc = func(addr string) (net.Conn, error) {
			return tls.DialWithDialer(
				&net.Dialer{Timeout: 10 * time.Second},
				"tcp",
				addr,
				tlsConfig)
		}
	} else {
		connFunc = func(addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", addr, 10*time.Second)
		}
	}
	if cxt.Err() == nil {
		logCxt.Info("Connecting to Typha.")
		s.connection, err = connFunc(typhaAddr.Addr)
		if err != nil {
			return err
		}
		s.connR = s.connection
		if s.options.DebugLogReads {
			s.connR = readlogger.New(s.connection)
		}
	}
	if cxt.Err() != nil {
		if s.connection != nil {
			err := s.connection.Close()
			if err != nil {
				log.WithError(err).Warn("Ignoring error from Close during shut-down of client.")
			}
		}
		return cxt.Err()
	}

	if s.options.ReadBufferSize != 0 {
		tcpConn := extractTCPConn(s.connection)
		if tcpConn == nil {
			log.Warn("Cannot set read buffer size, not a TCP connection?")
		} else {
			err := tcpConn.SetReadBuffer(s.options.ReadBufferSize)
			if err != nil {
				log.WithError(err).Warn("Failed to set read buffer size, ignoring")
			} else {
				log.WithField("size", s.options.ReadBufferSize).Warn("Set read buffer size")
			}
		}
	}

	logCxt.Info("Connected to Typha.")
	s.connInfo = &typhaAddr

	// Log TLS connection details.
	tlsConn, ok := s.connection.(*tls.Conn)
	log.WithField("ok", ok).Debug("TLS conn?")
	if ok {
		state := tlsConn.ConnectionState()
		for _, v := range state.PeerCertificates {
			bytes, _ := x509.MarshalPKIXPublicKey(v.PublicKey)
			logCxt.Debugf("%#v", bytes)
			logCxt.Debugf("%#v", v.Subject)
			logCxt.Debugf("%#v", v.URIs)
		}
		logCxt.WithFields(log.Fields{
			"handshake": state.HandshakeComplete,
		}).Debug("TLS negotiation")
	}

	return nil
}

func extractTCPConn(c net.Conn) *net.TCPConn {
	if wrapper, ok := c.(interface{ NetConn() net.Conn }); ok {
		// TLS conn provides an interface to get the underlying net.Conn
		c = wrapper.NetConn()
	}
	switch c := c.(type) {
	case *net.TCPConn:
		return c
	default:
		return nil
	}
}

func (s *SyncerClient) logConnectionFailure(cxt context.Context, logCxt *log.Entry, err error, operation string) {
	if cxt.Err() != nil {
		logCxt.WithError(err).Warn("Connection failed while being shut down by context.")
		return
	}
	logCxt.WithError(err).Errorf("Failed to %s", operation)
}

func (s *SyncerClient) loop(cxt context.Context, cancelFn context.CancelFunc, connFinished *sync.WaitGroup) {
	defer connFinished.Done()
	defer cancelFn()

	logCxt := s.logCxt.WithField("connection", s.connInfo)
	logCxt.Info("Started Typha client main loop")
	s.callbacks.OnStatusUpdated(api.ResyncInProgress)

	// Always start with basic gob encoding for the handshake.  We may upgrade to a compressed version below.
	s.writeLock.Lock()
	s.encoder = gob.NewEncoder(s.connection)
	s.writesClosed = false
	s.writeLock.Unlock()
	s.decoder = gob.NewDecoder(s.connR)

	ourSyncerType := s.options.SyncerType
	if ourSyncerType == "" {
		ourSyncerType = syncproto.SyncerTypeFelix
	}
	compAlgs := []syncproto.CompressionAlgorithm{syncproto.CompressionSnappy}
	if s.options.DisableDecoderRestart {
		// Compression requires decoder restart.
		compAlgs = nil
	}
	err := s.sendMessageToServer(cxt, logCxt, "send hello to server",
		syncproto.MsgClientHello{
			Hostname:                       s.myHostname,
			Version:                        s.myVersion,
			Info:                           s.myInfo,
			SyncerType:                     ourSyncerType,
			SupportsDecoderRestart:         !s.options.DisableDecoderRestart,
			SupportsModernPolicyKeys:       true,
			SupportedCompressionAlgorithms: compAlgs,
			ClientConnID:                   s.connID,
		},
	)
	if err != nil {
		return // (Failure already logged.)
	}

	// Read the handshake response.  It must be the first message.
	msg, err := s.readMessageFromServer(cxt, logCxt)
	if err != nil {
		return
	}
	serverHello, ok := msg.(syncproto.MsgServerHello)
	if !ok {
		logCxt.WithField("msg", msg).Error("Unexpected first message from server.")
		return
	}
	if serverHello.ServerConnID != 0 {
		logCxt = logCxt.WithField("serverConnID", serverHello.ServerConnID)
	}
	logCxt.WithField("serverMsg", serverHello).Info("ServerHello message received")

	// Abort if it looks like we're talking to an ancient Typha.  We used to
	// allow the connection and inform the client, but that's not easy to
	// do now that we reconnect to Typha on failure.
	if !serverHello.SupportsNodeResourceUpdates {
		logCxt.Warn("Server responded without support for node resource updates, disconnecting.")
		return
	}

	// Check the SyncerType reported by the server.  If the server is too old to support SyncerType then
	// the message will have an empty string in place of the SyncerType.  In that case we only proceed if
	// the client wants the felix syncer.
	serverSyncerType := serverHello.SyncerType
	if serverSyncerType == "" {
		logCxt.Info("Server responded without SyncerType, assuming an old Typha version that only " +
			"supports SyncerTypeFelix.")
		serverSyncerType = syncproto.SyncerTypeFelix
	}
	if ourSyncerType != serverSyncerType {
		logCxt.Errorf("We require SyncerType %s but Typha server doesn't support it.", ourSyncerType)
		return
	}

	// Handshake done.  If rebalancing is enabled, start the background timer
	// that periodically checks whether we're connected to our preferred Typha
	// and, if not, disconnects so we reconnect onto it.  We tie the goroutine
	// into connFinished so that the client's restart loop waits for it to exit
	// before starting the next connection (it must not act on a later
	// connection's socket).
	if s.rebalanceEnabled() {
		connFinished.Add(1)
		go s.rebalanceLoop(cxt, logCxt, cancelFn, connFinished)
	}

	// Start processing messages from the server.
	for cxt.Err() == nil {
		msg, err := s.readMessageFromServer(cxt, logCxt)
		if err != nil {
			return
		}
		debug := log.IsLevelEnabled(log.DebugLevel)
		switch msg := msg.(type) {
		case syncproto.MsgSyncStatus:
			logCxt.WithField("newStatus", msg.SyncStatus).Info("Status update from Typha.")
			s.callbacks.OnStatusUpdated(msg.SyncStatus)
		case syncproto.MsgPing:
			logCxt.Debug("Ping received from Typha")
			err := s.sendMessageToServer(cxt, logCxt, "write pong to server",
				syncproto.MsgPong{
					PingTimestamp: msg.Timestamp,
				},
			)
			if err != nil {
				return // (Failure already logged.)
			}
			logCxt.Debug("Pong sent to Typha")
		case syncproto.MsgKVs:
			updates := make([]api.Update, 0, len(msg.KVs))
			if s.options.DebugDiscardKVUpdates {
				// For simulating lots of clients in tests, just throw away the data.
				continue
			}
			for _, kv := range msg.KVs {
				update, err := kv.ToUpdate()
				if err != nil {
					logCxt.WithError(err).Error("Failed to deserialize update, skipping.")
					continue
				}
				if debug {
					logCxt.WithFields(log.Fields{
						"serialized":   kv,
						"deserialized": update,
					}).Debug("Decoded update from Typha")
				}
				updates = append(updates, update)
			}
			s.callbacks.OnUpdates(updates)
		case syncproto.MsgDecoderRestart:
			if s.options.DisableDecoderRestart {
				log.Error("Server sent MsgDecoderRestart but we signalled no support.")
				return
			}
			err = s.restartDecoder(cxt, logCxt, msg)
			if err != nil {
				log.WithError(err).Error("Failed to restart decoder")
				return
			}
		case syncproto.MsgServerHello:
			logCxt.WithField("serverVersion", msg.Version).Error("Unexpected extra server hello message received")
			return
		}
	}
}

// rebalanceEnabled reports whether the periodic rebalance check should run for
// this client.  Rebalancing disconnects the client so it reconnects onto its
// preferred Typha; that only makes sense if the client can restart its
// connection (RestartAwareCallbacks).  A non-positive configured interval
// disables it explicitly.
func (s *SyncerClient) rebalanceEnabled() bool {
	if s.options.rebalanceInterval() <= 0 {
		return false
	}
	if _, ok := s.callbacks.(RestartAwareCallbacks); !ok {
		s.logCxt.Debug("Client is not restart-aware; rebalancing to preferred Typha is disabled.")
		return false
	}
	return true
}

// rebalanceLoop runs for the lifetime of one connection.  On a jittered timer
// it re-runs discovery and, if we're not connected to our preferred Typha,
// sends a goodbye and cancels the connection so the client's restart loop
// reconnects us onto the preferred instance.
func (s *SyncerClient) rebalanceLoop(cxt context.Context, logCxt *log.Entry, cancelFn context.CancelFunc, connFinished *sync.WaitGroup) {
	defer connFinished.Done()

	interval := s.options.rebalanceInterval()
	// Jitter the interval so that, when the topology changes, clients migrate
	// gradually rather than all reconnecting at once.
	maxJitter := max(interval/4, time.Millisecond)
	ticker := jitter.NewTicker(interval, maxJitter)
	defer ticker.Stop()
	logCxt.WithField("interval", interval).Info("Started Typha rebalance check.")

	for {
		select {
		case <-cxt.Done():
			return
		case <-ticker.C:
			if s.maybeRebalance(cxt, logCxt) {
				// We've said goodbye; cancel the connection so the restart loop
				// reconnects us (to our preferred Typha) and stop checking.
				cancelFn()
				return
			}
		}
	}
}

// maybeRebalance checks whether we're connected to our preferred Typha and, if
// not, sends a goodbye and latches writes closed.  It returns true if it
// initiated a disconnect (the caller should then tear down the connection).
func (s *SyncerClient) maybeRebalance(cxt context.Context, logCxt *log.Entry) bool {
	preferred, ok, err := s.discoverer.PreferredTypha()
	if err != nil {
		logCxt.WithError(err).Info("Rebalance check: failed to re-discover Typha endpoints; staying on current connection.")
		return false
	}
	if !ok {
		logCxt.Info("Rebalance check: discovery returned no Typha endpoints; staying on current connection.")
		return false
	}
	if s.connInfo != nil && s.connInfo.Equal(preferred) {
		logCxt.WithField("preferred", preferred).Debug("Rebalance check: already connected to preferred Typha.")
		return false
	}
	logCxt.WithFields(log.Fields{
		"current":   s.connInfo,
		"preferred": preferred,
	}).Info("Connected to a non-preferred Typha; disconnecting to rebalance onto our preferred Typha instance.")
	s.sendGoodbyeAndCloseWrites(cxt, logCxt, rebalanceGoodbyeReason)
	// Forget which Typhas we've already tried so that the reconnect starts
	// from the head of our preference order.  Otherwise, if the preferred
	// Typha was tried (and unreachable) when this connection was made, the
	// tracker would skip it and we'd hop to yet another non-preferred
	// instance.  Safe without a lock: the restart loop only calls into the
	// tracker after this goroutine exits (it waits on connFinished).
	s.connAttemptTracker.Reset()
	return true
}

func (s *SyncerClient) restartDecoder(cxt context.Context, logCxt *log.Entry, msg syncproto.MsgDecoderRestart) error {
	logCxt.WithField("msg", msg).Info("Server asked us to restart our decoder")
	// Check if we should enable compression.
	switch msg.CompressionAlgorithm {
	case syncproto.CompressionSnappy:
		logCxt.Info("Server selected snappy compression.")
		r := snappy.NewReader(s.connR)
		s.decoder = gob.NewDecoder(r)
	case "":
		logCxt.Info("Server selected no compression.")
		s.decoder = gob.NewDecoder(s.connR)
	}
	// Server requires an ack of the MsgDecoderRestart before it can send data in the new format.
	err := s.sendMessageToServer(cxt, logCxt, "send ACK to server",
		syncproto.MsgACK{},
	)
	return err
}

// sendMessageToServer sends a single value-type MsgXYZ object to the server.  It updates the connection's
// write deadline to ensure we don't block forever.  Logs errors via logConnectionFailure.
//
// Once we've sent a goodbye (writesClosed), this becomes a no-op so that the
// goodbye stays the final message on the wire.
func (s *SyncerClient) sendMessageToServer(cxt context.Context, logCxt *log.Entry, op string, message any) error {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()
	if s.writesClosed {
		logCxt.WithField("op", op).Debug("Connection writes already closed (goodbye sent); dropping message.")
		return nil
	}
	return s.writeMessageLocked(cxt, logCxt, op, message)
}

// writeMessageLocked encodes a single message onto the connection.  The caller
// must hold writeLock.
func (s *SyncerClient) writeMessageLocked(cxt context.Context, logCxt *log.Entry, op string, message any) error {
	err := s.connection.SetWriteDeadline(time.Now().Add(s.options.writeTimeout()))
	if err != nil {
		s.logConnectionFailure(cxt, logCxt, err, "set timeout before "+op)
		return err
	}
	err = s.encoder.Encode(syncproto.Envelope{
		Message: message,
	})
	if err != nil {
		s.logConnectionFailure(cxt, logCxt, err, op)
		return err
	}
	return nil
}

// sendGoodbyeAndCloseWrites sends a final MsgClientGoodbye and latches the
// connection write-closed, all under writeLock, so that no other message (such
// as a pong from the read loop) can be interleaved after it.  Together with
// closing the socket immediately afterwards, this guarantees the goodbye is the
// last message the server sees from us before the connection drops.  Delivery
// is best-effort: any error is logged but otherwise ignored, since we're
// disconnecting regardless.
func (s *SyncerClient) sendGoodbyeAndCloseWrites(cxt context.Context, logCxt *log.Entry, reason string) {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()
	if s.writesClosed {
		return
	}
	if err := s.writeMessageLocked(cxt, logCxt, "send goodbye to server",
		syncproto.MsgClientGoodbye{Reason: reason}); err != nil {
		logCxt.WithError(err).Info("Failed to send goodbye to Typha before disconnecting; continuing to disconnect anyway.")
	}
	// Latch writes closed even if the send failed: we're about to close the
	// connection and don't want any trailing messages.
	s.writesClosed = true
}

// readMessageFromServer reads a single value-type MsgXYZ object from the server.  It updates the connection's
// read deadline to ensure we don't block forever.  Logs errors via logConnectionFailure.
func (s *SyncerClient) readMessageFromServer(cxt context.Context, logCxt *log.Entry) (any, error) {
	var envelope syncproto.Envelope
	// Update the read deadline before we try to read, otherwise we could block for a very long time if the
	// TCP connection was severed without being cleanly shut down.  Typha sends regular pings so we should receive
	// something even if there are no datamodel updates.
	err := s.connection.SetReadDeadline(time.Now().Add(s.options.readTimeout()))
	if err != nil {
		s.logConnectionFailure(cxt, logCxt, err, "set read timeout")
		return nil, err
	}
	err = s.decoder.Decode(&envelope)
	if err != nil {
		s.logConnectionFailure(cxt, logCxt, err, "read from server")
		return nil, err
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		logCxt.WithField("envelope", envelope).Debug("New message from Typha.")
	}
	return envelope.Message, nil
}
