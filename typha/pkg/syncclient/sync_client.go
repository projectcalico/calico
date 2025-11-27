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
	cbskn, ok := cbs.(CallbacksWithKeysKnown)
	if !ok {
		cbskn = simpleCallbacksAdapter{cbs}
	}
	sc := &SyncerClient{
		logCxt: log.WithFields(log.Fields{
			"type": options.SyncerType,
		}),
		callbacks:          cbskn,
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
	encoder    *gob.Encoder
	decoder    *gob.Decoder

	callbacks CallbacksWithKeysKnown
	Finished  sync.WaitGroup
}

type CallbacksWithKeysKnown interface {
	api.SyncerCallbacks
	OnUpdatesKeysKnown(updates []api.Update, keys []string)
}

type RestartAwareCallbacks interface {
	CallbacksWithKeysKnown
	OnTyphaConnectionRestarted()
}

type simpleCallbacksAdapter struct {
	api.SyncerCallbacks
}

func (c simpleCallbacksAdapter) OnUpdatesKeysKnown(updates []api.Update, keys []string) {
	c.OnUpdates(updates)
}

var _ CallbacksWithKeysKnown = simpleCallbacksAdapter{}

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

	connFinished.Add(1)
	go func() {
		// Broadcast that we're finished.
		defer connFinished.Done()

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
	}()
	return nil
}

func (s *SyncerClient) calculateConnectionAttemptLimit(numDiscoveredTyphas int) int {
	expectedNumTyphas := numDiscoveredTyphas
	if expectedNumTyphas < 3 {
		// Most clusters have at least 3 Typha instances so, if we discovered fewer instances,
		// assume that there may be more starting up.
		expectedNumTyphas = 3
	}
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
	s.encoder = gob.NewEncoder(s.connection)
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

	// Handshake done, start processing messages from the server.
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
			keys := make([]string, 0, len(msg.KVs))
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
				keys = append(keys, kv.Key)
			}
			s.callbacks.OnUpdatesKeysKnown(updates, keys)
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
func (s *SyncerClient) sendMessageToServer(cxt context.Context, logCxt *log.Entry, op string, message interface{}) error {
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

// readMessageFromServer reads a single value-type MsgXYZ object from the server.  It updates the connection's
// read deadline to ensure we don't block forever.  Logs errors via logConnectionFailure.
func (s *SyncerClient) readMessageFromServer(cxt context.Context, logCxt *log.Entry) (interface{}, error) {
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
