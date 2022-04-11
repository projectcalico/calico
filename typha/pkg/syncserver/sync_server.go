// Copyright (c) 2017-2019,2021 Tigera, Inc. All rights reserved.
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

package syncserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"

	"github.com/projectcalico/calico/typha/pkg/buildinfo"
	"github.com/projectcalico/calico/typha/pkg/jitter"
	"github.com/projectcalico/calico/typha/pkg/snapcache"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
	"github.com/projectcalico/calico/typha/pkg/tlsutils"
)

var (
	ErrReadFailed               = errors.New("Failed to read from client")
	ErrUnexpectedClientMsg      = errors.New("Unexpected message from client")
	ErrUnsupportedClientFeature = errors.New("Unsupported client feature")
)

var (
	counterNumConnectionsAccepted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "typha_connections_accepted",
		Help: "Total number of connections accepted over time.",
	})
	counterNumConnectionsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "typha_connections_dropped",
		Help: "Total number of connections dropped due to rebalancing.",
	})
	counterGracePeriodUsed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "typha_connections_grace_used",
		Help: "Total number of connections that made use of the grace period to catch up after sending the initial " +
			"snapshot.",
	})
	gaugeNumConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "typha_connections_active",
		Help: "Number of open client connections.",
	})
	summarySnapshotSendTime = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_client_snapshot_send_secs",
		Help: "How long it took to send the initial snapshot to each client.",
	})
	summaryClientLatency = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_client_latency_secs",
		Help: "Per-client latency.  I.e. how far behind the current state is each client.",
		// Reduce the time window so the stat is more useful after a spike.
		MaxAge:     1 * time.Minute,
		AgeBuckets: 2,
	})
	summaryWriteLatency = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_client_write_latency_secs",
		Help: "Per-client write.  How long each write call is taking.",
	})
	summaryNextCatchupLatency = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_next_breadcrumb_latency_secs",
		Help: "Time to retrieve next breadcrumb when already behind.",
	})
	summaryPingLatency = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_ping_latency",
		Help: "Round-trip ping latency to client.",
	})
	summaryNumKVsPerMsg = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_kvs_per_msg",
		Help: "Number of KV pairs sent in each message.",
	})
)

func init() {
	prometheus.MustRegister(counterNumConnectionsAccepted)
	prometheus.MustRegister(counterNumConnectionsDropped)
	prometheus.MustRegister(counterGracePeriodUsed)
	prometheus.MustRegister(gaugeNumConnections)
	prometheus.MustRegister(summarySnapshotSendTime)
	prometheus.MustRegister(summaryClientLatency)
	prometheus.MustRegister(summaryNextCatchupLatency)
	prometheus.MustRegister(summaryWriteLatency)
	prometheus.MustRegister(summaryPingLatency)
	prometheus.MustRegister(summaryNumKVsPerMsg)
}

const (
	defaultMaxMessageSize                 = 100
	defaultMaxFallBehind                  = 300 * time.Second
	defaultNewClientFallBehindGracePeriod = 300 * time.Second
	defaultBatchingAgeThreshold           = 100 * time.Millisecond
	defaultPingInterval                   = 10 * time.Second
	defaultDropInterval                   = 1 * time.Second
	defaultMaxConns                       = math.MaxInt32
	PortRandom                            = -1
)

type Server struct {
	config     Config
	caches     map[syncproto.SyncerType]BreadcrumbProvider
	nextConnID uint64
	maxConnsC  chan int
	chosenPort int
	listeningC chan struct{}

	dropInterval     time.Duration
	connTrackingLock sync.Mutex
	maxConns         int
	connIDToConn     map[uint64]*connection

	Finished sync.WaitGroup
}

type BreadcrumbProvider interface {
	CurrentBreadcrumb() *snapcache.Breadcrumb
}

type Config struct {
	Port                           int
	MaxMessageSize                 int
	MaxFallBehind                  time.Duration
	NewClientFallBehindGracePeriod time.Duration
	MinBatchingAgeThreshold        time.Duration
	PingInterval                   time.Duration
	PongTimeout                    time.Duration
	DropInterval                   time.Duration
	MaxConns                       int
	HealthAggregator               *health.HealthAggregator
	KeyFile                        string
	CertFile                       string
	CAFile                         string
	ClientCN                       string
	ClientURISAN                   string
}

const (
	healthName     = "sync_server"
	healthInterval = 10 * time.Second
)

func (c *Config) ApplyDefaults() {
	if c.MaxMessageSize < 1 {
		log.WithFields(log.Fields{
			"value":   c.MaxMessageSize,
			"default": defaultMaxMessageSize,
		}).Info("Defaulting MaxMessageSize.")
		c.MaxMessageSize = defaultMaxMessageSize
	}
	if c.MaxFallBehind <= 0 {
		log.WithFields(log.Fields{
			"value":   c.MaxFallBehind,
			"default": defaultMaxFallBehind,
		}).Info("Defaulting MaxFallBehind.")
		c.MaxFallBehind = defaultMaxFallBehind
	}
	if c.NewClientFallBehindGracePeriod <= 0 {
		log.WithFields(log.Fields{
			"value":   c.NewClientFallBehindGracePeriod,
			"default": defaultNewClientFallBehindGracePeriod,
		}).Info("Defaulting MaxFallBehind.")
		c.NewClientFallBehindGracePeriod = defaultNewClientFallBehindGracePeriod
	}
	if c.MinBatchingAgeThreshold <= 0 {
		log.WithFields(log.Fields{
			"value":   c.MinBatchingAgeThreshold,
			"default": defaultBatchingAgeThreshold,
		}).Info("Defaulting MinBatchingAgeThreshold.")
		c.MinBatchingAgeThreshold = defaultBatchingAgeThreshold
	}
	if c.PingInterval <= 0 {
		log.WithFields(log.Fields{
			"value":   c.PingInterval,
			"default": defaultPingInterval,
		}).Info("Defaulting PingInterval.")
		c.PingInterval = defaultPingInterval
	}
	if c.PongTimeout <= c.PingInterval*2 {
		defaultTimeout := c.PingInterval * 6
		log.WithFields(log.Fields{
			"value":   c.PongTimeout,
			"default": defaultTimeout,
		}).Info("PongTimeout < PingInterval * 2; Defaulting PongTimeout.")
		c.PongTimeout = defaultTimeout
	}
	if c.DropInterval <= 0 {
		log.WithFields(log.Fields{
			"value":   c.DropInterval,
			"default": defaultDropInterval,
		}).Info("Defaulting DropInterval.")
		c.DropInterval = defaultDropInterval
	}
	if c.MaxConns <= 0 {
		log.WithFields(log.Fields{
			"value":   c.MaxConns,
			"default": defaultMaxConns,
		}).Info("Defaulting MaxConns.")
		c.MaxConns = defaultMaxConns
	}
	if c.Port == 0 {
		// We use 0 to mean "use the default port".
		log.WithFields(log.Fields{
			"value":   c.Port,
			"default": syncproto.DefaultPort,
		}).Info("Defaulting Port.")
		c.Port = syncproto.DefaultPort
	}
}

func (c *Config) ListenPort() int {
	if c.Port == PortRandom {
		return 0
	}
	return c.Port
}

func (c *Config) requiringTLS() bool {
	// True if any of the TLS parameters are set.  This must match config.Config.requiringTLS().
	return c.KeyFile+c.CertFile+c.CAFile+c.ClientCN+c.ClientURISAN != ""
}

func New(caches map[syncproto.SyncerType]BreadcrumbProvider, config Config) *Server {
	config.ApplyDefaults()
	log.WithField("config", config).Info("Creating server")
	s := &Server{
		config:       config,
		caches:       caches,
		maxConnsC:    make(chan int),
		dropInterval: config.DropInterval,
		maxConns:     config.MaxConns,
		connIDToConn: map[uint64]*connection{},
		listeningC:   make(chan struct{}),
	}

	// Register that we will report liveness.
	if config.HealthAggregator != nil {
		config.HealthAggregator.RegisterReporter(
			healthName,
			&health.HealthReport{Live: true},
			healthInterval*2,
		)
	}

	return s
}

func (s *Server) Start(cxt context.Context) {
	s.Finished.Add(2)
	go s.serve(cxt)
	go s.governNumberOfConnections(cxt)
}

func (s *Server) SetMaxConns(numConns int) {
	s.maxConnsC <- numConns
}

func (s *Server) Port() int {
	<-s.listeningC
	return s.chosenPort
}

func (s *Server) serve(cxt context.Context) {
	defer s.Finished.Done()
	var cancelFn context.CancelFunc
	cxt, cancelFn = context.WithCancel(cxt)
	defer cancelFn()

	logCxt := log.WithField("port", s.config.Port)
	var (
		l   net.Listener
		err error
	)
	if s.config.requiringTLS() {
		pwd, _ := os.Getwd()
		logCxt.WithField("pwd", pwd).Info("Opening TLS listen socket")
		cert, tlsErr := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
		if tlsErr != nil {
			logCxt.WithFields(log.Fields{
				"certFile": s.config.CertFile,
				"keyFile":  s.config.KeyFile,
			}).WithError(tlsErr).Panic("Failed to load certificate and key")
		}
		tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
		// Typha API is a private binary API so we can enforce a recent TLS variant without
		// worrying about back-compatibility with old browsers (for example).
		tlsConfig.MinVersion = tls.VersionTLS12

		// Set allowed cipher suites.
		tlsConfig.CipherSuites = s.allowedCiphers()

		// Arrange for server to verify the clients' certificates.
		logCxt.Info("Will verify client certificates")
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		caPEMBlock, tlsErr := ioutil.ReadFile(s.config.CAFile)
		if tlsErr != nil {
			logCxt.WithError(tlsErr).Panic("Failed to read CA data")
		}
		tlsConfig.ClientCAs = x509.NewCertPool()
		ok := tlsConfig.ClientCAs.AppendCertsFromPEM(caPEMBlock)
		if !ok {
			logCxt.Panic("Failed to add CA data to pool")
		}
		tlsConfig.VerifyPeerCertificate = tlsutils.CertificateVerifier(
			logCxt,
			tlsConfig.ClientCAs,
			s.config.ClientCN,
			s.config.ClientURISAN,
		)

		laddr := fmt.Sprintf("0.0.0.0:%v", s.config.ListenPort())
		l, err = tls.Listen("tcp", laddr, &tlsConfig)
	} else {
		logCxt.Info("Opening listen socket")
		l, err = net.ListenTCP("tcp", &net.TCPAddr{Port: s.config.ListenPort()})
	}
	if err != nil {
		logCxt.WithError(err).Panic("Failed to open listen socket")
	}
	logCxt.Info("Opened listen socket")

	s.Finished.Add(1)
	go func() {
		<-cxt.Done()
		err := l.Close()
		if err != nil {
			log.WithError(err).Warn("Ignoring error from socket Close during shut-down.")
		}
		s.Finished.Done()
	}()
	s.chosenPort = l.Addr().(*net.TCPAddr).Port
	logCxt = log.WithField("port", s.chosenPort)
	close(s.listeningC)
	for {
		logCxt.Debug("About to accept connection")
		conn, err := l.Accept()
		if err != nil {
			if cxt.Err() != nil {
				logCxt.WithError(cxt.Err()).Info("Shutting down...")
				return
			}
			logCxt.WithError(err).Panic("Failed to accept connection")
			return
		}

		logCxt.Infof("Accepted from %s", conn.RemoteAddr())
		if s.config.requiringTLS() {
			// Doing TLS, we must do the handshake...
			tlsConn := conn.(*tls.Conn)
			logCxt.Debug("TLS connection")
			err = tlsConn.Handshake()
			if err != nil {
				logCxt.WithError(err).Error("TLS handshake error")
				err = conn.Close()
				if err != nil {
					logCxt.WithError(err).Warning("Error closing failed TLS connection")
				}
				continue
			}
			state := tlsConn.ConnectionState()
			for _, v := range state.PeerCertificates {
				bytes, _ := x509.MarshalPKIXPublicKey(v.PublicKey)
				logCxt.Debugf("%#v", bytes)
				logCxt.Debugf("%#v", v.Subject)
				logCxt.Debugf("%#v", v.URIs)
			}
		}

		connID := s.nextConnID
		s.nextConnID++
		logCxt.WithField("connID", connID).Info("New connection")
		counterNumConnectionsAccepted.Inc()

		// Create a new connection-scoped context, which we'll use for signaling to our child
		// goroutines to halt.
		connCxt, cancel := context.WithCancel(cxt)
		connection := &connection{
			ID:        connID,
			config:    &s.config,
			allCaches: s.caches,
			cxt:       connCxt,
			cancelCxt: cancel,
			conn:      conn,
			logCxt: log.WithFields(log.Fields{
				"client": conn.RemoteAddr(),
				"connID": connID,
			}),

			encoder: gob.NewEncoder(conn),
			readC:   make(chan interface{}),
		}
		// Track the connection's lifetime in connIDToConn so we can kill it later if needed.
		s.recordConnection(connection)
		// Defer to the connection-handler.
		s.Finished.Add(2)
		go func() {
			err := connection.handle(&s.Finished)
			if err != nil {
				log.WithError(err).Info("Connection handler finished")
			}
		}()
		// Clean up the entry in connIDToConn as soon as the context is canceled.
		go func() {
			<-connCxt.Done()
			s.discardConnection(connection)
			s.Finished.Done()
		}()
	}
}

func (s *Server) recordConnection(conn *connection) {
	s.connTrackingLock.Lock()
	s.connIDToConn[conn.ID] = conn
	s.connTrackingLock.Unlock()
}

func (s *Server) discardConnection(conn *connection) {
	s.connTrackingLock.Lock()
	delete(s.connIDToConn, conn.ID)
	s.connTrackingLock.Unlock()
}

func (s *Server) governNumberOfConnections(cxt context.Context) {
	defer s.Finished.Done()
	logCxt := log.WithField("thread", "numConnsGov")
	maxConns := s.maxConns
	ticker := jitter.NewTicker(s.dropInterval, s.dropInterval/10)
	healthTicks := time.NewTicker(healthInterval).C
	s.reportHealth()
	for {
		select {
		case newMax := <-s.maxConnsC:
			if newMax == maxConns {
				continue
			}
			s.connTrackingLock.Lock()
			currentNum := len(s.connIDToConn)
			s.connTrackingLock.Unlock()
			logCxt.WithFields(log.Fields{
				"oldMax":     maxConns,
				"newMax":     newMax,
				"currentNum": currentNum,
			}).Info("New target number of connections")
			maxConns = newMax
			s.connTrackingLock.Lock()
			s.maxConns = maxConns
			s.connTrackingLock.Unlock()
		case <-ticker.C:
			s.connTrackingLock.Lock()
			numConns := len(s.connIDToConn)
			if numConns > maxConns {
				for connID, conn := range s.connIDToConn {
					logCxt.WithFields(log.Fields{
						"max":     maxConns,
						"current": numConns,
						"connID":  connID,
					}).Warn("Currently have too many connections, terminating one at random.")
					conn.cancelCxt()
					counterNumConnectionsDropped.Inc()
					break
				}
			}
			s.connTrackingLock.Unlock()
		case <-cxt.Done():
			logCxt.Info("Context asked us to stop")
			return
		case <-healthTicks:
			s.reportHealth()
		}
	}
}

// allowedCiphers returns the set of allowed cipher suites for the server.
// The list is taken from https://github.com/golang/go/blob/dev.boringcrypto.go1.13/src/crypto/tls/boring.go#L54
func (s *Server) allowedCiphers() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}
}

func (s *Server) reportHealth() {
	if s.config.HealthAggregator != nil {
		s.config.HealthAggregator.Report(healthName, &health.HealthReport{Live: true})
	}
}

type connection struct {
	ID     uint64
	config *Config

	// cxt is the per-connection context.
	cxt context.Context
	// cancelCxt is the cancel function for the above context.  We call this from any goroutine that's stopping
	// to make sure that everything else gets shut down.
	cancelCxt context.CancelFunc
	// shutDownWG is used to wait for our background threads to finish.
	shutDownWG sync.WaitGroup

	// allCaches contains a mapping from syncer type (felix/BGP) to the right cache to use.  We don't know
	// which cache to use until we do the handshake.  Once the handshake is complete, we store the correct
	// cache in the "cache" field.
	allCaches map[syncproto.SyncerType]BreadcrumbProvider
	cache     BreadcrumbProvider
	conn      net.Conn

	encoder *gob.Encoder
	readC   chan interface{}

	logCxt *log.Entry
}

func (h *connection) handle(finishedWG *sync.WaitGroup) (err error) {
	// Ensure that stop gets called.  Stop will close the connection and context and wait for our background
	// goroutines to finish.
	defer func() {
		// Cancel the context and close the connection, this will trigger our background threads to shut down.
		// We need to do both because they may be blocked on IO or something else.
		h.logCxt.Info("Client connection shutting down.")
		h.cancelCxt()
		err := h.conn.Close()
		if err != nil {
			log.WithError(err).Error("Error when closing connection.  Ignoring!")
		}
		// Wait for the background threads to shut down.
		h.shutDownWG.Wait()
		gaugeNumConnections.Dec()
		h.logCxt.Info("Client connection shut down.")
		finishedWG.Done()
	}()

	h.logCxt.Info("Per-connection goroutine started")
	gaugeNumConnections.Inc()

	// Start goroutine to read messages from client and put them on a channel for this goroutine to process.
	h.shutDownWG.Add(1)
	go h.readFromClient(h.logCxt.WithField("thread", "read"))

	// Now do the (synchronous) handshake before we start our update-writing thread.
	if err = h.doHandshake(); err != nil {
		return // Error already logged.
	}

	// Start a goroutine to stream the snapshot and then the deltas to the client.
	h.shutDownWG.Add(1)
	go h.sendSnapshotAndUpdatesToClient(h.logCxt.WithField("thread", "kv-sender"))

	// Start a goroutine to send periodic pings.  We send pings from their own goroutine so that, if the Encoder
	// blocks, we don't prevent the main goroutine from checking the pongs.
	h.shutDownWG.Add(1)
	go h.sendPingsToClient(h.logCxt.WithField("thread", "pinger"))

	// Start a ticker to check that we receive pongs in a timely fashion.
	pongTicker := jitter.NewTicker(h.config.PingInterval/2, h.config.PingInterval/10)
	defer func() {
		h.logCxt.Info("Stopping pong check ticker.")
		pongTicker.Stop()
	}()
	lastPongReceived := time.Now()

	// Use this goroutine to wait for client messages and do the ping/pong liveness check.
	h.logCxt.Info("Waiting for messages from client")
	for {

		select {
		case msg := <-h.readC:
			if msg == nil {
				h.logCxt.Info("Read channel ended")
				return h.cxt.Err()
			}
			switch msg := msg.(type) {
			case syncproto.MsgPong:
				h.logCxt.Debug("Pong from client")
				lastPongReceived = time.Now()
				summaryPingLatency.Observe(time.Since(msg.PingTimestamp).Seconds())
			default:
				h.logCxt.WithField("msg", msg).Error("Unknown message from client")
				return errors.New("Unknown message type")
			}
		case <-pongTicker.C:
			since := time.Since(lastPongReceived)
			if since > h.config.PongTimeout {
				h.logCxt.WithFields(log.Fields{
					"pongTimeout":       h.config.PongTimeout,
					"timeSinceLastPong": since,
				}).Info("Too long since last pong from client, disconnecting")
				return errors.New("No pong received from client")
			}
		case <-h.cxt.Done():
			h.logCxt.Info("Asked to stop by Context.")
			return h.cxt.Err()
		}
	}
}

// readFromClient reads messages from the client and puts them on the h.readC channel.  It is responsible for closing the
// channel.
func (h *connection) readFromClient(logCxt *log.Entry) {
	defer func() {
		h.cancelCxt()
		close(h.readC)
		h.shutDownWG.Done()
		logCxt.Info("Read goroutine finished")
	}()
	r := gob.NewDecoder(h.conn)
	for {
		var envelope syncproto.Envelope
		err := r.Decode(&envelope)
		if err != nil {
			logCxt.WithError(err).Info("Failed to read from client")
			break
		}
		if envelope.Message == nil {
			log.Error("nil message from client")
			break
		}
		select {
		case h.readC <- envelope.Message:
		case <-h.cxt.Done():
			return
		}

	}
}

// waitForMessage blocks, waiting for a message on the h.readC channel.  It imposes a timeout.
func (h *connection) waitForMessage(logCxt *log.Entry) (interface{}, error) {
	// Read the hello message from the client.
	cxt, cancel := context.WithDeadline(h.cxt, time.Now().Add(60*time.Second))
	defer cancel()
	select {
	case msg := <-h.readC:
		if msg == nil {
			logCxt.Warning("Failed to read hello from client")
			return nil, ErrReadFailed
		}
		logCxt.WithField("msg", msg).Debug("Received message from client.")
		return msg, nil
	case <-cxt.Done():
		logCxt.Info("Asked to stop by context.")
		return nil, h.cxt.Err()
	}
}

func (h *connection) doHandshake() error {
	// Read the client's hello message.
	msg, err := h.waitForMessage(h.logCxt)
	if err != nil {
		h.logCxt.WithError(err).Warn("Failed to read client hello.")
		return err
	}
	hello, ok := msg.(syncproto.MsgClientHello)
	if !ok {
		h.logCxt.WithField("msg", msg).Error("Unexpected message from client.")
		return ErrUnexpectedClientMsg
	}
	h.logCxt.WithField("msg", hello).Info("Received Hello message from client.")

	syncerType := hello.SyncerType
	if syncerType == "" {
		// Old client, assume it's a down-level Felix.
		h.logCxt.Info("Client didn't provide a SyncerType, assuming SyncerTypeFelix for back-compatibility.")
		syncerType = syncproto.SyncerTypeFelix
	}
	desiredSyncerCache := h.allCaches[syncerType]
	if desiredSyncerCache == nil {
		h.logCxt.WithField("requestedType", syncerType).Info("Client requested unknown SyncerType.")
		return ErrUnsupportedClientFeature
	}
	h.cache = desiredSyncerCache

	// Respond to client's hello.
	err = h.sendMsg(syncproto.MsgServerHello{
		Version: buildinfo.GitVersion,
		// Echo back the SyncerType so that up-level clients know that we understood their request.  Down-level
		// clients will ignore.
		SyncerType:                  syncerType,
		SupportsNodeResourceUpdates: true,
	})
	if err != nil {
		log.WithError(err).Warning("Failed to send hello to client")
		return err
	}
	return nil
}

// sendMsg sends a message to the client.  It may be called from multiple goroutines because the Encoder is thread-safe.
func (h *connection) sendMsg(msg interface{}) error {
	if h.cxt.Err() != nil {
		// Optimisation, don't bother to send if we're being torn down.
		return h.cxt.Err()
	}
	envelope := syncproto.Envelope{
		Message: msg,
	}
	startTime := time.Now()
	err := h.encoder.Encode(&envelope)
	if err != nil {
		h.logCxt.WithError(err).Info("Failed to write to client")
		return err
	}
	summaryWriteLatency.Observe(time.Since(startTime).Seconds())
	return nil
}

// sendSnapshotAndUpdatesToClient sends the snapshot from the current Breadcrumb and then follows the Breadcrumbs
// sending deltas to the client.
func (h *connection) sendSnapshotAndUpdatesToClient(logCxt *log.Entry) {
	defer func() {
		logCxt.Info("KV-sender goroutine shutting down")
		h.cancelCxt()
		h.shutDownWG.Done()
		logCxt.Info("KV-sender goroutine finished")
	}()

	// Get the current snapshot and stream it to the client...
	breadcrumb := h.cache.CurrentBreadcrumb()
	err := h.streamSnapshotToClient(logCxt, breadcrumb)
	if err != nil {
		log.WithError(err).Info("Failed to send snapshot to client, tearing down connection.")
		return
	}
	// Finished sending the snapshot, calculate the grace time for the client to catch up to a recent breadcrumb.
	gracePeriodEndTime := time.Now().Add(h.config.NewClientFallBehindGracePeriod)

	// Track the sync status reported in each Breadcrumb so we can send an update if it changes.
	var lastSentStatus api.SyncStatus
	maybeSendStatus := func() (err error) {
		if lastSentStatus != breadcrumb.SyncStatus {
			logCxt.WithField("newStatus", breadcrumb.SyncStatus).Info(
				"Status update to send.")
			err = h.sendMsg(syncproto.MsgSyncStatus{
				SyncStatus: breadcrumb.SyncStatus,
			})
			if err != nil {
				logCxt.WithError(err).Info("Failed to send status to client")
				return
			}
			lastSentStatus = breadcrumb.SyncStatus
		}
		return
	}

	// The first Breadcrumb may have changed the status.  Send an update if so.
	if err := maybeSendStatus(); err != nil {
		return
	}

	loggedClientBehind := false
	for h.cxt.Err() == nil {
		// Wait for new Breadcrumbs.  If we're behind, we'll coalesce the deltas from multiple Breadcrumbs
		// before exiting the loop.
		var deltas []syncproto.SerializedUpdate
		for len(deltas) < h.config.MaxMessageSize {
			// Get the next breadcrumb.  This may block.
			nextStartTime := time.Now()
			var err error
			breadcrumb, err = breadcrumb.Next(h.cxt)
			if err != nil {
				logCxt.WithError(err).Info("Getting next Breadcrumb canceled by context.")
				return
			}
			timeSpentInNext := time.Since(nextStartTime)

			// Take a peek at the very latest breadcrumb to see how far behind we are...
			latestCrumb := h.cache.CurrentBreadcrumb()
			crumbAge := latestCrumb.Timestamp.Sub(breadcrumb.Timestamp)
			summaryClientLatency.Observe(crumbAge.Seconds())
			logCxt.WithFields(log.Fields{
				"seqNo":     breadcrumb.SequenceNumber,
				"timestamp": breadcrumb.Timestamp,
				"state":     breadcrumb.SyncStatus,
				"age":       crumbAge,
			}).Debug("New Breadcrumb")

			// Check if we're too far behind the latest Breadcrumb.
			if crumbAge > h.config.MaxFallBehind {
				// Allow extra time for new clients to catch up after sending the snapshot.  If the snapshot was
				// very large and clients are slow for some reason then we don't want to get stuck in a loop where
				// clients connect, grab the snapshot, immediately end up behind and get disconnected.
				//
				// This has a secondary effect: under extreme overload where clients are falling behind we give
				// them a grace period to apply the updates to the dataplane before we cut them off.  That means that
				// Felix will still make progress even though it's restarting, albeit with 90+s between dataplane
				// updates.
				if time.Now().After(gracePeriodEndTime) {
					logCxt.WithFields(log.Fields{
						"snapAge":        crumbAge,
						"mySeqNo":        breadcrumb.SequenceNumber,
						"latestSeqNo":    latestCrumb.SequenceNumber,
						"mySnapshotSize": breadcrumb.KVs.Size(),
					}).Warn("Client fell behind. Disconnecting.")
					return
				} else if !loggedClientBehind {
					logCxt.WithFields(log.Fields{
						"snapAge":        crumbAge,
						"mySeqNo":        breadcrumb.SequenceNumber,
						"latestSeqNo":    latestCrumb.SequenceNumber,
						"gracePeriod":    h.config.NewClientFallBehindGracePeriod,
						"mySnapshotSize": breadcrumb.KVs.Size(),
					}).Warn("Client is a long way behind after sending snapshot; " +
						"allowing grace period for it to catch up.")
					loggedClientBehind = true
					counterGracePeriodUsed.Add(1.0)
				}
			} else if loggedClientBehind && time.Now().After(gracePeriodEndTime) {
				// Client caught up after being behind when we sent it a snapshot.
				logCxt.WithFields(log.Fields{
					"snapAge":        crumbAge,
					"mySeqNo":        breadcrumb.SequenceNumber,
					"latestSeqNo":    latestCrumb.SequenceNumber,
					"mySnapshotSize": breadcrumb.KVs.Size(),
				}).Info("Client was behind after sending snapshot but it has now caught up.")
				loggedClientBehind = false // Avoid logging the "caught up" log on every loop.
			}

			if crumbAge < h.config.MinBatchingAgeThreshold && deltas == nil {
				// We're not behind and we haven't already started to batch up updates.  Avoid
				// copying the deltas and just send them
				deltas = breadcrumb.Deltas
				break
			}

			// Either we're already batching up updates or we're behind.  Append the deltas to the
			// buffer.
			deltas = append(deltas, breadcrumb.Deltas...)
			summaryNextCatchupLatency.Observe(timeSpentInNext.Seconds())

			if crumbAge < h.config.MinBatchingAgeThreshold {
				// Caught up, stop batching.
				break
			}
		}

		if len(deltas) > 0 {
			// Send the deltas relative to the previous snapshot.
			logCxt.WithField("num", len(deltas)).Debug("Sending deltas")
			summaryNumKVsPerMsg.Observe(float64(len(deltas)))
			err := h.sendMsg(syncproto.MsgKVs{
				KVs: deltas,
			})
			if err != nil {
				logCxt.WithError(err).Info("Failed to send to client.")
				return
			}
		}

		// Newest breadcrumb may have updated the sync status, send an update if so.
		if err := maybeSendStatus(); err != nil {
			return
		}
	}
}

// streamSnapshotToClient takes the snapshot contained in the Breadcrumb and streams it to the client in chunks.
func (h *connection) streamSnapshotToClient(logCxt *log.Entry, breadcrumb *snapcache.Breadcrumb) (err error) {
	logCxt = logCxt.WithFields(log.Fields{
		"seqNo":  breadcrumb.SequenceNumber,
		"status": breadcrumb.SyncStatus,
	})
	logCxt.Info("Starting to send snapshot to client")
	startTime := time.Now()

	// Get an iterator for the snapshot. cancelC is used to ensure that the iterator's goroutine gets cleaned up.
	cancelC := make(chan struct{})
	defer close(cancelC)
	iter := breadcrumb.KVs.Iterator(cancelC)

	// sendKVs is a utility function that sends the kvs buffer to the client and clears the buffer.
	var kvs []syncproto.SerializedUpdate
	var numKeys int
	sendKVs := func() error {
		if len(kvs) == 0 {
			return nil
		}
		logCxt.WithField("numKVs", len(kvs)).Debug("Sending snapshot KVs to client.")
		numKeys += len(kvs)
		summaryNumKVsPerMsg.Observe(float64(len(kvs)))
		err := h.sendMsg(syncproto.MsgKVs{
			KVs: kvs,
		})
		if err != nil {
			logCxt.WithError(err).Info("Failed to send to client")
		}
		kvs = kvs[:0]
		return err
	}

	for {
		select {
		case entry := <-iter:
			if entry == nil {
				// End of the iterator.  Make sure we send the last batch, if there is one...
				err = sendKVs()
				logCxt.WithField("numKeys", numKeys).Info("Finished sending snapshot to client")
				summarySnapshotSendTime.Observe(time.Since(startTime).Seconds())
				return
			}
			kvs = append(kvs, entry.Value.(syncproto.SerializedUpdate))
			if len(kvs) >= h.config.MaxMessageSize {
				// Buffer is full, send the next batch.
				err = sendKVs()
				if err != nil {
					return
				}
			}
		case <-h.cxt.Done():
			err = h.cxt.Err()
			logCxt.WithError(err).Info("Asked to stop by Context")
			return
		}
	}
}

// sendPingsToClient loops, sending pings to the client at the configured interval.
func (h *connection) sendPingsToClient(logCxt *log.Entry) {
	defer func() {
		h.cancelCxt()
		h.shutDownWG.Done()
		logCxt.Info("Pinger goroutine shut down.")
	}()
	pingTicker := jitter.NewTicker(h.config.PingInterval, h.config.PingInterval/10)
	defer func() {
		logCxt.Info("Stopping ping ticker")
		pingTicker.Stop()
	}()
	for {
		select {
		case <-pingTicker.C:
			logCxt.Debug("Sending ping.")
			err := h.sendMsg(syncproto.MsgPing{
				Timestamp: time.Now(),
			})
			if err != nil {
				log.WithError(err).Info("Failed to send ping to client")
				return
			}
		case <-h.cxt.Done():
			log.WithError(h.cxt.Err()).Info("Context was canceled.")
			return
		}
	}
}
