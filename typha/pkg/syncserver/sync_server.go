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
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"
	"github.com/projectcalico/calico/libcalico-go/lib/writelogger"
	"github.com/projectcalico/calico/pkg/buildinfo"
	"github.com/projectcalico/calico/typha/pkg/jitter"
	"github.com/projectcalico/calico/typha/pkg/promutils"
	"github.com/projectcalico/calico/typha/pkg/snapcache"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
	"github.com/projectcalico/calico/typha/pkg/tlsutils"
)

var (
	ErrReadFailed               = errors.New("failed to read from client")
	ErrUnexpectedClientMsg      = errors.New("unexpected message from client")
	ErrUnsupportedClientFeature = errors.New("unsupported client feature")
)

var (
	// Global Prometheus metrics, not specific to any particular syncer type.
	counterNumConnectionsAccepted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "typha_connections_accepted",
		Help: "Total number of connections accepted over time.",
	})
	counterNumConnectionsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "typha_connections_dropped",
		Help: "Total number of connections dropped due to rebalancing.",
	})
	gaugeNumConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "typha_connections_active",
		Help: "Number of open client connections, including connections that are still in the handshake.",
	})

	// Counters with per-syncer-type values.
	gaugeVecNumConnectionsStreaming = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "typha_connections_streaming",
		Help: "Number of client connections that completed the handshake and are streaming data.",
	}, []string{"syncer"})
	counterVecGracePeriodUsed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "typha_connections_grace_used",
		Help: "Total number of connections that made use of the grace period to catch up after sending the initial " +
			"snapshot.",
	}, []string{"syncer"})
)

func init() {
	prometheus.MustRegister(counterNumConnectionsAccepted)
	prometheus.MustRegister(counterNumConnectionsDropped)
	prometheus.MustRegister(gaugeNumConnections)

	prometheus.MustRegister(gaugeVecNumConnectionsStreaming)
	promutils.PreCreateGaugePerSyncer(gaugeVecNumConnectionsStreaming)
	prometheus.MustRegister(counterVecGracePeriodUsed)
	promutils.PreCreateCounterPerSyncer(counterVecGracePeriodUsed)
}

const (
	defaultBinarySnapshotTimeout          = 1 * time.Second
	defaultMaxMessageSize                 = 100
	defaultMaxFallBehind                  = 300 * time.Second
	defaultNewClientFallBehindGracePeriod = 300 * time.Second
	defaultBatchingAgeThreshold           = 100 * time.Millisecond
	defaultPingInterval                   = 10 * time.Second
	defaultWriteTimeout                   = 120 * time.Second
	defaultHandshakeTimeout               = 10 * time.Second
	defaultDropInterval                   = 1 * time.Second
	defaultShutdownTimeout                = 300 * time.Second
	defaultMaxConns                       = math.MaxInt32
	PortRandom                            = -1
)

type Server struct {
	config        Config
	caches        map[syncproto.SyncerType]BreadcrumbProvider
	binSnapCaches map[syncproto.CompressionAlgorithm]map[syncproto.SyncerType]snapshotCache
	nextConnID    uint64
	maxConnsC     chan int
	chosenPort    int
	listeningC    chan struct{}

	lock sync.Mutex

	shuttingDown bool
	shutdownC    chan struct{}
	connIDToConn map[uint64]*connection

	perSyncerConnMetrics map[syncproto.SyncerType]perSyncerConnMetrics

	Finished sync.WaitGroup
}

type BreadcrumbProvider interface {
	CurrentBreadcrumb() *snapcache.Breadcrumb
}

type Config struct {
	Host                           string
	Port                           int
	MaxMessageSize                 int
	BinarySnapshotTimeout          time.Duration
	MaxFallBehind                  time.Duration
	NewClientFallBehindGracePeriod time.Duration
	MinBatchingAgeThreshold        time.Duration
	PingInterval                   time.Duration
	PongTimeout                    time.Duration
	HandshakeTimeout               time.Duration
	WriteTimeout                   time.Duration
	DropInterval                   time.Duration
	ShutdownTimeout                time.Duration
	ShutdownMaxDropInterval        time.Duration
	MaxConns                       int
	HealthAggregator               *health.HealthAggregator
	KeyFile                        string
	CertFile                       string
	CAFile                         string
	ClientCN                       string
	ClientURISAN                   string
	WriteBufferSize                int

	// DebugLogWrites tells the server to wrap each connection with a Writer that
	// logs every write.  Intended only for use in tests!
	DebugLogWrites bool
}

const (
	healthName     = "SyncServer"
	healthInterval = 10 * time.Second
)

func (c *Config) ApplyDefaults() {
	if c.BinarySnapshotTimeout <= 0 {
		log.WithFields(log.Fields{
			"value":   c.BinarySnapshotTimeout,
			"default": defaultBinarySnapshotTimeout,
		}).Info("Defaulting BinarySnapshotTimeout.")
		c.BinarySnapshotTimeout = defaultBinarySnapshotTimeout
	}
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
	if c.HandshakeTimeout <= 0 {
		log.WithFields(log.Fields{
			"value":   c.HandshakeTimeout,
			"default": defaultHandshakeTimeout,
		}).Info("Defaulting HandshakeTimeout.")
		c.HandshakeTimeout = defaultHandshakeTimeout
	}
	if c.WriteTimeout <= 0 {
		log.WithField("default", defaultWriteTimeout).Info("Defaulting write timeout.")
		c.WriteTimeout = defaultWriteTimeout
	}
	if c.DropInterval <= 0 {
		log.WithFields(log.Fields{
			"value":   c.DropInterval,
			"default": defaultDropInterval,
		}).Info("Defaulting DropInterval.")
		c.DropInterval = defaultDropInterval
	}
	if c.ShutdownMaxDropInterval <= 0 {
		log.WithFields(log.Fields{
			"value":   c.ShutdownMaxDropInterval,
			"default": defaultDropInterval,
		}).Info("Defaulting ShutdownMaxDropInterval.")
		c.ShutdownMaxDropInterval = defaultDropInterval
	}
	if c.ShutdownTimeout <= 0 {
		log.WithFields(log.Fields{
			"value":   c.ShutdownTimeout,
			"default": defaultShutdownTimeout,
		}).Info("Defaulting ShutdownTimeout.")
		c.ShutdownTimeout = defaultShutdownTimeout
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
		config:               config,
		caches:               caches,
		binSnapCaches:        map[syncproto.CompressionAlgorithm]map[syncproto.SyncerType]snapshotCache{},
		maxConnsC:            make(chan int),
		shutdownC:            make(chan struct{}),
		nextConnID:           rand.Uint64()<<32 | 1,
		connIDToConn:         map[uint64]*connection{},
		listeningC:           make(chan struct{}),
		perSyncerConnMetrics: map[syncproto.SyncerType]perSyncerConnMetrics{},
	}

	s.binSnapCaches[syncproto.CompressionSnappy] = map[syncproto.SyncerType]snapshotCache{}
	for st, cache := range caches {
		s.perSyncerConnMetrics[st] = makePerSyncerConnMetrics(st)
		s.binSnapCaches[syncproto.CompressionSnappy][st] = NewSnappySnapCache(string(st), cache, config.BinarySnapshotTimeout, config.WriteTimeout)
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
	s.Finished.Add(3)
	cxt, cancelFn := context.WithCancel(cxt)
	go s.serve(cxt)
	go s.governNumberOfConnections(cxt)
	go s.handleGracefulShutDown(cxt, cancelFn)
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
		var tlsConfig *tls.Config
		tlsConfig, err = calicotls.NewTLSConfig()
		if err != nil {
			logCxt.WithError(err).Panic("Failed to create TLS Config")
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		// Arrange for server to verify the clients' certificates.
		logCxt.Info("Will verify client certificates")
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		caPEMBlock, tlsErr := os.ReadFile(s.config.CAFile)
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

		laddr := fmt.Sprintf("[%v]:%v", s.config.Host, s.config.ListenPort())
		l, err = tls.Listen("tcp", laddr, tlsConfig)
	} else {
		logCxt.Info("Opening listen socket")
		laddr := fmt.Sprintf("[%v]:%v", s.config.Host, s.config.ListenPort())
		l, err = net.Listen("tcp", laddr)
	}
	if err != nil {
		logCxt.WithError(err).Panic("Failed to open listen socket")
	}
	logCxt.Info("Opened listen socket")

	s.Finished.Add(1)
	go func() {
		select {
		case <-cxt.Done():
			log.Info("Context finished, closing listen socket.")
		case <-s.shutdownC:
			log.Info("Graceful shutdown triggered, closing listen socket.")
		}
		err := l.Close()
		if err != nil {
			log.WithError(err).Warn("Ignoring error from socket Close during shut-down.")
		}
		s.Finished.Done()
	}()

	chosenPort := l.Addr().(*net.TCPAddr).Port

	s.lock.Lock()
	s.chosenPort = chosenPort
	s.lock.Unlock()

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
			if s.ShuttingDown() {
				logCxt.Info("Listen socket closed, waiting for shut down to complete.")
				<-cxt.Done()
				return
			}
			logCxt.WithError(err).Panic("Failed to accept connection")
			return
		}

		logCxt.Infof("Accepted from %s", conn.RemoteAddr())

		if s.config.WriteBufferSize != 0 {
			// Try to set the write buffer size.  Only used in tests for now.
			setWriteBufferSizeBestEffort(conn, s.config.WriteBufferSize)
		}

		connID := s.nextConnID
		s.nextConnID++
		logCxt.WithField("connID", connID).Info("New connection")
		counterNumConnectionsAccepted.Inc()

		// Create a new connection-scoped context, which we'll use for signaling to our child
		// goroutines to halt.
		connCxt, cancel := context.WithCancel(cxt)
		var connW io.Writer = conn
		if s.config.DebugLogWrites {
			connW = writelogger.New(conn)
		}
		connection := &connection{
			ID:              connID,
			config:          &s.config,
			allCaches:       s.caches,
			allSnapshotters: s.binSnapCaches,
			cxt:             connCxt,
			cancelCxt:       cancel,
			conn:            conn,
			connW:           connW,
			logCxt: log.WithFields(log.Fields{
				"client": conn.RemoteAddr(),
				"connID": connID,
			}),

			encoder:     gob.NewEncoder(connW),
			flushWriter: func() error { return nil },
			readC:       make(chan interface{}),

			allMetrics: s.perSyncerConnMetrics,
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

func setWriteBufferSizeBestEffort(conn net.Conn, size int) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		// TLS connection: need to get the underlying socket to adjust the
		// write buffer size.
		conn = tlsConn.NetConn()
	}

	tcpConn, ok := conn.(interface{ SetWriteBuffer(bytes int) error })
	if !ok {
		log.WithField("conn", conn).Warn(
			"Failed to get underlying TCP connection to set write buffer size.")
		return
	}

	if err := tcpConn.SetWriteBuffer(size); err != nil {
		log.WithError(err).Warn("Failed to set write buffer size.")
		return
	}
}

func (s *Server) recordConnection(conn *connection) {
	s.lock.Lock()
	s.connIDToConn[conn.ID] = conn
	s.lock.Unlock()
}

func (s *Server) discardConnection(conn *connection) {
	s.lock.Lock()
	delete(s.connIDToConn, conn.ID)
	s.lock.Unlock()
}

func (s *Server) governNumberOfConnections(cxt context.Context) {
	defer s.Finished.Done()
	logCxt := log.WithField("thread", "numConnsGov")
	maxConns := s.config.MaxConns
	dropInterval := s.config.DropInterval
	ticker := jitter.NewTicker(dropInterval, dropInterval/10)
	healthTicks := time.NewTicker(healthInterval).C
	s.reportHealth()
	for {
		select {
		case newMax := <-s.maxConnsC:
			if newMax == maxConns {
				continue
			}
			logCxt.WithFields(log.Fields{
				"oldMax":     maxConns,
				"newMax":     newMax,
				"currentNum": s.NumActiveConnections(),
			}).Info("New target number of connections")
			maxConns = newMax
		case <-ticker.C:
			numConns := s.NumActiveConnections()
			if numConns > maxConns {
				logCxt := logCxt.WithFields(log.Fields{
					"max":     maxConns,
					"current": numConns,
				})
				dropped := s.TerminateRandomConnection(logCxt, "re-balance load with other Typha instances")
				if dropped {
					// Only increment the counter if we dropped a connection.
					counterNumConnectionsDropped.Inc()
				}
			}
		case <-cxt.Done():
			logCxt.Info("Context asked us to stop")
			return
		case <-healthTicks:
			s.reportHealth()
		}
	}
}

func (s *Server) handleGracefulShutDown(cxt context.Context, serverCancelFn context.CancelFunc) {
	defer s.Finished.Done()
	logCxt := log.WithField("thread", "gracefulShutdown")

	select {
	case <-s.shutdownC:
		logCxt.Info("Graceful shutdown triggered, starting to close connections...")
	case <-cxt.Done():
		logCxt.Info("Context asked us to stop")
		return
	}

	numConns := s.NumActiveConnections()
	if numConns == 0 {
		logCxt.Info("No active connections; shutting down immediately.")
		serverCancelFn()
		return
	}

	// Aim to close connections within 95% of the allotted time.
	dropInterval := s.config.ShutdownTimeout * 95 / 100 / time.Duration(numConns)
	logCtx := log.WithFields(log.Fields{
		"activeConnections":   numConns,
		"shutdownTimeout":     s.config.ShutdownTimeout,
		"maximumDropInterval": s.config.ShutdownMaxDropInterval,
	})
	if dropInterval > s.config.ShutdownMaxDropInterval {
		// We have a long time to shut down (say 5 minutes) but only a few connections.  Cap the delay between
		// dropping connections.
		dropInterval = s.config.ShutdownMaxDropInterval
		logCtx.Info("Using maximum shutdown drop interval.")
	} else {
		logCxt.WithField("dropInterval", dropInterval).Info("Calculated drop interval from shutdown timeout.")
	}
	ticker := jitter.NewTicker(dropInterval*95/100, dropInterval*10/100)
	for {
		select {
		case <-ticker.C:
			numConns := s.NumActiveConnections()
			logCxt := logCxt.WithField("remainingConns", numConns)
			dropped := s.TerminateRandomConnection(logCxt, "graceful shutdown in progress")
			if numConns <= 1 || !dropped {
				logCxt.Info("Finished closing connections, completing shut down...")
				// Note: we release the lock between NumActiveConnections and TerminateRandomConnection so,
				// in theory, if we haven't yet closed the listen socket, a new connection could just have been added.
				// We don't need to worry about that because serverCancelFn will shut down all remaining connections
				// by canceling their parent context.
				serverCancelFn()
				return
			}
		case <-cxt.Done():
			logCxt.Info("Context asked us to stop")
			return
		}
	}
}

func (s *Server) NumActiveConnections() int {
	s.lock.Lock()
	defer s.lock.Unlock()
	return len(s.connIDToConn)
}

func (s *Server) ShuttingDown() bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.shuttingDown
}

// TerminateRandomConnection tries to drop a connection at random.  On success, returns true.  If there are no
// connections returns false.
func (s *Server) TerminateRandomConnection(logCtx *log.Entry, reason string) bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	for connID, conn := range s.connIDToConn {
		logCtx.WithField("connID", connID).Infof("Closing connection; reason: %s.", reason)
		conn.cancelCxt()
		return true
	}
	return false
}

func (s *Server) reportHealth() {
	if s.config.HealthAggregator != nil {
		s.config.HealthAggregator.Report(healthName, &health.HealthReport{Live: true})
	}
}

func (s *Server) ShutDownGracefully() {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.shuttingDown {
		log.Info("Asked to shut down but shutdown already in progress.")
		return
	}
	log.Info("Starting graceful shutdown...")
	s.shuttingDown = true
	close(s.shutdownC)
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
	allCaches       map[syncproto.SyncerType]BreadcrumbProvider
	allSnapshotters map[syncproto.CompressionAlgorithm]map[syncproto.SyncerType]snapshotCache
	cache           BreadcrumbProvider
	syncerType      syncproto.SyncerType
	conn            net.Conn
	// connW is the writer to use to send things to the client.  It may be the net.Conn itself or a wrapper
	// around it.
	connW io.Writer

	// writeLock is used to protect calls that write to the connection after the initial synchronous handshake.
	// The delta-sending goroutine and the pinger both write to the connection.
	writeLock            sync.Mutex
	currentWriteDeadline time.Time
	encoder              *gob.Encoder
	flushWriter          func() error
	readC                chan interface{}

	logCxt                       *log.Entry
	chosenCompression            syncproto.CompressionAlgorithm
	clientSupportsDecoderRestart bool

	// Similarly to allCaches, allMetrics contains all the metrics relevant to a particular syncer.  We copy one
	// of them to the unnamed field after the handshake.
	allMetrics map[syncproto.SyncerType]perSyncerConnMetrics
	perSyncerConnMetrics
}

type snapshotCache interface {
	SendSnapshot(ctx context.Context, w io.Writer, conn WriteDeadlineSetter) (*snapcache.Breadcrumb, error)
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

	// Now do the (synchronous) handshake.
	if err = h.doHandshake(); err != nil {
		return // Error already logged.
	}
	h.gaugeNumConnectionsStreaming.Inc()
	defer h.gaugeNumConnectionsStreaming.Dec()

	// Figure out if we should restart the decoder with new settings.
	var binSnapCache snapshotCache
	if h.clientSupportsDecoderRestart {
		binSnapCache = h.allSnapshotters[h.chosenCompression][h.syncerType]
		var reasonsToRestart []string
		if h.chosenCompression != "" {
			reasonsToRestart = append(reasonsToRestart, fmt.Sprintf("enable compression: %v", h.chosenCompression))
		}
		if binSnapCache != nil {
			reasonsToRestart = append(reasonsToRestart, "send binary snapshot")
		}
		if len(reasonsToRestart) > 0 {
			// We have a reason to restart the encoding...
			h.logCxt.WithField("reasons", reasonsToRestart).Info("Restarting encoding.")
			err = h.restartEncodingIfSupported(strings.Join(reasonsToRestart, ";"))
			if err != nil {
				log.WithError(err).Info("Failed to restart encoding after handshake, tearing down connection.")
				return
			}
		}
	}

	var breadcrumb *snapcache.Breadcrumb
	if binSnapCache != nil {
		// We have a binary snapshot cache that supports this compression mode; send the compressed
		// binary snapshot instead of a streamed snapshot.
		snapStart := time.Now()
		breadcrumb, err = binSnapCache.SendSnapshot(h.cxt, h.connW, h.conn)
		if err != nil {
			log.WithError(err).Info("Failed to send snapshot to client, tearing down connection.")
			return
		}

		// The canned snapshot ends with a MsgDecoderRestart, so we just need to wait for the ACK.
		err = h.waitForAckAndRestartEncoder()
		if err != nil {
			log.WithError(err).Info("Failed to restart encoding after snapshot, tearing down connection.")
			return
		}
		h.logCxt.Info("Sent compressed binary snapshot and received ACK from client.")
		h.summarySnapshotSendTime.Observe(time.Since(snapStart).Seconds())
	} else {
		// Either client is old or we don't have support for sending a compressed snapshot of this type.
		// Stream the snapshot instead.
		h.logCxt.Info("Sending streamed snapshot.")
		breadcrumb = h.cache.CurrentBreadcrumb()
		err = h.streamSnapshotToClient(h.logCxt, breadcrumb)
		if err != nil {
			log.WithError(err).Info("Failed to send snapshot to client, tearing down connection.")
			return
		}
	}

	// Start a goroutine to stream deltas to the client.
	h.shutDownWG.Add(1)
	go h.sendDeltaUpdatesToClient(h.logCxt.WithField("thread", "kv-sender"), breadcrumb)

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
				h.summaryPingLatency.Observe(time.Since(msg.PingTimestamp).Seconds())
			default:
				h.logCxt.WithField("msg", msg).Error("Unknown message from client")
				return errors.New("unknown message type")
			}
		case <-pongTicker.C:
			since := time.Since(lastPongReceived)
			if since > h.config.PongTimeout {
				h.logCxt.WithFields(log.Fields{
					"pongTimeout":       h.config.PongTimeout,
					"timeSinceLastPong": since,
				}).Info("Too long since last pong from client, disconnecting")
				return errors.New("no pong received from client")
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
			if errors.Is(err, io.EOF) {
				logCxt.Info("Client closed the connection.")
			} else {
				logCxt.WithError(err).Info("Failed to read from client")
			}
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
func (h *connection) waitForMessage(logCxt *log.Entry, timeout time.Duration) (interface{}, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case msg := <-h.readC:
		if msg == nil {
			logCxt.Warning("Failed to read hello from client")
			return nil, ErrReadFailed
		}
		logCxt.WithField("msg", msg).Debug("Received message from client.")
		return msg, nil
	case <-timer.C:
		// Error gets logged by caller.
		return nil, fmt.Errorf("timed out waiting for message from client")
	case <-h.cxt.Done():
		// Error gets logged by caller.
		return nil, h.cxt.Err()
	}
}

func (h *connection) doHandshake() error {
	// Read the client's hello message.  Note: for TLS connections this
	// first read is where the TLS handshake happens.
	msg, err := h.waitForMessage(h.logCxt, h.config.HandshakeTimeout)
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
	h.syncerType = syncerType
	h.logCxt = h.logCxt.WithField("type", syncerType)
	h.perSyncerConnMetrics = h.allMetrics[syncerType]
	desiredSyncerCache := h.allCaches[syncerType]
	if desiredSyncerCache == nil {
		h.logCxt.WithField("requestedType", syncerType).Info("Client requested unknown SyncerType.")
		return ErrUnsupportedClientFeature
	}
	h.cache = desiredSyncerCache

	for _, alg := range hello.SupportedCompressionAlgorithms {
		switch alg {
		case syncproto.CompressionSnappy:
			h.chosenCompression = syncproto.CompressionSnappy
		}
	}
	h.clientSupportsDecoderRestart = hello.SupportsDecoderRestart
	if h.chosenCompression != "" && !hello.SupportsDecoderRestart {
		log.WithError(err).Warning("Client signalled compression but no support for decoder restart")
		h.chosenCompression = ""
	}

	if !hello.SupportsModernPolicyKeys {
		// The client is too old and we cannot support it. Reject the connection and wait for the
		// client to be upgraded.
		h.logCxt.Info("Client does not support modern policy keys, disconnecting.")
		return ErrUnsupportedClientFeature
	}

	// Respond to client's hello.
	err = h.sendMsg(syncproto.MsgServerHello{
		Version: buildinfo.Version,
		// Echo back the SyncerType so that up-level clients know that we understood their request.  Down-level
		// clients will ignore.
		SyncerType:                  syncerType,
		SupportsNodeResourceUpdates: true,
		ServerConnID:                h.ID,
	})
	if err != nil {
		log.WithError(err).Warning("Failed to send hello to client")
		return err
	}
	return nil
}

func (h *connection) restartEncodingIfSupported(message string) error {
	if !h.clientSupportsDecoderRestart {
		log.Debug("Can't restart decoder, client doesn't support it.")
		return nil
	}

	// Signal for the client to restart its decoder (possibly) with compression enabled.
	err := h.sendMsg(syncproto.MsgDecoderRestart{
		Message:              message,
		CompressionAlgorithm: h.chosenCompression,
	})
	if err != nil {
		log.WithError(err).Warning("Failed to send DecoderRestart to client")
		return err
	}

	err = h.waitForAckAndRestartEncoder()
	return err
}

func (h *connection) waitForAckAndRestartEncoder() error {
	// Wait until the client ACKs.  This avoids sending compressed data that
	// might get misinterpreted by the gob decoder.  We use the pong timeout
	// here because it has a very similar purpose; we sent something, and
	// we're waiting for the response.
	msg, err := h.waitForMessage(h.logCxt, h.config.PongTimeout)
	if err != nil {
		h.logCxt.WithError(err).Warn("Failed to read client ACK.")
		return err
	}
	ack, ok := msg.(syncproto.MsgACK)
	if !ok {
		h.logCxt.WithField("msg", msg).Error("Unexpected message from client.")
		return ErrUnexpectedClientMsg
	}
	h.logCxt.WithField("msg", ack).Info("Received ACK message from client.")

	// Upgrade to compressed connection if required.
	bw := bufio.NewWriter(h.connW)
	switch h.chosenCompression {
	case syncproto.CompressionSnappy:
		w := snappy.NewBufferedWriter(bw)
		h.encoder = gob.NewEncoder(w) // Need a new Encoder, there's no way to change out the Writer.
		h.flushWriter = func() error {
			err := w.Flush()
			if err != nil {
				return err
			}
			return bw.Flush()
		}
	default:
		h.encoder = gob.NewEncoder(bw) // Need a new Encoder, there's no way to change out the Writer.
		h.flushWriter = bw.Flush
	}
	return nil
}

// sendMsg sends a message to the client.  It may be called from multiple goroutines.
func (h *connection) sendMsg(msg interface{}) error {
	if h.cxt.Err() != nil {
		// Optimisation, don't bother to send if we're being torn down.
		return h.cxt.Err()
	}
	h.logCxt.WithField("msg", msg).Trace("Sending message to client")
	envelope := syncproto.Envelope{
		Message: msg,
	}
	startTime := time.Now()

	// The gob Encoder has its own mutex, but we need to synchronise around the flush operation as well.
	h.writeLock.Lock()
	defer h.writeLock.Unlock()

	// Make sure we have a timeout on the connection so that we can't block forever in the synchronous
	// part of the protocol.  After we send the snapshot we rely more on the layer 7 ping/pong.
	if err := h.maybeResetWriteTimeout(); err != nil {
		h.logCxt.WithError(err).Info("Failed to set write timeout when sending to client.")
		return err
	}

	if err := h.encoder.Encode(&envelope); err != nil {
		h.logCxt.WithError(err).Info("Failed to write to client")
		return err
	}
	if err := h.flushWriter(); err != nil {
		h.logCxt.WithError(err).Info("Failed to flush write to client")
		return err
	}
	h.summaryWriteLatency.Observe(time.Since(startTime).Seconds())
	return nil
}

func (h *connection) maybeResetWriteTimeout() error {
	now := time.Now()
	// Under heavy load, updating the timeout for every message seemed to cause noticeable overhead,
	// so we add a 10% buffer and then only reset it when it drops too low.
	if h.currentWriteDeadline.Before(now.Add(h.config.WriteTimeout)) {
		newWriteDeadline := now.Add(h.config.WriteTimeout * 110 / 100)
		err := h.conn.SetWriteDeadline(newWriteDeadline)
		if err != nil {
			h.logCxt.WithError(err).Info("Failed to set client write timeout")
			return err
		}
		h.currentWriteDeadline = newWriteDeadline
	}
	return nil
}

// sendDeltaUpdatesToClient follows the breadcrumbs from the given one, sending delta updates from each
// subsequent breadcrumb to the client.  It does not send the deltas from the given breadcrumb (it assumes
// that breadcrumb was sent to the client already as the snapshot).
func (h *connection) sendDeltaUpdatesToClient(logCxt *log.Entry, breadcrumb *snapcache.Breadcrumb) {
	defer func() {
		logCxt.Info("KV-sender goroutine shutting down")
		h.cancelCxt()
		h.shutDownWG.Done()
		logCxt.Info("KV-sender goroutine finished")
	}()

	// We just finished sending the snapshot, calculate the grace time for the client to catch up to a recent breadcrumb.
	gracePeriodEndTime := time.Now().Add(h.config.NewClientFallBehindGracePeriod)
	log.WithField("graceEnd", gracePeriodEndTime).Info("Calculated end of client's grace period.")

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
			h.summaryClientLatency.Observe(crumbAge.Seconds())
			logCxt.WithFields(log.Fields{
				"seqNo":     breadcrumb.SequenceNumber,
				"timestamp": breadcrumb.Timestamp,
				"state":     breadcrumb.SyncStatus,
				"age":       crumbAge,
			}).Debug("Got next breadcrumb for this client.")

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
						"mySnapshotSize": breadcrumb.KVs.Len(),
					}).Warn("Client fell behind. Disconnecting.")
					return
				} else if !loggedClientBehind {
					logCxt.WithFields(log.Fields{
						"snapAge":        crumbAge,
						"mySeqNo":        breadcrumb.SequenceNumber,
						"latestSeqNo":    latestCrumb.SequenceNumber,
						"gracePeriod":    h.config.NewClientFallBehindGracePeriod,
						"mySnapshotSize": breadcrumb.KVs.Len(),
					}).Warn("Client is a long way behind after sending snapshot; " +
						"allowing grace period for it to catch up.")
					loggedClientBehind = true
					h.counterGracePeriodUsed.Inc()
				}
			} else if loggedClientBehind && time.Now().After(gracePeriodEndTime) {
				// Client caught up after being behind when we sent it a snapshot.
				logCxt.WithFields(log.Fields{
					"snapAge":        crumbAge,
					"mySeqNo":        breadcrumb.SequenceNumber,
					"latestSeqNo":    latestCrumb.SequenceNumber,
					"mySnapshotSize": breadcrumb.KVs.Len(),
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
			h.summaryNextCatchupLatency.Observe(timeSpentInNext.Seconds())

			if crumbAge < h.config.MinBatchingAgeThreshold {
				// Caught up, stop batching.
				break
			}
		}

		if len(deltas) > 0 {
			// Send the deltas relative to the previous snapshot.
			logCxt.WithField("num", len(deltas)).Debug("Sending deltas")
			h.summaryNumKVsPerMsg.Observe(float64(len(deltas)))
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
func (h *connection) streamSnapshotToClient(logCxt *log.Entry, breadcrumb *snapcache.Breadcrumb) error {
	startTime := time.Now()
	err := writeSnapshotMessages(
		h.cxt,
		h.logCxt.WithField("destination", "direct to client"),
		breadcrumb,
		h.sendMsg,
		h.config.MaxMessageSize,
	)
	if err != nil {
		return err
	}
	logCxt.WithField("numKeys", breadcrumb.KVs.Len()).Info("Finished sending snapshot to client")
	h.summarySnapshotSendTime.Observe(time.Since(startTime).Seconds())
	return nil
}

// writeSnapshotMessages chunks the given breadcrumb up into syncproto.MsgKVs objects and calls writeMsg for each one.
func writeSnapshotMessages(
	ctx context.Context,
	logCxt *log.Entry,
	breadcrumb *snapcache.Breadcrumb,
	writeMsg func(any) error,
	maxMsgSize int,
) (err error) {
	logCxt = logCxt.WithFields(log.Fields{
		"seqNo":  breadcrumb.SequenceNumber,
		"status": breadcrumb.SyncStatus,
	})
	logCxt.Info("Starting to write snapshot")

	// writeKVs is a utility function that sends the kvs buffer to the client (if non-empty) and clears the buffer.
	var kvs []syncproto.SerializedUpdate
	var numKeys int
	writeKVs := func() error {
		if len(kvs) == 0 {
			return nil
		}
		logCxt.WithField("numKVs", len(kvs)).Debug("Writing snapshot KVs.")
		numKeys += len(kvs)
		err := writeMsg(syncproto.MsgKVs{
			KVs: kvs,
		})
		if err != nil {
			logCxt.WithError(err).Info("Failed to write snapshot KVs")
		}
		kvs = kvs[:0]
		return err
	}

	breadcrumb.KVs.Ascend(func(entry syncproto.SerializedUpdate) bool {
		if ctx.Err() != nil {
			err = ctx.Err()
			return false
		}
		kvs = append(kvs, entry)
		if len(kvs) >= maxMsgSize {
			// Buffer is full, send the next batch.
			err = writeKVs()
			if err != nil {
				return false
			}
		}
		return true
	})
	if err != nil {
		return
	}

	err = writeKVs()
	if err != nil {
		return
	}
	logCxt.Info("Finished writing snapshot.")
	return
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

// perSyncerConnMetrics contains a set of Prometheus metrics that each connection needs to update.  There is one
// set per syncer type.
type perSyncerConnMetrics struct {
	counterGracePeriodUsed       prometheus.Counter
	summarySnapshotSendTime      prometheus.Summary
	summaryClientLatency         prometheus.Summary
	summaryWriteLatency          prometheus.Summary
	summaryNextCatchupLatency    prometheus.Summary
	summaryPingLatency           prometheus.Summary
	summaryNumKVsPerMsg          prometheus.Summary
	gaugeNumConnectionsStreaming prometheus.Gauge
}

func makePerSyncerConnMetrics(syncerType syncproto.SyncerType) perSyncerConnMetrics {
	var c perSyncerConnMetrics
	syncerLabels := map[string]string{
		"syncer": string(syncerType),
	}
	c.summarySnapshotSendTime = promutils.GetOrRegister(cprometheus.NewSummary(prometheus.SummaryOpts{
		Name:        "typha_client_snapshot_send_secs",
		Help:        "How long it took to send the initial snapshot to each client.",
		ConstLabels: syncerLabels,
	}))
	c.summaryClientLatency = promutils.GetOrRegister(cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_client_latency_secs",
		Help: "Per-client latency.  I.e. how far behind the current state is each client.",
		// Reduce the time window so the stat is more useful after a spike.
		MaxAge:      1 * time.Minute,
		AgeBuckets:  2,
		ConstLabels: syncerLabels,
	}))
	c.summaryWriteLatency = promutils.GetOrRegister(cprometheus.NewSummary(prometheus.SummaryOpts{
		Name:        "typha_client_write_latency_secs",
		Help:        "Per-client write.  How long each write call is taking.",
		ConstLabels: syncerLabels,
	}))
	c.summaryNextCatchupLatency = promutils.GetOrRegister(cprometheus.NewSummary(prometheus.SummaryOpts{
		Name:        "typha_next_breadcrumb_latency_secs",
		Help:        "Time to retrieve next breadcrumb when already behind.",
		ConstLabels: syncerLabels,
	}))
	c.summaryPingLatency = promutils.GetOrRegister(cprometheus.NewSummary(prometheus.SummaryOpts{
		Name:        "typha_ping_latency",
		Help:        "Round-trip ping latency to client.",
		ConstLabels: syncerLabels,
	}))
	c.summaryNumKVsPerMsg = promutils.GetOrRegister(cprometheus.NewSummary(prometheus.SummaryOpts{
		Name:        "typha_kvs_per_msg",
		Help:        "Number of KV pairs sent in each message.",
		ConstLabels: syncerLabels,
	}))
	c.counterGracePeriodUsed = counterVecGracePeriodUsed.WithLabelValues(string(syncerType))
	c.gaugeNumConnectionsStreaming = gaugeVecNumConnectionsStreaming.WithLabelValues(string(syncerType))
	return c
}
