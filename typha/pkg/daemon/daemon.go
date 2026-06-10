// Copyright (c) 2017-2018,2020-2021 Tigera, Inc. All rights reserved.
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

package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/bgpsyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/dedupebuffer"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/felixsyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/nodestatussyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/tunnelipsyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/debugserver"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/libcalico-go/lib/metricsserver"
	"github.com/projectcalico/calico/pkg/buildinfo"
	"github.com/projectcalico/calico/typha/pkg/calc"
	"github.com/projectcalico/calico/typha/pkg/config"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/jitter"
	"github.com/projectcalico/calico/typha/pkg/k8s"
	"github.com/projectcalico/calico/typha/pkg/leaderelection"
	"github.com/projectcalico/calico/typha/pkg/logutils"
	"github.com/projectcalico/calico/typha/pkg/rolemanager"
	"github.com/projectcalico/calico/typha/pkg/snapcache"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
	"github.com/projectcalico/calico/typha/pkg/syncserver"
	"github.com/projectcalico/calico/typha/pkg/syncsource"
)

const DefaultConfigFile = "/etc/calico/typha.cfg"

// TyphaDaemon handles the lifecycle of the Typha process. Use NewCommand() for the CLI
// entry point, or call Run() directly for programmatic use. The lifecycle is broken out
// into several individual methods for ease of testing.
type TyphaDaemon struct {
	BuildInfoLogCxt *log.Entry
	ConfigFilePath  string
	DatastoreClient DatastoreClient
	ConfigParams    *config.Config

	// The components of the server, created in CreateServer() below.
	SyncerPipelines    []*syncerPipeline
	CachesBySyncerType map[syncproto.SyncerType]syncserver.BreadcrumbProvider
	Server             *syncserver.Server

	// The functions below default to real library functions but they can be overridden for testing.
	NewClientV3           func(config apiconfig.CalicoAPIConfig) (DatastoreClient, error)
	ConfigureEarlyLogging func()
	ConfigureLogging      func(configParams *config.Config)

	// Health monitoring.
	healthAggregator *health.HealthAggregator

	// Node counting.
	nodeCounter *calc.NodeCounter

	// Hierarchical mode.  roleManaged is true when the pipeline sources are
	// owned by the role manager (election-driven hierarchy) rather than wired
	// statically.  Elector is the leader-election subsystem; it is stored here
	// (per WS-B's handoff note) so the role manager can subscribe.  RoleManager
	// drives promotion/demotion.
	roleManaged   bool
	Elector       *leaderelection.Elector
	RoleManager   *rolemanager.Manager
	electorCancel context.CancelFunc

	// upstreamDiscoverer is the discoverer the role manager's upstream sources
	// use to find the leader.  Stored so the self/non-holder filter can consult
	// the elector's CurrentHolder.
	upstreamDiscoverer *discovery.Discoverer
}

// syncerPipeline is the per-syncer-type processing chain.  The head of the
// chain is a dedupe buffer that is permanently installed for the lifetime of
// the process; the actual source (a datastore syncer or an upstream-Typha
// syncclient) attaches behind it via the Source field.  See typha/DESIGN.md,
// "Hierarchical mode", for why the buffer is the stable element.
//
//	Source -> DedupeBuffer -(SendToSinkForever)-> Validator (+NodeCounter) ->
//	    ValidatorToCache decoupler -> snapcache.Cache
type syncerPipeline struct {
	Type             syncproto.SyncerType
	Source           syncsource.SyncerSource
	DedupeBuffer     *dedupebuffer.DedupeBuffer
	Validator        *calc.ValidationFilter
	ValidatorToCache *calc.SyncerCallbacksDecoupler
	Cache            *snapcache.Cache

	// Source factories.  In role-managed (election-driven hierarchical) mode,
	// Source is left nil and the role manager builds/stops sources on demand via
	// these factories.  In the static modes (datastore-only or static upstream)
	// Source is built eagerly and started by Start; the factories are unused.
	NewDatastoreSource func() syncsource.SyncerSource
	NewUpstreamSource  func() syncsource.SyncerSource
}

// Start brings up the always-on part of the pipeline (the downstream pumps and
// the snapcache).  It starts the source too unless roleManaged is true, in which
// case the role manager owns the source lifecycle.
func (p syncerPipeline) Start(cxt context.Context, roleManaged bool) {
	logCxt := log.WithField("syncerType", p.Type)
	logCxt.Info("Starting validator-to-cache decoupler")
	go p.ValidatorToCache.SendTo(p.Cache)
	logCxt.Info("Starting dedupe buffer pump")
	go p.DedupeBuffer.SendToSinkForever(p.Validator)
	logCxt.Info("Starting cache")
	p.Cache.Start(cxt)
	if roleManaged {
		logCxt.Info("Role-managed pipeline; source will be started by the role manager")
	} else {
		logCxt.Info("Starting syncer source")
		if err := p.Source.Start(cxt); err != nil {
			logCxt.WithError(err).Fatal("Failed to start syncer source")
		}
	}
	logCxt.Info("Started syncer pipeline")
}

func New() *TyphaDaemon {
	return &TyphaDaemon{
		NewClientV3: func(config apiconfig.CalicoAPIConfig) (DatastoreClient, error) {
			client, err := clientv3.New(config)
			if err != nil {
				return nil, err
			}
			return ClientV3Shim{client.(RealClientV3), config}, nil
		},
		ConfigureEarlyLogging: logutils.ConfigureEarlyLogging,
		ConfigureLogging:      logutils.ConfigureLogging,
		CachesBySyncerType:    map[syncproto.SyncerType]syncserver.BreadcrumbProvider{},
	}
}

// Run starts the Typha daemon with the given config file path and blocks until shutdown.
func (t *TyphaDaemon) Run(ctx context.Context, configFile string) error {
	t.DoEarlyRuntimeSetup()
	t.ConfigFilePath = configFile
	t.BuildInfoLogCxt = log.WithFields(log.Fields{
		"version":    buildinfo.Version,
		"buildDate":  buildinfo.BuildDate,
		"gitCommit":  buildinfo.GitRevision,
		"GOMAXPROCS": runtime.GOMAXPROCS(0),
	})
	t.BuildInfoLogCxt.Info("Typha starting up")
	if err := t.LoadConfiguration(ctx); err != nil {
		return err
	}
	t.CreateServer()
	t.Start(ctx)
	t.WaitAndShutDown(ctx)
	return nil
}

// DoEarlyRuntimeSetup does early runtime/logging configuration that needs to happen before we do any work.
func (t *TyphaDaemon) DoEarlyRuntimeSetup() {
	// Special-case handling for environment variable-configured logging:
	// Initialise early so we can trace out config parsing.
	t.ConfigureEarlyLogging()
}

// SetConfigFilePath sets the config file path and initializes the build info log context.
// Used by tests that need to configure the daemon without going through the CLI.
func (t *TyphaDaemon) SetConfigFilePath(path string) {
	t.ConfigFilePath = path
	t.BuildInfoLogCxt = log.WithFields(log.Fields{
		"version":    buildinfo.Version,
		"buildDate":  buildinfo.BuildDate,
		"gitCommit":  buildinfo.GitRevision,
		"GOMAXPROCS": runtime.GOMAXPROCS(0),
	})
}

// LoadConfiguration uses the command-line configuration and environment variables to load our configuration.
// It initializes the datastore connection.
func (t *TyphaDaemon) LoadConfiguration(ctx context.Context) error {
	// Log out the kubernetes server details that we use in BPF mode.
	log.WithFields(log.Fields{
		"KUBERNETES_SERVICE_HOST": os.Getenv("KUBERNETES_SERVICE_HOST"),
		"KUBERNETES_SERVICE_PORT": os.Getenv("KUBERNETES_SERVICE_PORT"),
	}).Info("Kubernetes server override env vars.")

	// Load the configuration from all the different sources including the
	// datastore and merge. Keep retrying on failure.  We'll sit in this
	// loop until the datastore is ready.
	log.Infof("Loading configuration...")
	var configParams *config.Config
	var datastoreConfig apiconfig.CalicoAPIConfig
configRetry:
	for {
		if err := ctx.Err(); err != nil {
			log.WithError(err).Warn("Context canceled.")
			return err
		}
		// Load locally-defined config, including the datastore connection
		// parameters. First the environment variables.
		configParams = config.New()
		envConfig := config.LoadConfigFromEnvironment(os.Environ())
		// Then, the config file.
		fileConfig, err := config.LoadConfigFile(t.ConfigFilePath)
		if err != nil {
			log.WithError(err).WithField("configFile", t.ConfigFilePath).Error(
				"Failed to load configuration file")
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		// Parse and merge the local config.
		_, err = configParams.UpdateFrom(envConfig, config.EnvironmentVariable)
		if err != nil {
			log.WithError(err).WithField("configFile", t.ConfigFilePath).Error(
				"Failed to parse configuration environment variable")
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		_, err = configParams.UpdateFrom(fileConfig, config.ConfigFile)
		if err != nil {
			log.WithError(err).WithField("configFile", t.ConfigFilePath).Error(
				"Failed to parse configuration file")
			time.Sleep(1 * time.Second)
			continue configRetry
		}

		// Validate the config params
		err = configParams.Validate()
		if err != nil {
			log.WithError(err).Error(
				"Failed to parse/validate configuration.")
			time.Sleep(1 * time.Second)
			continue configRetry
		}

		// We should now have enough config to connect to the datastore.
		datastoreConfig = configParams.DatastoreConfig()
		t.DatastoreClient, err = t.NewClientV3(datastoreConfig)
		if err != nil {
			log.WithError(err).Error("Failed to connect to datastore")
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		break configRetry
	}

	// If we get here, we've loaded the configuration successfully.
	// Update log levels before we do anything else.
	t.ConfigureLogging(configParams)
	// Since we may have enabled more logging, log with the build context
	// again.
	t.BuildInfoLogCxt.WithField("config", configParams).Info(
		"Successfully loaded configuration.")

	// Ensure that, as soon as we are able to connect to the datastore at all, it is initialized.
	// Note: we block further start-up while we do this, which means, if we're stuck here for long enough,
	// the liveness healthcheck will time out and start to fail.  That's fairly reasonable, being stuck here
	// likely means we have some persistent datastore connection issue and restarting Typha may solve that.
	for {
		if err := ctx.Err(); err != nil {
			log.WithError(err).Warn("Context canceled.")
			return err
		}
		var err error
		func() { // Closure to avoid leaking the defer.
			log.Info("Initializing the datastore (if needed).")
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			err = t.DatastoreClient.EnsureInitialized(ctx, "", "typha")
		}()
		if err != nil {
			log.WithError(err).Error("Failed to initialize datastore")
			time.Sleep(1 * time.Second)
			continue
		}
		log.Info("Datastore initialized.")

		break
	}
	t.ConfigParams = configParams
	return nil
}

func (t *TyphaDaemon) addSyncerPipeline(
	syncerType syncproto.SyncerType,
	newSyncer func(callbacks bapi.SyncerCallbacks) bapi.Syncer,
	upstreamDiscoverer *discovery.Discoverer,
) {
	// The dedupe buffer is the permanent head of the pipeline; it feeds the
	// validator via its SendToSinkForever pump (started in pipeline.Start).  It
	// is also the syncer callbacks sink that the source delivers into, and it is
	// restart-aware so that the upstream syncclient can reconcile on reconnect
	// (and so that WS-C can swap sources behind it).
	dedupeBuf := dedupebuffer.New()

	toCache := calc.NewSyncerCallbacksDecoupler()
	var validator *calc.ValidationFilter
	if syncerType == syncproto.SyncerTypeFelix {
		// If this is a felix syncer, insert a counter after the validation filter which is used to track
		// the number of nodes in the cluster. We only want to count nodes once, which is why we only do this
		// for the felix syncer and not the BGP syncer as well.
		t.nodeCounter = calc.NewNodeCounter(toCache)
		validator = calc.NewValidationFilter(t.nodeCounter)
	} else {
		// Otherwise, just go from validator to cache directly.
		validator = calc.NewValidationFilter(toCache)
	}

	// Create our snapshot cache, which stores point-in-time copies of the datastore contents.
	cache := snapcache.New(snapcache.Config{
		MaxBatchSize:     t.ConfigParams.SnapshotCacheMaxBatchSize,
		HealthAggregator: t.healthAggregator,
		Name:             string(syncerType),
	})

	// Build source factories for this pipeline.  newDatastoreSource runs a real
	// datastore syncer (leader / non-hierarchical).  newUpstreamSource connects
	// to an upstream Typha (follower).
	newDatastoreSource := func() syncsource.SyncerSource {
		return syncsource.NewDatastoreSource(newSyncer, dedupeBuf)
	}
	newUpstreamSource := func() syncsource.SyncerSource {
		return syncsource.NewUpstreamTyphaSource(
			upstreamDiscoverer,
			syncsource.UpstreamConfig{
				MyVersion:  buildinfo.Version,
				MyHostname: t.hostname(),
				MyInfo: fmt.Sprintf("Revision: %s; Build date: %s",
					buildinfo.GitRevision, buildinfo.BuildDate),
				SyncerType: syncerType,
				ClientOptions: syncclient.Options{
					ReadTimeout:  t.ConfigParams.UpstreamReadTimeout,
					WriteTimeout: t.ConfigParams.UpstreamWriteTimeout,
					KeyFile:      t.ConfigParams.ClientKeyFile,
					CertFile:     t.ConfigParams.ClientCertFile,
					CAFile:       t.ConfigParams.ClientCAFile,
					ServerCN:     t.ConfigParams.UpstreamServerCN,
					ServerURISAN: t.ConfigParams.UpstreamServerURISAN,
				},
			},
			dedupeBuf,
		)
	}

	// Choose the source wiring:
	//   - role-managed hierarchy: leave Source nil; the role manager creates and
	//     swaps sources via the factories.
	//   - static upstream (HierarchyEnabled + UpstreamAddr/Service, no election):
	//     eagerly build an upstream source (WS-A behaviour, manual chaining).
	//   - default: eagerly build a datastore source.
	var source syncsource.SyncerSource
	switch {
	case t.roleManaged:
		source = nil
	case t.ConfigParams.HierarchyEnabled:
		source = newUpstreamSource()
	default:
		source = newDatastoreSource()
	}

	pipeline := &syncerPipeline{
		Type:               syncerType,
		Source:             source,
		DedupeBuffer:       dedupeBuf,
		Validator:          validator,
		ValidatorToCache:   toCache,
		Cache:              cache,
		NewDatastoreSource: newDatastoreSource,
		NewUpstreamSource:  newUpstreamSource,
	}
	t.SyncerPipelines = append(t.SyncerPipelines, pipeline)
	t.CachesBySyncerType[syncerType] = cache
}

// hostname returns this Typha's hostname for use in the client hello when
// connecting to an upstream Typha.  It is best-effort; the upstream only uses
// it for logging/metrics.
func (t *TyphaDaemon) hostname() string {
	if hn, err := os.Hostname(); err == nil {
		return hn
	}
	return "typha"
}

// CreateServer creates and configures (but does not start) the server components.
func (t *TyphaDaemon) CreateServer() {
	// Health monitoring, for liveness and readiness endpoints.
	t.healthAggregator = health.NewHealthAggregator()

	// Decide whether the role manager owns the pipeline sources.  This is the
	// election-driven hierarchy: hierarchy enabled, election enabled, and no
	// static upstream configured (a static upstream takes precedence and pins us
	// as a follower, for manual chaining / tests).
	t.roleManaged = t.ConfigParams.HierarchyEnabled &&
		t.ConfigParams.LeaderElectionEnabled &&
		!t.ConfigParams.UpstreamConfigured()
	if t.ConfigParams.HierarchyEnabled && t.ConfigParams.UpstreamConfigured() && t.ConfigParams.LeaderElectionEnabled {
		log.Warn("Both a static upstream and leader election are configured; " +
			"the static upstream takes precedence and this Typha will not participate " +
			"in election-driven promotion/demotion.")
	}

	// In hierarchical mode, build a discoverer for the upstream Typha that all
	// four pipelines share (the discoverer is stateless with respect to syncer
	// type; each pipeline gets its own syncclient connection).  In role-managed
	// mode the discoverer targets the leader Service; in static mode it uses the
	// configured upstream address/service.
	if t.ConfigParams.HierarchyEnabled {
		t.upstreamDiscoverer = t.newUpstreamDiscoverer()
	}
	upstreamDiscoverer := t.upstreamDiscoverer

	// Now create the Syncer and caching layer (one pipeline for each syncer we support).
	t.addSyncerPipeline(syncproto.SyncerTypeFelix, t.DatastoreClient.FelixSyncerByIface, upstreamDiscoverer)
	t.addSyncerPipeline(syncproto.SyncerTypeBGP, t.DatastoreClient.BGPSyncerByIface, upstreamDiscoverer)
	t.addSyncerPipeline(syncproto.SyncerTypeTunnelIPAllocation, t.DatastoreClient.TunnelIPAllocationSyncerByIface, upstreamDiscoverer)
	t.addSyncerPipeline(syncproto.SyncerTypeNodeStatus, t.DatastoreClient.NodeStatusSyncerByIface, upstreamDiscoverer)

	// Create the server, which listens for connections from Felix.
	t.Server = syncserver.New(
		t.CachesBySyncerType,
		syncserver.Config{
			MaxMessageSize:                 t.ConfigParams.ServerMaxMessageSize,
			MinBatchingAgeThreshold:        t.ConfigParams.ServerMinBatchingAgeThresholdSecs,
			MaxFallBehind:                  t.ConfigParams.ServerMaxFallBehindSecs,
			NewClientFallBehindGracePeriod: t.ConfigParams.ServerNewClientFallBehindGracePeriod,
			PingInterval:                   t.ConfigParams.ServerPingIntervalSecs,
			PongTimeout:                    t.ConfigParams.ServerPongTimeoutSecs,
			HandshakeTimeout:               t.ConfigParams.ServerHandshakeTimeoutSecs,
			DropInterval:                   t.ConfigParams.ConnectionDropIntervalSecs,
			ShutdownTimeout:                t.ConfigParams.ShutdownTimeoutSecs,
			ShutdownMaxDropInterval:        t.ConfigParams.ShutdownConnectionDropIntervalMaxSecs,
			MaxConns:                       t.ConfigParams.MaxConnectionsUpperLimit,
			Port:                           t.ConfigParams.ServerPort,
			Host:                           t.ConfigParams.ServerHost,
			HealthAggregator:               t.healthAggregator,
			KeyFile:                        t.ConfigParams.ServerKeyFile,
			CertFile:                       t.ConfigParams.ServerCertFile,
			CAFile:                         t.ConfigParams.CAFile,
			ClientCN:                       t.ConfigParams.ClientCN,
			ClientURISAN:                   t.ConfigParams.ClientURISAN,
		},
	)
}

// newUpstreamDiscoverer builds the discovery.Discoverer used to find the
// upstream Typha in hierarchical mode.
//
//   - Static mode (UpstreamAddr / UpstreamK8s* set): honour those params
//     directly (WS-A behaviour, manual chaining / tests).
//   - Role-managed mode (election-driven): discover via the leader Service,
//     which selects only the pod that has labelled itself leader.
//
// In both cases we install a post-discovery filter that drops any endpoint that
// resolves to ourselves, and, in role-managed mode, any endpoint that is not the
// current lease holder (belt-and-braces cycle prevention).
func (t *TyphaDaemon) newUpstreamDiscoverer() *discovery.Discoverer {
	var opts []discovery.Option
	if t.roleManaged {
		// Discover the leader through the leader Service.  PodNamespace is where
		// the leader Service lives (same namespace as the Typha pods).
		opts = []discovery.Option{
			discovery.WithInClusterKubeClient(),
			discovery.WithKubeService(t.ConfigParams.PodNamespace, t.ConfigParams.LeaderServiceName),
			discovery.WithKubeServicePortNameOverride(t.ConfigParams.LeaderServicePortName),
			discovery.WithPostDiscoveryFilter(t.filterOutSelf),
			discovery.WithPostDiscoveryFilter(t.filterToLeaseHolder),
		}
	} else {
		opts = []discovery.Option{
			discovery.WithAddrOverride(t.ConfigParams.UpstreamAddr),
			discovery.WithInClusterKubeClient(),
			discovery.WithKubeService(t.ConfigParams.UpstreamK8sNamespace, t.ConfigParams.UpstreamK8sServiceName),
			discovery.WithKubeServicePortNameOverride(t.ConfigParams.UpstreamK8sPortName),
			discovery.WithPostDiscoveryFilter(t.filterOutSelf),
		}
	}
	return discovery.New(opts...)
}

// filterToLeaseHolder is a post-discovery filter used in role-managed mode.  The
// leader Service should already select only the leader pod, but as belt-and-
// braces (a label can linger after a SIGKILL until the pod's endpoints
// disappear) we additionally drop any endpoint that is not the current lease
// holder, when the holder is known.  We resolve the holder pod's IP via the k8s
// API only as needed; if we cannot resolve it we keep the endpoint (failing open
// rather than disconnecting from a possibly-correct leader).
func (t *TyphaDaemon) filterToLeaseHolder(typhas []discovery.Typha) ([]discovery.Typha, error) {
	if t.Elector == nil {
		return typhas, nil
	}
	holder, ok := t.Elector.CurrentHolder()
	if !ok || holder == "" {
		// No holder observed yet; don't filter (let discovery return what it
		// found — the Service selector is the primary guard).
		return typhas, nil
	}
	// The holder identity is the leader's pod name.  We don't have a cheap
	// pod-name-on-endpoint mapping here (EndpointSlice carries node name, not pod
	// name), so this filter is best-effort: if the leader Service is returning a
	// single endpoint we trust it.  When more than one endpoint is returned
	// (stale label window) we log loudly; full pod-IP resolution is deferred to
	// WS-E where per-tier identity is modelled.
	if len(typhas) > 1 {
		log.WithFields(log.Fields{
			"holder":    holder,
			"endpoints": typhas,
		}).Warn("Leader Service returned multiple endpoints; expected one. " +
			"Proceeding with discovered endpoints (a stale leader label may be lingering).")
	}
	return typhas, nil
}

// filterOutSelf removes any discovered upstream Typha endpoint that points back
// at this instance, so that we never chain to ourselves.  We compare against
// our own pod IP (POD_IP / our hostname's resolved address) and our server
// port.
func (t *TyphaDaemon) filterOutSelf(typhas []discovery.Typha) ([]discovery.Typha, error) {
	selfIPs := t.selfIPs()
	if len(selfIPs) == 0 {
		return typhas, nil
	}
	var out []discovery.Typha
	for _, typha := range typhas {
		host, _, err := net.SplitHostPort(typha.Addr)
		if err != nil {
			// Can't parse; keep it rather than risk dropping a valid endpoint.
			out = append(out, typha)
			continue
		}
		candidateIP := typha.IP
		if candidateIP == "" {
			candidateIP = host
		}
		if selfIPs[candidateIP] {
			log.WithField("addr", typha.Addr).Warn(
				"Filtering out upstream Typha endpoint that points back at ourselves.")
			continue
		}
		out = append(out, typha)
	}
	return out, nil
}

// selfIPs returns the set of IP addresses that identify this Typha instance,
// used by the self-connection guard.  Uses POD_IP if set, plus any addresses
// our hostname resolves to.
func (t *TyphaDaemon) selfIPs() map[string]bool {
	ips := map[string]bool{}
	if podIP := os.Getenv("POD_IP"); podIP != "" {
		ips[podIP] = true
	}
	if addrs, err := net.LookupHost(t.hostname()); err == nil {
		for _, a := range addrs {
			ips[a] = true
		}
	}
	return ips
}

// Start starts all the server components in background goroutines.
func (t *TyphaDaemon) Start(cxt context.Context) {
	// Now we've connected everything up, start the background processing threads.
	log.Info("Starting the datastore Syncer/cache layer")
	for _, s := range t.SyncerPipelines {
		s.Start(cxt, t.roleManaged)
	}
	t.Server.Start(cxt)
	if t.ConfigParams.ConnectionRebalancingMode == "kubernetes" {
		log.Info("Kubernetes connection rebalancing is enabled, starting k8s poll goroutine.")
		k8sAPI := k8s.NewK8sAPI(t.nodeCounter)
		ticker := jitter.NewTicker(
			t.ConfigParams.K8sServicePollIntervalSecs,
			t.ConfigParams.K8sServicePollIntervalSecs/10)
		go k8s.PollK8sForConnectionLimit(cxt, t.ConfigParams, ticker.C, k8sAPI, t.Server, len(t.CachesBySyncerType))
	}
	log.Info("Started the datastore Syncer/cache layer/server.")

	t.maybeStartLeaderElection(cxt)

	if t.ConfigParams.DebugPort != 0 {
		debugserver.StartDebugPprofServer(t.ConfigParams.DebugHost, t.ConfigParams.DebugPort)
	}
	if t.ConfigParams.PrometheusMetricsEnabled {
		log.Info("Prometheus metrics enabled.")
		t.configurePrometheusMetrics()
		if t.ConfigParams.PrometheusMetricsKeyFile != "" || t.ConfigParams.PrometheusMetricsCertFile != "" {
			log.Info("Trying to start metrics https server.")
			go func() {
				err := metricsserver.ServePrometheusMetricsHTTPS(
					prometheus.DefaultGatherer,
					t.ConfigParams.PrometheusMetricsHost,
					t.ConfigParams.PrometheusMetricsPort,
					t.ConfigParams.PrometheusMetricsCertFile,
					t.ConfigParams.PrometheusMetricsKeyFile,
					t.ConfigParams.PrometheusMetricsClientAuth,
					t.ConfigParams.PrometheusMetricsCAFile,
				)
				if err != nil {
					log.Info("Error starting metrics https server.", err)
				}
			}()
		} else {
			log.Info("Starting metrics http server.")
			go metricsserver.ServePrometheusMetricsHTTP(
				prometheus.DefaultGatherer,
				t.ConfigParams.PrometheusMetricsHost,
				t.ConfigParams.PrometheusMetricsPort,
			)
		}
	}

	if t.ConfigParams.HealthEnabled {
		log.WithFields(log.Fields{
			"host": t.ConfigParams.HealthHost,
			"port": t.ConfigParams.HealthPort,
		}).Info("Health enabled.  Starting server.")
		t.healthAggregator.ServeHTTP(t.ConfigParams.HealthEnabled, t.ConfigParams.HealthHost, t.ConfigParams.HealthPort)
	}
}

// maybeStartLeaderElection starts the Kubernetes Lease-based leader election
// subsystem when LeaderElectionEnabled is true (and the datastore is
// kubernetes).  The elector is stored on the daemon (Elector field) and run on
// its own cancellable context so graceful shutdown can release the lease before
// draining clients.
//
// In role-managed mode (election-driven hierarchy) this also constructs and runs
// the role manager, which consumes the elector's Roles() channel to promote and
// demote the syncer pipelines.  Outside role-managed mode the election result is
// inert: we just log transitions (WS-B behaviour preserved for the static cases).
func (t *TyphaDaemon) maybeStartLeaderElection(ctx context.Context) {
	if !t.ConfigParams.LeaderElectionEnabled {
		return
	}
	if t.ConfigParams.DatastoreType != "kubernetes" {
		log.Warn("LeaderElectionEnabled=true but DatastoreType is not kubernetes; skipping leader election")
		return
	}

	// Build the k8s clientset directly (separate from the connection-rebalancing
	// k8sAPI to keep Start() changes minimal).
	k8sAPI := k8s.NewK8sAPI(t.nodeCounter)
	cs, err := k8sAPI.Clientset()
	if err != nil {
		log.WithError(err).Error("Leader election: failed to build Kubernetes clientset; election disabled")
		return
	}

	leaseNS := t.ConfigParams.LeaseNamespace
	if leaseNS == "" {
		leaseNS = t.ConfigParams.PodNamespace
	}

	elCfg := leaderelection.Config{
		Enabled:        true,
		LeaseName:      t.ConfigParams.LeaseName,
		LeaseNamespace: leaseNS,
		Identity:       t.ConfigParams.PodName,
		LeaseDuration:  t.ConfigParams.LeaderElectionDuration,
		RenewDeadline:  t.ConfigParams.LeaderRenewDeadline,
		RetryPeriod:    t.ConfigParams.LeaderRetryPeriod,
	}
	elector := leaderelection.New(cs, elCfg, t.ConfigParams.PodName, t.ConfigParams.PodNamespace)
	if elector == nil {
		return
	}
	t.Elector = elector

	// Register a health reporter so the health aggregator knows the elector is alive.
	t.healthAggregator.RegisterReporter("LeaderElection", &health.HealthReport{Live: true}, 0)
	t.healthAggregator.Report("LeaderElection", &health.HealthReport{Live: true})

	// Run the elector on its own context so we can release the lease early during
	// graceful shutdown (cancel electorCancel before draining clients).
	electorCtx, electorCancel := context.WithCancel(ctx)
	t.electorCancel = electorCancel
	go elector.Run(electorCtx)

	if t.roleManaged {
		t.startRoleManager(ctx, cs, elector)
	} else {
		// Election result is inert in the static cases; just log transitions.
		go func() {
			for {
				select {
				case role := <-elector.Roles():
					log.WithField("role", role).Info("Leader election role transition")
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}

// startRoleManager builds the role manager from the daemon's pipelines and runs
// it on the given context.  The role manager owns the source lifecycle in
// role-managed mode.
func (t *TyphaDaemon) startRoleManager(ctx context.Context, cs kubernetes.Interface, elector *leaderelection.Elector) {
	pipelines := make([]*rolemanager.Pipeline, 0, len(t.SyncerPipelines))
	for _, p := range t.SyncerPipelines {
		p := p
		pipelines = append(pipelines, &rolemanager.Pipeline{
			Name:               string(p.Type),
			Buffer:             p.DedupeBuffer,
			NewDatastoreSource: p.NewDatastoreSource,
			NewUpstreamSource:  p.NewUpstreamSource,
		})
	}

	labeller := k8s.NewPodLabeller(cs, t.ConfigParams.PodNamespace, t.ConfigParams.PodName)

	t.RoleManager = rolemanager.New(
		rolemanager.Config{Debounce: t.ConfigParams.RoleTransitionDebounce},
		elector,
		labeller,
		pipelines,
	)
	log.Info("Starting role manager (election-driven hierarchical mode).")
	go t.RoleManager.Run(ctx)
}

func (t *TyphaDaemon) configurePrometheusMetrics() {
	if t.ConfigParams.PrometheusGoMetricsEnabled && t.ConfigParams.PrometheusProcessMetricsEnabled {
		log.Info("Including Golang & Process metrics")
	} else {
		if !t.ConfigParams.PrometheusGoMetricsEnabled {
			log.Info("Discarding Golang metrics")
			prometheus.Unregister(collectors.NewGoCollector())
		}
		if !t.ConfigParams.PrometheusProcessMetricsEnabled {
			log.Info("Discarding process metrics")
			prometheus.Unregister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		}
	}
}

// WaitAndShutDown waits for OS signals or context.Done() and exits as appropriate.
func (t *TyphaDaemon) WaitAndShutDown(cxt context.Context) {
	// Hook and process the signals we care about
	usr1SignalChan := make(chan os.Signal, 1)
	signal.Notify(usr1SignalChan, syscall.SIGUSR1)
	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGTERM)
	serverFinished := make(chan struct{})
	go func() {
		defer close(serverFinished)
		t.Server.Finished.Wait()
	}()
	for {
		select {
		case <-termChan:
			log.Warn("Received SIGTERM, shutting down")
			// Graceful shutdown ordering: if we are (or might be) the leader,
			// release the lease and drop our leader label *first*, so followers
			// fail over to a new leader early, before we start draining clients.
			// Cancelling the elector context triggers ReleaseOnCancel; the role
			// manager (which shares the parent context) removes the leader label
			// when its context is cancelled, but we also proactively remove it
			// here to shorten the window.
			t.releaseLeadershipForShutdown()
			t.Server.ShutDownGracefully()
		case <-usr1SignalChan:
			log.Info("Received SIGUSR1, emitting heap profile")
			dumpHeapMemoryProfile(t.ConfigParams)
		case <-cxt.Done():
			log.Info("Context asked us to stop.")
			return
		case <-serverFinished:
			log.Fatal("Server has shut down.")
		}
	}
}

// releaseLeadershipForShutdown releases the leader lease (via ReleaseOnCancel)
// at the start of graceful shutdown so a follower can take over before we begin
// draining client connections.  Safe to call when election is disabled.
func (t *TyphaDaemon) releaseLeadershipForShutdown() {
	if t.electorCancel == nil {
		return
	}
	log.Info("Releasing leader lease before draining client connections.")
	t.electorCancel()
}

// ClientV3Shim wraps a real client, allowing its syncer to be mocked.
type ClientV3Shim struct {
	RealClientV3
	config apiconfig.CalicoAPIConfig
}

func (s ClientV3Shim) FelixSyncerByIface(callbacks bapi.SyncerCallbacks) bapi.Syncer {
	return felixsyncer.New(s.Backend(), s.config.Spec, callbacks, true)
}

func (s ClientV3Shim) BGPSyncerByIface(callbacks bapi.SyncerCallbacks) bapi.Syncer {
	return bgpsyncer.New(s.Backend(), callbacks, "", s.config.Spec)
}

func (s ClientV3Shim) TunnelIPAllocationSyncerByIface(callbacks bapi.SyncerCallbacks) bapi.Syncer {
	return tunnelipsyncer.New(s.Backend(), callbacks, "")
}

func (s ClientV3Shim) NodeStatusSyncerByIface(callbacks bapi.SyncerCallbacks) bapi.Syncer {
	return nodestatussyncer.New(s.Backend(), callbacks)
}

// DatastoreClient is our interface to the datastore, used for mocking in the UTs.
type DatastoreClient interface {
	clientv3.Interface
	FelixSyncerByIface(callbacks bapi.SyncerCallbacks) bapi.Syncer
	BGPSyncerByIface(callbacks bapi.SyncerCallbacks) bapi.Syncer
	TunnelIPAllocationSyncerByIface(callbacks bapi.SyncerCallbacks) bapi.Syncer
	NodeStatusSyncerByIface(callbacks bapi.SyncerCallbacks) bapi.Syncer
}

// RealClientV3 is the real API of the V3 client, including the semi-private API that we use to get the backend.
type RealClientV3 interface {
	clientv3.Interface
	Backend() bapi.Client
}

// TODO Typha: Share with Felix.
func dumpHeapMemoryProfile(configParams *config.Config) {
	// If a memory profile file name is configured, dump a heap memory profile.  If the
	// configured filename includes "<timestamp>", that will be replaced with a stamp indicating
	// the current time.
	memProfFileName := configParams.DebugMemoryProfilePath
	if memProfFileName != "" {
		logCxt := log.WithField("file", memProfFileName)
		logCxt.Info("Asked to create a memory profile.")

		// If the configured file name includes "<timestamp>", replace that with the current
		// time.
		if strings.Contains(memProfFileName, "<timestamp>") {
			timestamp := time.Now().Format("2006-01-02-15:04:05")
			memProfFileName = strings.Replace(memProfFileName, "<timestamp>", timestamp, 1)
			logCxt = log.WithField("file", memProfFileName)
		}

		// Open a file with that name.
		memProfFile, err := os.Create(memProfFileName)
		if err != nil {
			logCxt.WithError(err).Fatal("Could not create memory profile file")
			memProfFile = nil
		} else {
			defer func() {
				err := memProfFile.Close()
				if err != nil {
					log.WithError(err).Error("Error while closing memory profile file.")
				}
			}()
			logCxt.Info("Writing memory profile...")
			// The initial resync uses a lot of scratch space so now is
			// a good time to force a GC and return any RAM that we can.
			debug.FreeOSMemory()
			if err := pprof.WriteHeapProfile(memProfFile); err != nil {
				logCxt.WithError(err).Error("Could not write memory profile")
			}
			logCxt.Info("Finished writing memory profile")
		}
	}
}
