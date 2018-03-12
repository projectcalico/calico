// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
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

package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/felix/binder"
	"github.com/projectcalico/felix/buildinfo"
	"github.com/projectcalico/felix/calc"
	"github.com/projectcalico/felix/config"
	_ "github.com/projectcalico/felix/config"
	dp "github.com/projectcalico/felix/dataplane"
	"github.com/projectcalico/felix/logutils"
	"github.com/projectcalico/felix/policysync"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/statusrep"
	"github.com/projectcalico/felix/usagerep"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/felixsyncer"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
	errors2 "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/health"
	"github.com/projectcalico/libcalico-go/lib/set"
	"github.com/projectcalico/typha/pkg/syncclient"
)

const usage = `Felix, the Calico per-host daemon.

Usage:
  calico-felix [options]

Options:
  -c --config-file=<filename>  Config file to load [default: /etc/calico/felix.cfg].
  --version                    Print the version and exit.
`

const (
	// Our default value for GOGC if it is not set.  This is the percentage that heap usage must
	// grow by to trigger a garbage collection.  Go's default is 100, meaning that 50% of the
	// heap can be lost to garbage.  We reduce it to this value to trade increased CPU usage for
	// lower occupancy.
	defaultGCPercent = 20

	// String sent on the failure report channel to indicate we're shutting down for config
	// change.
	reasonConfigChanged = "config changed"
	// Process return code used to report a config change.  This is the same as the code used
	// by SIGHUP, which means that the wrapper script also restarts Felix on a SIGHUP.
	configChangedRC = 129
)

// main is the entry point to the calico-felix binary.
//
// Its main role is to sequence Felix's startup by:
//
// Initialising early logging config (log format and early debug settings).
//
// Parsing command line parameters.
//
// Loading datastore configuration from the environment or config file.
//
// Loading more configuration from the datastore (this is retried until success).
//
// Starting the configured internal (golang) or external dataplane driver.
//
// Starting the background processing goroutines, which load and keep in sync with the
// state from the datastore, the "calculation graph".
//
// Starting the usage reporting and prometheus metrics endpoint threads (if configured).
//
// Then, it defers to monitorAndManageShutdown(), which blocks until one of the components
// fails, then attempts a graceful shutdown.  At that point, all the processing is in
// background goroutines.
//
// To avoid having to maintain rarely-used code paths, Felix handles updates to its
// main config parameters by exiting and allowing itself to be restarted by the init
// daemon.
func main() {
	// Go's RNG is not seeded by default.  Do that now.
	rand.Seed(time.Now().UTC().UnixNano())

	// Special-case handling for environment variable-configured logging:
	// Initialise early so we can trace out config parsing.
	logutils.ConfigureEarlyLogging()

	ctx := context.Background()

	if os.Getenv("GOGC") == "" {
		// Tune the GC to trade off a little extra CPU usage for significantly lower
		// occupancy at high scale.  This is worthwhile because Felix runs per-host so
		// any occupancy improvement is multiplied by the number of hosts.
		log.Debugf("No GOGC value set, defaulting to %d%%.", defaultGCPercent)
		debug.SetGCPercent(defaultGCPercent)
	}

	// Parse command-line args.
	version := "Version:            " + buildinfo.GitVersion + "\n" +
		"Full git commit ID: " + buildinfo.GitRevision + "\n" +
		"Build date:         " + buildinfo.BuildDate + "\n"
	arguments, err := docopt.Parse(usage, nil, true, version, false)
	if err != nil {
		println(usage)
		log.Fatalf("Failed to parse usage, exiting: %v", err)
	}
	buildInfoLogCxt := log.WithFields(log.Fields{
		"version":    buildinfo.GitVersion,
		"buildDate":  buildinfo.BuildDate,
		"gitCommit":  buildinfo.GitRevision,
		"GOMAXPROCS": runtime.GOMAXPROCS(0),
	})
	buildInfoLogCxt.Info("Felix starting up")
	log.Infof("Command line arguments: %v", arguments)

	// Health monitoring, for liveness and readiness endpoints.  The following loop can take a
	// while before the datastore reports itself as ready - for example when there is data that
	// needs to be migrated from a previous version - and we still want to Felix to report
	// itself as live (but not ready) while we are waiting for that.  So we create the
	// aggregator upfront and will start serving health status over HTTP as soon as we see _any_
	// config that indicates that.
	healthAggregator := health.NewHealthAggregator()

	const healthName = "felix-startup"

	// Register this function as a reporter of liveness and readiness, with no timeout.
	healthAggregator.RegisterReporter(healthName, &health.HealthReport{Live: true, Ready: true}, 0)

	// Load the configuration from all the different sources including the
	// datastore and merge. Keep retrying on failure.  We'll sit in this
	// loop until the datastore is ready.
	log.Infof("Loading configuration...")
	var backendClient bapi.Client
	var configParams *config.Config
	var typhaAddr string
	var numClientsCreated int
configRetry:
	for {
		if numClientsCreated > 60 {
			// If we're in a restart loop, periodically exit (so we can be restarted) since
			// - it may solve the problem if there's something wrong with our process
			// - it prevents us from leaking connections to the datastore.
			exitWithCustomRC(configChangedRC, "Restarting to avoid leaking datastore connections")
		}

		// Make an initial report that says we're live but not yet ready.
		healthAggregator.Report(healthName, &health.HealthReport{Live: true, Ready: false})

		// Load locally-defined config, including the datastore connection
		// parameters. First the environment variables.
		configParams = config.New()
		envConfig := config.LoadConfigFromEnvironment(os.Environ())
		// Then, the config file.
		configFile := arguments["--config-file"].(string)
		fileConfig, err := config.LoadConfigFile(configFile)
		if err != nil {
			log.WithError(err).WithField("configFile", configFile).Error(
				"Failed to load configuration file")
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		// Parse and merge the local config.
		configParams.UpdateFrom(envConfig, config.EnvironmentVariable)
		if configParams.Err != nil {
			log.WithError(configParams.Err).WithField("configFile", configFile).Error(
				"Failed to parse configuration environment variable")
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		configParams.UpdateFrom(fileConfig, config.ConfigFile)
		if configParams.Err != nil {
			log.WithError(configParams.Err).WithField("configFile", configFile).Error(
				"Failed to parse configuration file")
			time.Sleep(1 * time.Second)
			continue configRetry
		}

		// Each time round this loop, check that we're serving health reports if we should
		// be, or cancel any existing server if we should not be serving any more.
		healthAggregator.ServeHTTP(configParams.HealthEnabled, configParams.HealthPort)

		// We should now have enough config to connect to the datastore
		// so we can load the remainder of the config.
		datastoreConfig := configParams.DatastoreConfig()
		backendClient, err = backend.NewClient(datastoreConfig)
		if err != nil {
			log.WithError(err).Error("Failed to create datastore client")
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		numClientsCreated++
		for {
			globalConfig, hostConfig, err := loadConfigFromDatastore(
				ctx, backendClient, configParams.FelixHostname)
			if err == ErrNotReady {
				log.Warn("Waiting for datastore to be initialized (or migrated)")
				time.Sleep(1 * time.Second)
				healthAggregator.Report(healthName, &health.HealthReport{Live: true, Ready: true})
				continue
			} else if err != nil {
				log.WithError(err).Error("Failed to get config from datastore")
				time.Sleep(1 * time.Second)
				continue configRetry
			}
			configParams.UpdateFrom(globalConfig, config.DatastoreGlobal)
			configParams.UpdateFrom(hostConfig, config.DatastorePerHost)
			break
		}
		configParams.Validate()
		if configParams.Err != nil {
			log.WithError(configParams.Err).Error(
				"Failed to parse/validate configuration from datastore.")
			time.Sleep(1 * time.Second)
			continue configRetry
		}

		// We now have some config flags that affect how we configure the syncer.
		// After loading the config from the datastore, reconnect, possibly with new
		// config.  We don't need to re-load the configuration _again_ because the
		// calculation graph will spot if the config has changed since we were initialised.
		datastoreConfig = configParams.DatastoreConfig()
		backendClient, err = backend.NewClient(datastoreConfig)
		if err != nil {
			log.WithError(err).Error("Failed to (re)connect to datastore")
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		numClientsCreated++

		// If we're configured to discover Typha, do that now so we can retry if we fail.
		typhaAddr, err = discoverTyphaAddr(configParams)
		if err != nil {
			log.WithError(err).Error("Typha discovery enabled but discovery failed.")
			time.Sleep(1 * time.Second)
			continue configRetry
		}

		break configRetry
	}

	if numClientsCreated > 2 {
		// We don't have a way to close datastore connection so, if we reconnected after
		// a failure to load config, restart felix to avoid leaking connections.
		exitWithCustomRC(configChangedRC, "Restarting to avoid leaking datastore connections")
	}

	// We're now both live and ready.
	healthAggregator.Report(healthName, &health.HealthReport{Live: true, Ready: true})

	// Enable or disable the health HTTP server according to coalesced config.
	healthAggregator.ServeHTTP(configParams.HealthEnabled, configParams.HealthPort)

	// If we get here, we've loaded the configuration successfully.
	// Update log levels before we do anything else.
	logutils.ConfigureLogging(configParams)
	// Since we may have enabled more logging, log with the build context
	// again.
	buildInfoLogCxt.WithField("config", configParams).Info(
		"Successfully loaded configuration.")

	// Start up the dataplane driver.  This may be the internal go-based driver or an external
	// one.
	var dpDriver dp.DataplaneDriver
	var dpDriverCmd *exec.Cmd

	failureReportChan := make(chan string)
	configChangedRestartCallback := func() { failureReportChan <- reasonConfigChanged }

	dpDriver, dpDriverCmd = dp.StartDataplaneDriver(configParams, healthAggregator, configChangedRestartCallback)

	// Initialise the glue logic that connects the calculation graph to/from the dataplane driver.
	log.Info("Connect to the dataplane driver.")

	var connToUsageRepUpdChan chan map[string]string
	if configParams.UsageReportingEnabled {
		// Make a channel for the connector to use to send updates to the usage reporter.
		// (Otherwise, we pass in a nil channel, which disables such updates.)
		connToUsageRepUpdChan = make(chan map[string]string, 1)
	}
	dpConnector := newConnector(configParams, connToUsageRepUpdChan, backendClient, dpDriver, failureReportChan)

	// If enabled, create a server for the policy sync API.  This allows clients to connect to
	// Felix over a socket and receive policy updates.
	var policySyncServer *policysync.Server
	var policySyncProcessor *policysync.Processor
	var policySyncAPIBinder binder.Binder
	calcGraphClientChannels := []chan<- interface{}{dpConnector.ToDataplane}
	if configParams.PolicySyncPathPrefix != "" {
		log.WithField("policySyncPathPrefix", configParams.PolicySyncPathPrefix).Info(
			"Policy sync API enabled.  Creating the policy sync server.")
		toPolicySync := make(chan interface{})
		policySyncUIDAllocator := policysync.NewUIDAllocator()
		policySyncProcessor = policysync.NewProcessor(toPolicySync)
		policySyncServer = policysync.NewServer(
			policySyncProcessor.JoinUpdates,
			policySyncUIDAllocator.NextUID,
		)
		policySyncAPIBinder = binder.NewBinder(configParams.PolicySyncPathPrefix)
		policySyncServer.RegisterGrpc(policySyncAPIBinder.Server())
		calcGraphClientChannels = append(calcGraphClientChannels, toPolicySync)
	}

	// Now create the calculation graph, which receives updates from the
	// datastore and outputs dataplane updates for the dataplane driver.
	//
	// The Syncer has its own thread and we use an extra thread for the
	// Validator, just to pipeline that part of the calculation then the
	// main calculation graph runs in a single thread for simplicity.
	// The output of the calculation graph arrives at the dataplane
	// connection via channel.
	//
	// Syncer -chan-> Validator -chan-> Calc graph -chan->   dataplane
	//        KVPair            KVPair             protobufs

	// Get a Syncer from the datastore, or a connection to our remote sync daemon, Typha,
	// which will feed the calculation graph with updates, bringing Felix into sync.
	var syncer Startable
	var typhaConnection *syncclient.SyncerClient
	syncerToValidator := calc.NewSyncerCallbacksDecoupler()
	if typhaAddr != "" {
		// Use a remote Syncer, via the Typha server.
		log.WithField("addr", typhaAddr).Info("Connecting to Typha.")
		typhaConnection = syncclient.New(
			typhaAddr,
			buildinfo.GitVersion,
			configParams.FelixHostname,
			fmt.Sprintf("Revision: %s; Build date: %s",
				buildinfo.GitRevision, buildinfo.BuildDate),
			syncerToValidator,
			&syncclient.Options{
				ReadTimeout:  configParams.TyphaReadTimeout,
				WriteTimeout: configParams.TyphaWriteTimeout,
			},
		)
	} else {
		// Use the syncer locally.
		syncer = felixsyncer.New(backendClient, syncerToValidator)
	}
	log.WithField("syncer", syncer).Info("Created Syncer")

	// Create the ipsets/active policy calculation graph, which will
	// do the dynamic calculation of ipset memberships and active policies
	// etc.
	asyncCalcGraph := calc.NewAsyncCalcGraph(
		configParams,
		calcGraphClientChannels,
		healthAggregator,
	)

	if configParams.UsageReportingEnabled {
		// Usage reporting enabled, add stats collector to graph.  When it detects an update
		// to the stats, it makes a callback, which we use to send an update on a channel.
		// We use a buffered channel here to avoid blocking the calculation graph.
		statsChanIn := make(chan calc.StatsUpdate, 1)
		statsCollector := calc.NewStatsCollector(func(stats calc.StatsUpdate) error {
			statsChanIn <- stats
			return nil
		})
		statsCollector.RegisterWith(asyncCalcGraph.Dispatcher)

		// Rather than sending the updates directly to the usage reporting thread, we
		// decouple with an extra goroutine.  This prevents blocking the calculation graph
		// goroutine if the usage reporting goroutine is blocked on IO, for example.
		// Using a buffered channel wouldn't work here because the usage reporting
		// goroutine can block for a long time on IO so we could build up a long queue.
		statsChanOut := make(chan calc.StatsUpdate)
		go func() {
			var statsChanOutOrNil chan calc.StatsUpdate
			var stats calc.StatsUpdate
			for {
				select {
				case stats = <-statsChanIn:
					// Got a stats update, activate the output channel.
					log.WithField("stats", stats).Debug("Buffer: stats update received")
					statsChanOutOrNil = statsChanOut
				case statsChanOutOrNil <- stats:
					// Passed on the update, deactivate the output channel until
					// the next update.
					log.WithField("stats", stats).Debug("Buffer: stats update sent")
					statsChanOutOrNil = nil
				}
			}
		}()

		usageRep := usagerep.New(
			configParams.UsageReportingInitialDelaySecs,
			configParams.UsageReportingIntervalSecs,
			statsChanOut,
			connToUsageRepUpdChan,
		)
		go usageRep.PeriodicallyReportUsage(context.Background())
	} else {
		// Usage reporting disabled, but we still want a stats collector for the
		// felix_cluster_* metrics.  Register a no-op function as the callback.
		statsCollector := calc.NewStatsCollector(func(stats calc.StatsUpdate) error {
			return nil
		})
		statsCollector.RegisterWith(asyncCalcGraph.Dispatcher)
	}

	// Create the validator, which sits between the syncer and the
	// calculation graph.
	validator := calc.NewValidationFilter(asyncCalcGraph)

	// Start the background processing threads.
	if syncer != nil {
		log.Infof("Starting the datastore Syncer")
		syncer.Start()
	} else {
		log.Infof("Starting the Typha connection")
		err := typhaConnection.Start(context.Background())
		if err != nil {
			log.WithError(err).Fatal("Failed to connect to Typha")
		}
		go func() {
			typhaConnection.Finished.Wait()
			failureReportChan <- "Connection to Typha failed"
		}()
	}
	go syncerToValidator.SendTo(validator)
	asyncCalcGraph.Start()
	log.Infof("Started the processing graph")
	var stopSignalChans []chan<- bool
	if configParams.EndpointReportingEnabled {
		delay := configParams.EndpointReportingDelaySecs
		log.WithField("delay", delay).Info(
			"Endpoint status reporting enabled, starting status reporter")
		dpConnector.statusReporter = statusrep.NewEndpointStatusReporter(
			configParams.FelixHostname,
			dpConnector.StatusUpdatesFromDataplane,
			dpConnector.InSync,
			dpConnector.datastore,
			delay,
			delay*180,
		)
		dpConnector.statusReporter.Start()
	}

	// Start communicating with the dataplane driver.
	dpConnector.Start()

	if policySyncProcessor != nil {
		log.WithField("policySyncPathPrefix", configParams.PolicySyncPathPrefix).Info(
			"Policy sync API enabled.  Starting the policy sync server.")
		policySyncProcessor.Start()
		sc := make(chan bool)
		stopSignalChans = append(stopSignalChans, sc)
		go policySyncAPIBinder.SearchAndBind(sc)
	}

	// Send the opening message to the dataplane driver, giving it its
	// config.
	dpConnector.ToDataplane <- &proto.ConfigUpdate{
		Config: configParams.RawValues(),
	}

	if configParams.PrometheusMetricsEnabled {
		log.Info("Prometheus metrics enabled.  Starting server.")
		gaugeHost := prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        "felix_host",
			Help:        "Configured Felix hostname (as a label), typically used in grouping/aggregating stats; the label defaults to the hostname of the host but can be overridden by configuration. The value of the gauge is always set to 1.",
			ConstLabels: prometheus.Labels{"host": configParams.FelixHostname},
		})
		gaugeHost.Set(1)
		prometheus.MustRegister(gaugeHost)
		go servePrometheusMetrics(configParams)
	}

	// On receipt of SIGUSR1, write out heap profile.
	logutils.DumpHeapMemoryOnSignal(configParams)

	// Now monitor the worker process and our worker threads and shut
	// down the process gracefully if they fail.
	monitorAndManageShutdown(failureReportChan, dpDriverCmd, stopSignalChans)
}

func servePrometheusMetrics(configParams *config.Config) {
	for {
		log.WithField("port", configParams.PrometheusMetricsPort).Info("Starting prometheus metrics endpoint")
		if configParams.PrometheusGoMetricsEnabled && configParams.PrometheusProcessMetricsEnabled {
			log.Info("Including Golang & Process metrics")
		} else {
			if !configParams.PrometheusGoMetricsEnabled {
				log.Info("Discarding Golang metrics")
				prometheus.Unregister(prometheus.NewGoCollector())
			}
			if !configParams.PrometheusProcessMetricsEnabled {
				log.Info("Discarding process metrics")
				prometheus.Unregister(prometheus.NewProcessCollector(os.Getpid(), ""))
			}
		}
		http.Handle("/metrics", promhttp.Handler())
		err := http.ListenAndServe(fmt.Sprintf(":%v", configParams.PrometheusMetricsPort), nil)
		log.WithError(err).Error(
			"Prometheus metrics endpoint failed, trying to restart it...")
		time.Sleep(1 * time.Second)
	}
}

func monitorAndManageShutdown(failureReportChan <-chan string, driverCmd *exec.Cmd, stopSignalChans []chan<- bool) {
	// Ask the runtime to tell us if we get a term/int signal.
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM)
	signal.Notify(signalChan, syscall.SIGINT)
	signal.Notify(signalChan, syscall.SIGHUP)

	// Start a background thread to tell us when the dataplane driver stops.
	// If the driver stops unexpectedly, we'll terminate this process.
	// If this process needs to stop, we'll kill the driver and then wait
	// for the message from the background thread.
	driverStoppedC := make(chan bool)
	go func() {
		if driverCmd == nil {
			log.Info("No driver process to monitor")
			return
		}
		err := driverCmd.Wait()
		log.WithError(err).Warn("Driver process stopped")
		driverStoppedC <- true
	}()

	// Wait for one of the channels to give us a reason to shut down.
	driverAlreadyStopped := driverCmd == nil
	receivedFatalSignal := false
	var reason string
	select {
	case <-driverStoppedC:
		reason = "Driver stopped"
		driverAlreadyStopped = true
	case sig := <-signalChan:
		if sig == syscall.SIGHUP {
			log.Warning("Received a SIGHUP, treating as a request to reload config")
			reason = reasonConfigChanged
		} else {
			reason = fmt.Sprintf("Received OS signal %v", sig)
			receivedFatalSignal = true
		}
	case reason = <-failureReportChan:
	}
	logCxt := log.WithField("reason", reason)
	logCxt.Warn("Felix is shutting down")

	// Notify other components to stop.
	for _, c := range stopSignalChans {
		select {
		case c <- true:
		default:
		}
	}

	if !driverAlreadyStopped {
		// Driver may still be running, just in case the driver is
		// unresponsive, start a thread to kill this process if we
		// don't manage to kill the driver.
		logCxt.Info("Driver still running, trying to shut it down...")
		giveUpOnSigTerm := make(chan bool)
		go func() {
			time.Sleep(4 * time.Second)
			giveUpOnSigTerm <- true
			time.Sleep(1 * time.Second)
			log.Fatal("Failed to wait for driver to exit, giving up.")
		}()
		// Signal to the driver to exit.
		driverCmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-driverStoppedC:
			logCxt.Info("Driver shut down after SIGTERM")
		case <-giveUpOnSigTerm:
			logCxt.Error("Driver did not respond to SIGTERM, sending SIGKILL")
			driverCmd.Process.Kill()
			<-driverStoppedC
			logCxt.Info("Driver shut down after SIGKILL")
		}
	}

	if !receivedFatalSignal {
		// We're exiting due to a failure or a config change, wait
		// a couple of seconds to ensure that we don't go into a tight
		// restart loop (which would make the init daemon in calico/node give
		// up trying to restart us).
		logCxt.Info("Sleeping to avoid tight restart loop.")
		go func() {
			time.Sleep(2 * time.Second)

			if reason == reasonConfigChanged {
				exitWithCustomRC(configChangedRC, "Exiting for config change")
				return
			}

			logCxt.Fatal("Exiting.")
		}()

		for {
			sig := <-signalChan
			if sig == syscall.SIGHUP {
				logCxt.Warning("Ignoring SIGHUP because we're already shutting down")
				continue
			}
			logCxt.WithField("signal", sig).Fatal(
				"Signal received while shutting down, exiting immediately")
		}
	}

	logCxt.Fatal("Exiting immediately")
}

func exitWithCustomRC(rc int, message string) {
	// To ensure that the logs get flushed, we need to exit with Panic() or Fatal().
	// However, Fatal() doesn't let us set a custom RC.  To work around that, we create a panic,
	// but then intercept it and exit with the desired RC.
	log.WithField("rc", rc).Info("Exiting with custom RC")
	defer os.Exit(rc)
	log.Panic(message)
	panic(message) // defensive.
}

var (
	ErrNotReady = errors.New("datastore is not ready or has not been initialised")
)

func loadConfigFromDatastore(
	ctx context.Context, client bapi.Client, hostname string,
) (globalConfig, hostConfig map[string]string, err error) {

	// The configuration is split over 3 different resource types and 4 different resource
	// instances in the v3 data model:
	// -  ClusterInformation (global): name "default"
	// -  FelixConfiguration (global): name "default"
	// -  FelixConfiguration (per-host): name "node.<hostname>"
	// -  Node (per-host): name: <hostname>
	// Get the global values and host specific values separately.  We re-use the updateprocessor
	// logic to convert the single v3 resource to a set of v1 key/values.
	hostConfig = make(map[string]string)
	globalConfig = make(map[string]string)
	var ready bool
	err = getAndMergeConfig(
		ctx, client, globalConfig,
		apiv3.KindClusterInformation, "default",
		updateprocessors.NewClusterInfoUpdateProcessor(),
		&ready,
	)
	if err != nil {
		return
	}
	if !ready {
		// The ClusterInformation struct should contain the ready flag, if it is not set, abort.
		err = ErrNotReady
		return
	}
	err = getAndMergeConfig(
		ctx, client, globalConfig,
		apiv3.KindFelixConfiguration, "default",
		updateprocessors.NewFelixConfigUpdateProcessor(),
		&ready,
	)
	if err != nil {
		return
	}
	err = getAndMergeConfig(
		ctx, client, hostConfig,
		apiv3.KindFelixConfiguration, "node."+hostname,
		updateprocessors.NewFelixConfigUpdateProcessor(),
		&ready,
	)
	if err != nil {
		return
	}
	err = getAndMergeConfig(
		ctx, client, hostConfig,
		apiv3.KindNode, hostname,
		updateprocessors.NewFelixNodeUpdateProcessor(),
		&ready,
	)
	if err != nil {
		return
	}

	return
}

// getAndMergeConfig gets the v3 resource configuration extracts the separate config values
// (where each configuration value is stored in a field of the v3 resource Spec) and merges into
// the supplied map, as required by our v1-style configuration loader.
func getAndMergeConfig(
	ctx context.Context, client bapi.Client, config map[string]string,
	kind string, name string,
	configConverter watchersyncer.SyncerUpdateProcessor,
	ready *bool,
) error {
	logCxt := log.WithFields(log.Fields{"kind": kind, "name": name})

	cfg, err := client.Get(ctx, model.ResourceKey{
		Kind:      kind,
		Name:      name,
		Namespace: "",
	}, "")
	if err != nil {
		switch err.(type) {
		case errors2.ErrorResourceDoesNotExist:
			logCxt.Info("No config of this type")
			return nil
		default:
			logCxt.WithError(err).Info("Failed to load config from datastore")
			return err
		}
	}

	// Re-use the update processor logic implemented for the Syncer.  We give it a v3 config
	// object in a KVPair and it uses the annotations defined on it to split it into v1-style
	// KV pairs.  Log any errors - but don't fail completely to avoid cyclic restarts.
	v1kvs, err := configConverter.Process(cfg)
	if err != nil {
		logCxt.WithError(err).Error("Failed to convert configuration")
	}

	// Loop through the converted values and update our config map with values from either the
	// Global or Host configs.
	for _, v1KV := range v1kvs {
		if _, ok := v1KV.Key.(model.ReadyFlagKey); ok {
			logCxt.WithField("ready", v1KV.Value).Info("Loaded ready flag")
			if v1KV.Value == true {
				*ready = true
			}
		} else if v1KV.Value != nil {
			switch k := v1KV.Key.(type) {
			case model.GlobalConfigKey:
				config[k.Name] = v1KV.Value.(string)
			case model.HostConfigKey:
				config[k.Name] = v1KV.Value.(string)
			default:
				logCxt.WithField("KV", v1KV).Debug("Skipping config - not required for initial loading")
			}
		}
	}
	return nil
}

type DataplaneConnector struct {
	config                     *config.Config
	configUpdChan              chan<- map[string]string
	ToDataplane                chan interface{}
	StatusUpdatesFromDataplane chan interface{}
	InSync                     chan bool
	failureReportChan          chan<- string
	dataplane                  dp.DataplaneDriver
	datastore                  bapi.Client
	statusReporter             *statusrep.EndpointStatusReporter

	datastoreInSync bool

	firstStatusReportSent bool
}

type Startable interface {
	Start()
}

func newConnector(configParams *config.Config,
	configUpdChan chan<- map[string]string,
	datastore bapi.Client,
	dataplane dp.DataplaneDriver,
	failureReportChan chan<- string,
) *DataplaneConnector {
	felixConn := &DataplaneConnector{
		config:                     configParams,
		configUpdChan:              configUpdChan,
		datastore:                  datastore,
		ToDataplane:                make(chan interface{}),
		StatusUpdatesFromDataplane: make(chan interface{}),
		InSync:            make(chan bool, 1),
		failureReportChan: failureReportChan,
		dataplane:         dataplane,
	}
	return felixConn
}

func (fc *DataplaneConnector) readMessagesFromDataplane() {
	defer func() {
		fc.shutDownProcess("Failed to read messages from dataplane")
	}()
	log.Info("Reading from dataplane driver pipe...")
	ctx := context.Background()
	for {
		payload, err := fc.dataplane.RecvMessage()
		if err != nil {
			log.WithError(err).Error("Failed to read from front-end socket")
			fc.shutDownProcess("Failed to read from front-end socket")
		}
		log.WithField("payload", payload).Debug("New message from dataplane")
		switch msg := payload.(type) {
		case *proto.ProcessStatusUpdate:
			fc.handleProcessStatusUpdate(ctx, msg)
		case *proto.WorkloadEndpointStatusUpdate:
			if fc.statusReporter != nil {
				fc.StatusUpdatesFromDataplane <- msg
			}
		case *proto.WorkloadEndpointStatusRemove:
			if fc.statusReporter != nil {
				fc.StatusUpdatesFromDataplane <- msg
			}
		case *proto.HostEndpointStatusUpdate:
			if fc.statusReporter != nil {
				fc.StatusUpdatesFromDataplane <- msg
			}
		case *proto.HostEndpointStatusRemove:
			if fc.statusReporter != nil {
				fc.StatusUpdatesFromDataplane <- msg
			}
		default:
			log.WithField("msg", msg).Warning("Unknown message from dataplane")
		}
		log.Debug("Finished handling message from front-end")
	}
}

func (fc *DataplaneConnector) handleProcessStatusUpdate(ctx context.Context, msg *proto.ProcessStatusUpdate) {
	log.Debugf("Status update from dataplane driver: %v", *msg)
	statusReport := model.StatusReport{
		Timestamp:     msg.IsoTimestamp,
		UptimeSeconds: msg.Uptime,
		FirstUpdate:   !fc.firstStatusReportSent,
	}
	kv := model.KVPair{
		Key:   model.ActiveStatusReportKey{Hostname: fc.config.FelixHostname},
		Value: &statusReport,
		TTL:   fc.config.ReportingTTLSecs,
	}
	applyCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	_, err := fc.datastore.Apply(applyCtx, &kv)
	cancel()
	if err != nil {
		log.Warningf("Failed to write status to datastore: %v", err)
	} else {
		fc.firstStatusReportSent = true
	}
	kv = model.KVPair{
		Key:   model.LastStatusReportKey{Hostname: fc.config.FelixHostname},
		Value: &statusReport,
	}
	applyCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
	_, err = fc.datastore.Apply(applyCtx, &kv)
	cancel()
	if err != nil {
		log.Warningf("Failed to write status to datastore: %v", err)
	}
}

var handledConfigChanges = set.From("CalicoVersion", "ClusterGUID", "ClusterType")

func (fc *DataplaneConnector) sendMessagesToDataplaneDriver() {
	defer func() {
		fc.shutDownProcess("Failed to send messages to dataplane")
	}()

	var config map[string]string
	for {
		msg := <-fc.ToDataplane
		switch msg := msg.(type) {
		case *proto.InSync:
			log.Info("Datastore now in sync.")
			if !fc.datastoreInSync {
				log.Info("Datastore in sync for first time, sending message to status reporter.")
				fc.datastoreInSync = true
				fc.InSync <- true
			}
		case *proto.ConfigUpdate:
			if config != nil {
				log.WithFields(log.Fields{
					"old": config,
					"new": msg.Config,
				}).Info("Config updated, checking whether we need to restart")
				restartNeeded := false
				for kNew, vNew := range msg.Config {
					logCxt := log.WithFields(log.Fields{"key": kNew, "new": vNew})
					if vOld, prs := config[kNew]; !prs {
						logCxt = logCxt.WithField("updateType", "add")
					} else if vNew != vOld {
						logCxt = logCxt.WithFields(log.Fields{"old": vOld, "updateType": "update"})
					} else {
						continue
					}
					if handledConfigChanges.Contains(kNew) {
						logCxt.Info("Config change can be handled without restart")
						continue
					}
					logCxt.Warning("Config change requires restart")
					restartNeeded = true
				}
				for kOld, vOld := range config {
					logCxt := log.WithFields(log.Fields{"key": kOld, "old": vOld, "updateType": "delete"})
					if _, prs := msg.Config[kOld]; prs {
						// Key was present in the message so we've handled above.
						continue
					}
					if handledConfigChanges.Contains(kOld) {
						logCxt.Info("Config change can be handled without restart")
						continue
					}
					logCxt.Warning("Config change requires restart")
					restartNeeded = true
				}

				if restartNeeded {
					fc.shutDownProcess("config changed")
				}
			}

			// Take a copy of the config to compare against next time.
			config = make(map[string]string)
			for k, v := range msg.Config {
				config[k] = v
			}

			if fc.configUpdChan != nil {
				// Send the config over to the usage reporter.
				fc.configUpdChan <- config
			}
		case *calc.DatastoreNotReady:
			log.Warn("Datastore became unready, need to restart.")
			fc.shutDownProcess("datastore became unready")
		}
		if err := fc.dataplane.SendMessage(msg); err != nil {
			fc.shutDownProcess("Failed to write to dataplane driver")
		}
	}
}

func (fc *DataplaneConnector) shutDownProcess(reason string) {
	// Send a failure report to the managed shutdown thread then give it
	// a few seconds to do the shutdown.
	fc.failureReportChan <- reason
	time.Sleep(5 * time.Second)
	// The graceful shutdown failed, terminate the process.
	log.Panic("Managed shutdown failed. Panicking.")
}

func (fc *DataplaneConnector) Start() {
	// Start a background thread to write to the dataplane driver.
	go fc.sendMessagesToDataplaneDriver()

	// Start background thread to read messages from dataplane driver.
	go fc.readMessagesFromDataplane()
}

var ErrServiceNotReady = errors.New("Kubernetes service missing IP or port.")

func discoverTyphaAddr(configParams *config.Config) (string, error) {
	if configParams.TyphaAddr != "" {
		// Explicit address; trumps other sources of config.
		return configParams.TyphaAddr, nil
	}

	if configParams.TyphaK8sServiceName == "" {
		// No explicit address, and no service name, not using Typha.
		return "", nil
	}

	// If we get here, we need to look up the Typha service using the k8s API.
	// TODO Typha: support Typha lookup without using rest.InClusterConfig().
	k8sconf, err := rest.InClusterConfig()
	if err != nil {
		log.WithError(err).Error("Unable to create Kubernetes config.")
		return "", err
	}
	clientset, err := kubernetes.NewForConfig(k8sconf)
	if err != nil {
		log.WithError(err).Error("Unable to create Kubernetes client set.")
		return "", err
	}
	svcClient := clientset.CoreV1().Services(configParams.TyphaK8sNamespace)
	svc, err := svcClient.Get(configParams.TyphaK8sServiceName, v1.GetOptions{})
	if err != nil {
		log.WithError(err).Error("Unable to get Typha service from Kubernetes.")
		return "", err
	}
	host := svc.Spec.ClusterIP
	log.WithField("clusterIP", host).Info("Found Typha ClusterIP.")
	if host == "" {
		log.WithError(err).Error("Typha service had no ClusterIP.")
		return "", ErrServiceNotReady
	}
	for _, p := range svc.Spec.Ports {
		if p.Name == "calico-typha" {
			log.WithField("port", p).Info("Found Typha service port.")
			typhaAddr := fmt.Sprintf("%s:%v", host, p.Port)
			return typhaAddr, nil
		}
	}
	log.Error("Didn't find Typha service port.")
	return "", ErrServiceNotReady
}
