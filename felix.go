// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/docopt/docopt-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/projectcalico/felix/buildinfo"
	"github.com/projectcalico/felix/calc"
	"github.com/projectcalico/felix/config"
	_ "github.com/projectcalico/felix/config"
	"github.com/projectcalico/felix/extdataplane"
	"github.com/projectcalico/felix/intdataplane"
	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/logutils"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/rules"
	"github.com/projectcalico/felix/statusrep"
	"github.com/projectcalico/felix/usagerep"
	"github.com/projectcalico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

const usage = `Felix, the Calico per-host daemon.

Usage:
  calico-felix [-c <config>]

Options:
  -c --config-file=<config>  Config file to load [default: /etc/calico/felix.cfg].
  --version                  Print the version and exit.
`

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
	// Special-case handling for environment variable-configured logging:
	// Initialise early so we can trace out config parsing.
	logutils.ConfigureEarlyLogging()

	// Parse command-line args.
	version := ("Version:            " + buildinfo.GitVersion + "\n" +
		"Full git commit ID: " + buildinfo.GitRevision + "\n" +
		"Build date:         " + buildinfo.BuildDate + "\n")
	arguments, err := docopt.Parse(usage, nil, true, version, false)
	if err != nil {
		println(usage)
		log.Fatalf("Failed to parse usage, exiting: %v", err)
	}
	buildInfoLogCxt := log.WithFields(log.Fields{
		"version":   buildinfo.GitVersion,
		"buildDate": buildinfo.BuildDate,
		"gitCommit": buildinfo.GitRevision,
	})
	buildInfoLogCxt.Info("Felix starting up")
	log.Infof("Command line arguments: %v", arguments)

	// Load the configuration from all the different sources including the
	// datastore and merge. Keep retrying on failure.  We'll sit in this
	// loop until the datastore is ready.
	log.Infof("Loading configuration...")
	var datastore bapi.Client
	var configParams *config.Config
configRetry:
	for {
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

		// We should now have enough config to connect to the datastore
		// so we can load the remainder of the config.
		datastoreConfig := configParams.DatastoreConfig()
		datastore, err = backend.NewClient(datastoreConfig)
		if err != nil {
			log.WithError(err).Error("Failed to connect to datastore")
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		globalConfig, hostConfig := loadConfigFromDatastore(datastore,
			configParams.FelixHostname)
		configParams.UpdateFrom(globalConfig, config.DatastoreGlobal)
		configParams.UpdateFrom(hostConfig, config.DatastorePerHost)
		configParams.Validate()
		if configParams.Err != nil {
			log.WithError(configParams.Err).Error(
				"Failed to parse/validate configuration from datastore.")
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		break configRetry
	}

	// If we get here, we've loaded the configuration successfully.
	// Update log levels before we do anything else.
	logutils.ConfigureLogging(configParams)
	// Since we may have enabled more logging, log with the build context
	// again.
	buildInfoLogCxt.WithField("config", configParams).Info(
		"Successfully loaded configuration.")

	// Start up the dataplane driver.  This may be the internal go-based driver or an external
	// one.
	var dpDriver dataplaneDriver
	var dpDriverCmd *exec.Cmd
	if configParams.UseInternalDataplaneDriver {
		log.Info("Using internal dataplane driver.")
		markAccept := configParams.NextIptablesMark()
		markPass := configParams.NextIptablesMark()
		markWorkload := configParams.NextIptablesMark()
		log.WithFields(log.Fields{
			"acceptMark":   markAccept,
			"passMark":     markPass,
			"workloadMark": markWorkload,
		}).Info("Calculated iptables mark bits")
		dpConfig := intdataplane.Config{
			RulesConfig: rules.Config{
				WorkloadIfacePrefixes: configParams.InterfacePrefixes(),

				IPSetConfigV4: ipsets.NewIPVersionConfig(
					ipsets.IPFamilyV4,
					rules.IPSetNamePrefix,
					rules.AllHistoricIPSetNamePrefixes,
					rules.LegacyV4IPSetNames,
				),
				IPSetConfigV6: ipsets.NewIPVersionConfig(
					ipsets.IPFamilyV6,
					rules.IPSetNamePrefix,
					rules.AllHistoricIPSetNamePrefixes,
					nil,
				),

				OpenStackSpecialCasesEnabled: configParams.OpenstackActive(),
				OpenStackMetadataIP:          net.ParseIP(configParams.MetadataAddr),
				OpenStackMetadataPort:        uint16(configParams.MetadataPort),

				IptablesMarkAccept:       markAccept,
				IptablesMarkPass:         markPass,
				IptablesMarkFromWorkload: markWorkload,

				IPIPEnabled:       configParams.IpInIpEnabled,
				IPIPTunnelAddress: configParams.IpInIpTunnelAddr,

				DropLogPrefix:        configParams.LogPrefix,
				ActionOnDrop:         configParams.DropActionOverride,
				EndpointToHostAction: configParams.DefaultEndpointToHostAction,

				FailsafeInboundHostPorts:  configParams.FailsafeInboundHostPorts,
				FailsafeOutboundHostPorts: configParams.FailsafeOutboundHostPorts,
			},
			IPIPMTU:                 configParams.IpInIpMtu,
			IptablesRefreshInterval: time.Duration(configParams.IptablesRefreshInterval) * time.Second,
			IptablesInsertMode:      configParams.ChainInsertMode,
			MaxIPSetSize:            configParams.MaxIpsetSize,
			IgnoreLooseRPF:          configParams.IgnoreLooseRPF,
			IPv6Enabled:             configParams.Ipv6Support,
			StatusReportingInterval: time.Duration(configParams.ReportingIntervalSecs) *
				time.Second,
		}
		intDP := intdataplane.NewIntDataplaneDriver(dpConfig)
		intDP.Start()
		dpDriver = intDP
	} else {
		log.WithField("driver", configParams.DataplaneDriver).Info(
			"Using external dataplane driver.")
		dpDriver, dpDriverCmd = extdataplane.StartExtDataplaneDriver(configParams.DataplaneDriver)
	}

	// Initialise the glue logic that connects the calculation graph to/from the dataplane driver.
	log.Info("Connect to the dataplane driver.")
	failureReportChan := make(chan string)
	dpConnector := newConnector(configParams, datastore, dpDriver, failureReportChan)

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

	// Get a Syncer from the datastore, which will feed the calculation
	// graph with updates, bringing Felix into sync..
	syncerToValidator := calc.NewSyncerCallbacksDecoupler()
	syncer := datastore.Syncer(syncerToValidator)
	log.Debugf("Created Syncer: %#v", syncer)

	// Create the ipsets/active policy calculation graph, which will
	// do the dynamic calculation of ipset memberships and active policies
	// etc.
	asyncCalcGraph := calc.NewAsyncCalcGraph(configParams, dpConnector.ToDataplane)

	if configParams.UsageReportingEnabled {
		// Usage reporting enabled, add stats collector to graph and
		// start the usage reporting thread.
		statsChan := make(chan calc.StatsUpdate, 1)
		statsCollector := calc.NewStatsCollector(func(stats calc.StatsUpdate) error {
			select {
			case statsChan <- stats:
				return nil
			default:
				return errors.New("Stats channel blocked")
			}
		})
		statsCollector.RegisterWith(asyncCalcGraph.Dispatcher)
		go usagerep.PeriodicallyReportUsage(
			24*time.Hour,
			configParams.FelixHostname,
			configParams.ClusterGUID,
			configParams.ClusterType,
			statsChan,
		)
	}

	// Create the validator, which sits between the syncer and the
	// calculation graph.
	validator := calc.NewValidationFilter(asyncCalcGraph)

	// Start the background processing threads.
	log.Infof("Starting the datastore Syncer/processing graph")
	syncer.Start()
	go syncerToValidator.SendTo(validator)
	asyncCalcGraph.Start()
	log.Infof("Started the datastore Syncer/processing graph")
	var stopSignalChans []chan<- bool
	if configParams.EndpointReportingEnabled {
		delay := configParams.EndpointReportingDelay()
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

	// Send the opening message to the dataplane driver, giving it its
	// config.
	dpConnector.ToDataplane <- &proto.ConfigUpdate{
		Config: configParams.RawValues(),
	}

	if configParams.PrometheusMetricsEnabled {
		log.Info("Prometheus metrics enabled.  Starting server.")
		go servePrometheusMetrics(configParams.PrometheusMetricsPort)
	}

	// Now monitor the worker process and our worker threads and shut
	// down the process gracefully if they fail.
	monitorAndManageShutdown(failureReportChan, dpDriverCmd, stopSignalChans)
}

func servePrometheusMetrics(port int) {
	for {
		log.WithField("port", port).Info("Starting prometheus metrics endpoint")
		http.Handle("/metrics", promhttp.Handler())
		err := http.ListenAndServe(fmt.Sprintf(":%v", port), nil)
		log.WithError(err).Error(
			"Prometheus metrics endpoint failed, trying to restart it...")
		time.Sleep(1 * time.Second)
	}
}

func monitorAndManageShutdown(failureReportChan <-chan string, driverCmd *exec.Cmd, stopSignalChans []chan<- bool) {
	// Ask the runtime to tell us if we get a term signal.
	termSignalChan := make(chan os.Signal)
	signal.Notify(termSignalChan, syscall.SIGTERM)

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
	receivedSignal := false
	var reason string
	select {
	case <-driverStoppedC:
		reason = "Driver stopped"
		driverAlreadyStopped = true
	case sig := <-termSignalChan:
		reason = fmt.Sprintf("Received OS signal %v", sig)
		receivedSignal = true
	case reason = <-failureReportChan:
	}
	log.WithField("reason", reason).Warn("Felix is shutting down")

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
		log.Info("Driver still running, trying to shut it down...")
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
			log.Info("Driver shut down after SIGTERM")
		case <-giveUpOnSigTerm:
			log.Error("Driver did not respond to SIGTERM, sending SIGKILL")
			driverCmd.Process.Kill()
			<-driverStoppedC
			log.Info("Driver shut down after SIGKILL")
		}
	}

	if !receivedSignal {
		// We're exiting due to a failure or a config change, wait
		// a couple of seconds to ensure that we don't go into a tight
		// restart loop (which would make the init daemon give up trying
		// to restart us).
		log.Info("Shutdown wasn't cause by signal, pausing to avoid tight restart loop")
		go func() {
			time.Sleep(2 * time.Second)
			log.Info("Pause complete, exiting.")
			syscall.Exit(1)
		}()
		// But, if we get a signal while we're waiting quit immediately.
		<-termSignalChan
	}

	// Then exit our process.
	log.Info("Received signal, exiting immediately")
	syscall.Exit(1)
}

func loadConfigFromDatastore(datastore bapi.Client, hostname string) (globalConfig, hostConfig map[string]string) {
	for {
		log.Info("Waiting for the datastore to be ready")
		if kv, err := datastore.Get(model.ReadyFlagKey{}); err != nil {
			log.WithError(err).Error("Failed to read global datastore 'Ready' flag, will retry...")
			time.Sleep(1 * time.Second)
			continue
		} else if kv.Value != true {
			log.Warning("Global datastore 'Ready' flag set to false, waiting...")
			time.Sleep(1 * time.Second)
			continue
		}

		log.Info("Loading global config from datastore")
		kvs, err := datastore.List(model.GlobalConfigListOptions{})
		if err != nil {
			log.WithError(err).Error("Failed to load config from datastore")
			time.Sleep(1 * time.Second)
			continue
		}
		globalConfig = make(map[string]string)
		for _, kv := range kvs {
			key := kv.Key.(model.GlobalConfigKey)
			value := kv.Value.(string)
			globalConfig[key.Name] = value
		}

		log.Infof("Loading per-host config from datastore; hostname=%v", hostname)
		kvs, err = datastore.List(
			model.HostConfigListOptions{Hostname: hostname})
		if err != nil {
			log.WithError(err).Error("Failed to load config from datastore")
			time.Sleep(1 * time.Second)
			continue
		}
		hostConfig = make(map[string]string)
		for _, kv := range kvs {
			key := kv.Key.(model.HostConfigKey)
			value := kv.Value.(string)
			hostConfig[key.Name] = value
		}
		log.Info("Loaded config from datastore")
		break
	}
	return globalConfig, hostConfig
}

type dataplaneDriver interface {
	SendMessage(msg interface{}) error
	RecvMessage() (msg interface{}, err error)
}

type DataplaneConnector struct {
	config                     *config.Config
	ToDataplane                chan interface{}
	StatusUpdatesFromDataplane chan interface{}
	InSync                     chan bool
	failureReportChan          chan<- string
	dataplane                  dataplaneDriver
	datastore                  bapi.Client
	statusReporter             *statusrep.EndpointStatusReporter

	datastoreInSync bool

	firstStatusReportSent bool
}

type Startable interface {
	Start()
}

func newConnector(configParams *config.Config,
	datastore bapi.Client,
	dataplane dataplaneDriver,
	failureReportChan chan<- string) *DataplaneConnector {
	felixConn := &DataplaneConnector{
		config:                     configParams,
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
	for {
		payload, err := fc.dataplane.RecvMessage()
		if err != nil {
			log.WithError(err).Error("Failed to read from front-end socket")
			fc.shutDownProcess("Failed to read from front-end socket")
		}
		log.WithField("payload", payload).Debug("New message from dataplane")
		switch msg := payload.(type) {
		case *proto.ProcessStatusUpdate:
			fc.handleProcessStatusUpdate(msg)
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

func (fc *DataplaneConnector) handleProcessStatusUpdate(msg *proto.ProcessStatusUpdate) {
	log.Debugf("Status update from dataplane driver: %v", *msg)
	statusReport := model.StatusReport{
		Timestamp:     msg.IsoTimestamp,
		UptimeSeconds: msg.Uptime,
		FirstUpdate:   !fc.firstStatusReportSent,
	}
	kv := model.KVPair{
		Key:   model.ActiveStatusReportKey{Hostname: fc.config.FelixHostname},
		Value: &statusReport,
		TTL:   time.Duration(fc.config.ReportingTTLSecs) * time.Second,
	}
	_, err := fc.datastore.Apply(&kv)
	if err != nil {
		log.Warningf("Failed to write status to datastore: %v", err)
	} else {
		fc.firstStatusReportSent = true
	}
	kv = model.KVPair{
		Key:   model.LastStatusReportKey{Hostname: fc.config.FelixHostname},
		Value: &statusReport,
	}
	_, err = fc.datastore.Apply(&kv)
	if err != nil {
		log.Warningf("Failed to write status to datastore: %v", err)
	}
}

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
			logCxt := log.WithFields(log.Fields{
				"old": config,
				"new": msg.Config,
			})
			logCxt.Info("Possible config update")
			if config != nil && !reflect.DeepEqual(msg.Config, config) {
				logCxt.Warn("Felix configuration changed. Need to restart.")
				fc.shutDownProcess("config changed")
			} else if config == nil {
				logCxt.Info("Config resolved.")
				config = make(map[string]string)
				for k, v := range msg.Config {
					config[k] = v
				}
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
