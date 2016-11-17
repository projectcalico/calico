// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	"encoding/binary"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/docopt/docopt-go"
	pb "github.com/gogo/protobuf/proto"
	"github.com/projectcalico/felix/go/felix/buildinfo"
	"github.com/projectcalico/felix/go/felix/calc"
	"github.com/projectcalico/felix/go/felix/config"
	_ "github.com/projectcalico/felix/go/felix/config"
	"github.com/projectcalico/felix/go/felix/ip"
	"github.com/projectcalico/felix/go/felix/logutils"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/felix/go/felix/statusrep"
	"github.com/projectcalico/felix/go/felix/usagerep"
	"github.com/projectcalico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"syscall"
	"time"
)

const usage = `Felix, the Calico per-host daemon.

Usage:
  calico-felix [-c <config>]

Options:
  -c --config-file=<config>  Config file to load [default: /etc/calico/felix.cfg].
  --version                  Print the version and exit.
`

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

	// Create a pair of pipes, one for sending messages to the dataplane
	// driver, the other for receiving.
	toDriverR, toDriverW, err := os.Pipe()
	if err != nil {
		log.WithError(err).Fatal("Failed to open pipe for dataplane driver")
	}
	fromDriverR, fromDriverW, err := os.Pipe()
	if err != nil {
		log.WithError(err).Fatal("Failed to open pipe for dataplane driver")
	}

	cmd := exec.Command(configParams.DataplaneDriver)
	driverOut, err := cmd.StdoutPipe()
	if err != nil {
		log.WithError(err).Fatal("Failed to create pipe for dataplane driver")
	}
	driverErr, err := cmd.StderrPipe()
	if err != nil {
		log.WithError(err).Fatal("Failed to create pipe for dataplane driver")
	}
	go io.Copy(os.Stdout, driverOut)
	go io.Copy(os.Stderr, driverErr)
	cmd.ExtraFiles = []*os.File{toDriverR, fromDriverW}
	if err := cmd.Start(); err != nil {
		log.WithError(err).Fatal("Failed to start dataplane driver")
	}

	// Now the sub-process is running, close our copy of the file handles
	// for the child's end of the pipes.
	if err := toDriverR.Close(); err != nil {
		cmd.Process.Kill()
		log.WithError(err).Fatal("Failed to close parent's copy of pipe")
	}
	if err := fromDriverW.Close(); err != nil {
		cmd.Process.Kill()
		log.WithError(err).Fatal("Failed to close parent's copy of pipe")
	}

	// Create the connection to/from the dataplane driver.
	log.Info("Connect to the dataplane driver.")
	failureReportChan := make(chan string)
	felixConn := NewDataplaneConn(configParams,
		datastore, toDriverW, fromDriverR, failureReportChan)

	// Now create the calculation graph, which receives updates from the
	// datastore and outputs dataplane updates for the dataplane driver.
	//
	// The Syncer has its own thread and we use an extra thread for the
	// Validator, just to pipeline that part of the calculation then the
	// main calculation graph runs in a single thread for simplicity.
	// The output of the calculation graph arrives at the dataplane
	// connection via channel.
	//
	// Syncer -chan-> Validator -chan-> Calc graph -chan-> felixConn
	//        KVPair            KVPair             protobufs

	// Get a Syncer from the datastore, which will feed the calculation
	// graph with updates, bringing Felix into sync..
	syncerToValidator := calc.NewSyncerCallbacksDecoupler()
	syncer := datastore.Syncer(syncerToValidator)
	log.Debugf("Created Syncer: %#v", syncer)

	// Create the ipsets/active policy calculation graph, which will
	// do the dynamic calculation of ipset memberships and active policies
	// etc.
	asyncCalcGraph := calc.NewAsyncCalcGraph(configParams, felixConn.ToDataplane)

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
		felixConn.statusReporter = statusrep.NewEndpointStatusReporter(
			configParams.FelixHostname,
			felixConn.StatusUpdatesFromDataplane,
			felixConn.InSync,
			felixConn.datastore,
			delay,
			delay*180,
		)
		felixConn.statusReporter.Start()
	}

	// Start communicating with the dataplane driver.
	felixConn.Start()

	// Send the opening message to the dataplane driver, giving it its
	// config.
	felixConn.ToDataplane <- &proto.ConfigUpdate{
		Config: configParams.RawValues(),
	}

	if configParams.PrometheusMetricsEnabled {
		log.Info("Prometheus metrics enabled.  Starting server.")
		go servePrometheusMetrics(configParams.PrometheusMetricsPort)
	}

	// Now monitor the worker process and our worker threads and shut
	// down the process gracefully if they fail.
	monitorAndManageShutdown(failureReportChan, cmd, stopSignalChans)
}

func servePrometheusMetrics(port int) {
	for {
		log.WithField("port", port).Info("Starting prometheus metrics endpoint")
		http.Handle("/metrics", promhttp.Handler())
		err := http.ListenAndServe(fmt.Sprintf(":%v", port), nil)
		log.WithError(err).Error(
			"Prometheus metrics endpoint failed, trying to restart it...")
		time.Sleep(1)
	}
}

func monitorAndManageShutdown(failureReportChan <-chan string, driverCmd *exec.Cmd, stopSignalChans []chan<- bool) {
	// Ask the runtime to tell us if we get a term signal.
	termSignalChan := make(chan os.Signal)
	signal.Notify(termSignalChan, syscall.SIGTERM)

	// Start a background thread to tell us when the driver stops.
	// If the driver stops unexpectedly, we'll terminate this process.
	// If this process needs to stop, we'll kill the driver and then wait
	// for the message from the background thread.
	driverStoppedC := make(chan bool)
	go func() {
		err := driverCmd.Wait()
		log.WithError(err).Warn("Driver process stopped")
		driverStoppedC <- true
	}()

	// Wait for one of the channels to give us a reason to shut down.
	driverAlreadyStopped := false
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

type ipUpdate struct {
	ipset string
	ip    ip.Addr
}

type DataplaneConn struct {
	config                     *config.Config
	ToDataplane                chan interface{}
	StatusUpdatesFromDataplane chan interface{}
	InSync                     chan bool
	failureReportChan          chan<- string
	felixReader                io.Reader
	felixWriter                io.Writer
	datastore                  bapi.Client
	statusReporter             *statusrep.EndpointStatusReporter

	datastoreInSync bool

	firstStatusReportSent bool
	nextSeqNumber         uint64
}

type Startable interface {
	Start()
}

func NewDataplaneConn(configParams *config.Config,
	datastore bapi.Client,
	toDriver io.Writer,
	fromDriver io.Reader,
	failureReportChan chan<- string) *DataplaneConn {
	felixConn := &DataplaneConn{
		config:                     configParams,
		datastore:                  datastore,
		ToDataplane:                make(chan interface{}),
		StatusUpdatesFromDataplane: make(chan interface{}),
		InSync:            make(chan bool, 1),
		failureReportChan: failureReportChan,
		felixReader:       fromDriver,
		felixWriter:       toDriver,
	}
	return felixConn
}

func (fc *DataplaneConn) readMessagesFromDataplane() {
	defer func() {
		fc.shutDownProcess("Failed to read messages from dataplane")
	}()
	log.Info("Reading from dataplane driver pipe...")
	for {
		buf := make([]byte, 8)
		_, err := io.ReadFull(fc.felixReader, buf)
		if err != nil {
			log.WithError(err).Error("Failed to read from front-end socket")
			fc.shutDownProcess("Failed to read from front-end socket")
		}
		length := binary.LittleEndian.Uint64(buf)

		data := make([]byte, length)
		_, err = io.ReadFull(fc.felixReader, data)
		if err != nil {
			log.WithError(err).Error("Failed to read from front-end socket")
			fc.shutDownProcess("Failed to read from front-end socket")
		}

		msg := proto.FromDataplane{}
		pb.Unmarshal(data, &msg)

		log.Debugf("Message from Felix: %#v", msg.Payload)

		payload := msg.Payload
		switch msg := payload.(type) {
		case *proto.FromDataplane_ProcessStatusUpdate:
			fc.handleProcessStatusUpdate(msg.ProcessStatusUpdate)
		case *proto.FromDataplane_WorkloadEndpointStatusUpdate:
			if fc.statusReporter != nil {
				fc.StatusUpdatesFromDataplane <- msg.WorkloadEndpointStatusUpdate
			}
		case *proto.FromDataplane_WorkloadEndpointStatusRemove:
			if fc.statusReporter != nil {
				fc.StatusUpdatesFromDataplane <- msg.WorkloadEndpointStatusRemove
			}
		case *proto.FromDataplane_HostEndpointStatusUpdate:
			if fc.statusReporter != nil {
				fc.StatusUpdatesFromDataplane <- msg.HostEndpointStatusUpdate
			}
		case *proto.FromDataplane_HostEndpointStatusRemove:
			if fc.statusReporter != nil {
				fc.StatusUpdatesFromDataplane <- msg.HostEndpointStatusRemove
			}
		default:
			log.Warningf("XXXX Unknown message from felix: %#v", msg)
		}
		log.Debug("Finished handling message from front-end")
	}
}

func (fc *DataplaneConn) handleProcessStatusUpdate(msg *proto.ProcessStatusUpdate) {
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

func (fc *DataplaneConn) sendMessagesToDataplaneDriver() {
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
		fc.marshalToDataplane(msg)
	}
}

func (fc *DataplaneConn) shutDownProcess(reason string) {
	// Send a failure report to the managed shutdown thread then give it
	// a few seconds to do the shutdown.
	fc.failureReportChan <- reason
	time.Sleep(5 * time.Second)
	// The graceful shutdown failed, terminate the process.
	log.Panic("Managed shutdown failed. Panicking.")
}

func (fc *DataplaneConn) marshalToDataplane(msg interface{}) {
	log.Debugf("Writing msg (%v) to felix: %#v", fc.nextSeqNumber, msg)

	envelope := &proto.ToDataplane{
		SequenceNumber: fc.nextSeqNumber,
	}
	fc.nextSeqNumber += 1
	switch msg := msg.(type) {
	case *proto.ConfigUpdate:
		envelope.Payload = &proto.ToDataplane_ConfigUpdate{msg}
	case *proto.InSync:
		envelope.Payload = &proto.ToDataplane_InSync{msg}
	case *proto.IPSetUpdate:
		envelope.Payload = &proto.ToDataplane_IpsetUpdate{msg}
	case *proto.IPSetDeltaUpdate:
		envelope.Payload = &proto.ToDataplane_IpsetDeltaUpdate{msg}
	case *proto.IPSetRemove:
		envelope.Payload = &proto.ToDataplane_IpsetRemove{msg}
	case *proto.ActivePolicyUpdate:
		envelope.Payload = &proto.ToDataplane_ActivePolicyUpdate{msg}
	case *proto.ActivePolicyRemove:
		envelope.Payload = &proto.ToDataplane_ActivePolicyRemove{msg}
	case *proto.ActiveProfileUpdate:
		envelope.Payload = &proto.ToDataplane_ActiveProfileUpdate{msg}
	case *proto.ActiveProfileRemove:
		envelope.Payload = &proto.ToDataplane_ActiveProfileRemove{msg}
	case *proto.HostEndpointUpdate:
		envelope.Payload = &proto.ToDataplane_HostEndpointUpdate{msg}
	case *proto.HostEndpointRemove:
		envelope.Payload = &proto.ToDataplane_HostEndpointRemove{msg}
	case *proto.WorkloadEndpointUpdate:
		envelope.Payload = &proto.ToDataplane_WorkloadEndpointUpdate{msg}
	case *proto.WorkloadEndpointRemove:
		envelope.Payload = &proto.ToDataplane_WorkloadEndpointRemove{msg}
	case *proto.HostMetadataUpdate:
		envelope.Payload = &proto.ToDataplane_HostMetadataUpdate{msg}
	case *proto.HostMetadataRemove:
		envelope.Payload = &proto.ToDataplane_HostMetadataRemove{msg}
	case *proto.IPAMPoolUpdate:
		envelope.Payload = &proto.ToDataplane_IpamPoolUpdate{msg}
	case *proto.IPAMPoolRemove:
		envelope.Payload = &proto.ToDataplane_IpamPoolRemove{msg}
	default:
		log.WithField("msg", msg).Panic("Unknown message type")
	}
	data, err := pb.Marshal(envelope)
	if err != nil {
		log.WithError(err).WithField("msg", msg).Panic(
			"Failed to marshal data to front end")
	}

	lengthBuffer := make([]byte, 8)
	binary.LittleEndian.PutUint64(lengthBuffer, uint64(len(data)))

	numBytes, err := fc.felixWriter.Write(lengthBuffer)
	if err != nil || numBytes != len(lengthBuffer) {
		log.WithError(err).WithField("bytesWritten", numBytes).Error(
			"Failed to write to dataplane driver")
		fc.shutDownProcess("Failed to write to front end")
	}
	numBytes, err = fc.felixWriter.Write(data)
	if err != nil || numBytes != len(data) {
		log.WithError(err).WithField("bytesWritten", numBytes).Error(
			"Failed to write to dataplane driver")
		fc.shutDownProcess("Failed to write to front end")
	}
}

func (fc *DataplaneConn) Start() {
	// Start a background thread to write to the dataplane driver.
	go fc.sendMessagesToDataplaneDriver()

	// Start background thread to read messages from dataplane driver.
	go fc.readMessagesFromDataplane()
}
