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
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/docopt/docopt-go"
	pb "github.com/gogo/protobuf/proto"
	"github.com/projectcalico/felix/go/datastructures/ip"
	"github.com/projectcalico/felix/go/felix/buildinfo"
	"github.com/projectcalico/felix/go/felix/calc"
	"github.com/projectcalico/felix/go/felix/config"
	_ "github.com/projectcalico/felix/go/felix/config"
	"github.com/projectcalico/felix/go/felix/logutils"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/felix/go/felix/status"
	"github.com/projectcalico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"io"
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
	version := ("Version:    " + buildinfo.Version + "\n" +
		"Build date: " + buildinfo.BuildDate + "\n" +
		"Git commit: " + buildinfo.GitRevision)
	arguments, err := docopt.Parse(usage, nil, true, version, false)
	if err != nil {
		println(usage)
		log.Fatalf("Failed to parse usage, exiting: %v", err)
	}
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
			log.Errorf("Failed to load configuration file, %s: %s",
				configFile, err)
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		// Parse and merge the local config.
		configParams.UpdateFrom(envConfig, config.EnvironmentVariable)
		configParams.UpdateFrom(fileConfig, config.ConfigFile)
		if configParams.Err != nil {
			log.Errorf("Failed to parse configuration: %s", configParams.Err)
			time.Sleep(1 * time.Second)
			continue configRetry
		}

		// We should now have enough config to connect to the datastore
		// so we can load the remainder of the config.
		datastoreConfig := configParams.DatastoreConfig()
		datastore, err = backend.NewClient(datastoreConfig)
		if err != nil {
			log.Errorf("Failed to connect to datastore: %v", err)
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		globalConfig, hostConfig := loadConfigFromDatastore(datastore,
			configParams.FelixHostname)
		configParams.UpdateFrom(globalConfig, config.DatastoreGlobal)
		configParams.UpdateFrom(hostConfig, config.DatastorePerHost)
		configParams.Validate()
		if configParams.Err != nil {
			log.Fatalf("Failed to parse/validate configuration from datastore: %s",
				configParams.Err)
			time.Sleep(1 * time.Second)
			continue configRetry
		}
		break configRetry
	}

	// If we get here, we've loaded the configuration successfully.
	// Update log levels before we do anything else.
	logutils.ConfigureLogging(configParams)
	log.Infof("Successfully loaded configuration: %+v", configParams)

	// Create a pair of pipes, one for sending messages to the dataplane
	// driver, the other for receiving.
	toDriverR, toDriverW, err := os.Pipe()
	if err != nil {
		log.Fatalf("Failed to open pipe for dataplane driver: %v", err)
	}
	fromDriverR, fromDriverW, err := os.Pipe()
	if err != nil {
		log.Fatalf("Failed to open pipe for dataplane driver: %v", err)
	}

	cmd := exec.Command(configParams.DataplaneDriver)
	driverOut, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal("Failed to create pipe for dataplane driver")
	}
	driverErr, err := cmd.StderrPipe()
	if err != nil {
		log.Fatal("Failed to create pipe for dataplane driver")
	}
	go io.Copy(os.Stdout, driverOut)
	go io.Copy(os.Stderr, driverErr)
	cmd.ExtraFiles = []*os.File{toDriverR, fromDriverW}
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start dataplane driver: %v", err)
	}
	shutdownReasonChan := make(chan string)
	// Start a thread to shut this process down if the driver fails.
	go func() {
		err := cmd.Wait()
		shutdownReasonChan <- fmt.Sprintf("Dataplane driver process failed: %v", err)
	}()

	termSignalChan := make(chan os.Signal)
	signal.Notify(termSignalChan, syscall.SIGTERM)

	// Once we've got to this point, the dataplane driver is running.
	// Start a goroutine to sequence the shutdown if we hit an error or
	// get sent a TERM signal.  This is done on a best-effort basis.  If
	// we fail to shut down the driver it will exit when its pipe is
	// closed.
	go manageShutdown(termSignalChan, shutdownReasonChan, cmd)

	// Now the sub-process is running, close our copy of the file handles
	// for the child's end of the pipes.
	if err := toDriverR.Close(); err != nil {
		log.Fatalf("Failed to close parent's copy of pipe")
	}
	if err := fromDriverW.Close(); err != nil {
		log.Fatalf("Failed to close parent's copy of pipe")
	}

	log.Info("Starting the dataplane driver")
	failureReportChan := make(chan string)
	felixConn := NewDataplaneConn(configParams,
		datastore, toDriverW, fromDriverR, failureReportChan)
	felixConn.Start()
	reason := <-failureReportChan
	log.Warn("Background worker stopped, attempting managed shutdown.")
	shutdownReasonChan <- reason
	time.Sleep(5 * time.Second)
	log.Fatal("Managed shutdown failed, exiting.")
}

func manageShutdown(osSignalChan <-chan os.Signal, failureReportChan <-chan string, driverCmd *exec.Cmd) {
	select {
	case sig := <-osSignalChan:
		log.Infof("Received OS signal %v; shutting down.", sig)
	case failureReason := <-failureReportChan:
		log.Errorf("Detected failure: %v; shutting down.", failureReason)
	}

	// Make sure we don't wait for ever if the driver is unresponsive.
	go func() {
		time.Sleep(5)
		log.Fatal("Failed to wait for driver to exit, giving up.")
	}()

	// Signal to the driver to exit.
	driverCmd.Process.Kill()
	driverCmd.Wait()

	// Then exit our process.
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
			log.Errorf("Failed to load config from datastore: %v", err)
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
			log.Errorf("Failed to load config from datastore: %v", err)
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
	config            *config.Config
	toFelix           chan interface{}
	endpointUpdates   chan interface{}
	inSync            chan bool
	failureReportChan chan<- string
	felixReader       io.Reader
	felixWriter       io.Writer
	datastore         bapi.Client
	statusReporter    *status.EndpointStatusReporter

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
		config:            configParams,
		datastore:         datastore,
		toFelix:           make(chan interface{}),
		endpointUpdates:   make(chan interface{}),
		inSync:            make(chan bool, 1),
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
			log.Fatalf("Failed to read from front-end socket: %v", err)
		}
		length := binary.LittleEndian.Uint64(buf)

		data := make([]byte, length)
		_, err = io.ReadFull(fc.felixReader, data)
		if err != nil {
			log.Fatalf("Failed to read from front-end socket: %v", err)
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
				fc.endpointUpdates <- msg.WorkloadEndpointStatusUpdate
			}
		case *proto.FromDataplane_WorkloadEndpointStatusRemove:
			if fc.statusReporter != nil {
				fc.endpointUpdates <- msg.WorkloadEndpointStatusRemove
			}
		case *proto.FromDataplane_HostEndpointStatusUpdate:
			if fc.statusReporter != nil {
				fc.endpointUpdates <- msg.HostEndpointStatusUpdate
			}
		case *proto.FromDataplane_HostEndpointStatusRemove:
			if fc.statusReporter != nil {
				fc.endpointUpdates <- msg.HostEndpointStatusRemove
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
		msg := <-fc.toFelix
		switch msg := msg.(type) {
		case *proto.InSync:
			log.Info("Datastore now in sync.")
			if !fc.datastoreInSync {
				fc.datastoreInSync = true
				fc.inSync <- true
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
	default:
		log.Fatalf("Unknown message type: %#v", msg)
	}
	//
	//if log.V(4) {
	//	// For debugging purposes, dump the message to
	//	// messagepack; parse it as a map and dump it to JSON.
	//	bs := make([]byte, 0)
	//	enc := codec.NewEncoderBytes(&bs, msgpackHandle)
	//	enc.Encode(envelope)
	//
	//	dec := codec.NewDecoderBytes(bs, msgpackHandle)
	//	var decodedType string
	//	msgAsMap := make(map[string]interface{})
	//	dec.Decode(&decodedType)
	//	dec.Decode(msgAsMap)
	//	jsonMsg, err := json.Marshal(msgAsMap)
	//	if err == nil {
	//		log.Infof("Dumped message: %v %v", decodedType, string(jsonMsg))
	//	} else {
	//		log.Infof("Failed to dump map to JSON: (%v) %v", err, msgAsMap)
	//	}
	//}
	data, err := pb.Marshal(envelope)
	if err != nil {
		log.Fatalf("Failed to marshal data to front end: %#v; %v",
			msg, err)
	}

	lengthBuffer := make([]byte, 8)
	binary.LittleEndian.PutUint64(lengthBuffer, uint64(len(data)))

	numBytes, err := fc.felixWriter.Write(lengthBuffer)
	if err != nil || numBytes != len(lengthBuffer) {
		log.Fatalf("Failed to write to front end (only wrote %v bytes): %v",
			numBytes, err)
	}
	numBytes, err = fc.felixWriter.Write(data)
	if err != nil || numBytes != len(data) {
		log.Fatalf("Failed to write to front end (only wrote %v bytes): %v",
			numBytes, err)
	}
}

func (fc *DataplaneConn) Start() {
	// Start a background thread to write to the dataplane driver.
	go fc.sendMessagesToDataplaneDriver()

	// Send the opening message to the dataplane driver, giving it its
	// config.
	fc.toFelix <- &proto.ConfigUpdate{
		Config: fc.config.RawValues(),
	}

	// Start background thread to read messages from dataplane driver.
	go fc.readMessagesFromDataplane()

	// Create the datastore syncer, which will feed the calculation graph.
	syncerToValidator := calc.NewSyncerCallbacksDecoupler()
	syncer := fc.datastore.Syncer(syncerToValidator)
	log.Debugf("Created Syncer: %#v", syncer)

	// Create the ipsets/active policy calculation graph, which will
	// do the dynamic calculation of ipset memberships and active policies
	// etc.
	asyncCalcGraph := calc.NewAsyncCalcGraph(fc.config, fc.toFelix)

	// Create the validator, which sits between the syncer and the
	// calculation graph.
	validator := calc.NewValidationFilter(asyncCalcGraph)

	// Start the background processing threads.
	log.Infof("Starting the datastore Syncer/processing graph")
	syncer.Start()
	go syncerToValidator.SendTo(validator)
	asyncCalcGraph.Start()
	log.Infof("Started the datastore Syncer/processing graph")

	if fc.config.EndpointReportingEnabled {
		log.Info("Endpoint status reporting enabled, starting status reporter")
		fc.statusReporter = status.NewEndpointStatusReporter(
			fc.config.FelixHostname,
			fc.endpointUpdates,
			fc.inSync,
			fc.datastore,
			fc.config.EndpointReportingDelay(),
			fc.config.EndpointReportingDelay()*180,
		)
		fc.statusReporter.Start()
	}
}
