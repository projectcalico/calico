// Copyright (c) 2016-2017,2020-2021 Tigera, Inc. All rights reserved.
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

package config

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

var (
	IfaceListRegexp   = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}(,[a-zA-Z0-9_-]{1,15})*$`)
	AuthorityRegexp   = regexp.MustCompile(`^[^:/]+:\d+$`)
	HostnameRegexp    = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	StringRegexp      = regexp.MustCompile(`^.*$`)
	HostAddressRegexp = regexp.MustCompile(`^[a-zA-Z0-9:._+-]{1,64}$`)
)

const (
	maxUint = ^uint(0)
	maxInt  = int(maxUint >> 1)
	minInt  = -maxInt - 1
)

// Source of a config value.  Values from higher-numbered sources override
// those from lower-numbered sources.  Note: some parameters (such as those
// needed to connect to the datastore) can only be set from a local source.
type Source uint8

const (
	Default = iota
	DatastoreGlobal
	DatastorePerHost
	ConfigFile
	EnvironmentVariable
)

var SourcesInDescendingOrder = []Source{EnvironmentVariable, ConfigFile, DatastorePerHost, DatastoreGlobal}

func (source Source) String() string {
	switch source {
	case Default:
		return "<default>"
	case DatastoreGlobal:
		return "datastore (global)"
	case DatastorePerHost:
		return "datastore (per-host)"
	case ConfigFile:
		return "config file"
	case EnvironmentVariable:
		return "environment variable"
	}
	return fmt.Sprintf("<unknown(%v)>", uint8(source))
}

func (source Source) Local() bool {
	switch source {
	case Default, ConfigFile, EnvironmentVariable:
		return true
	default:
		return false
	}
}

// Config contains the best, parsed config values loaded from the various sources.
// We use tags to control the parsing and validation.
type Config struct {
	// Configuration parameters.

	DatastoreType string `config:"oneof(kubernetes,etcdv3);etcdv3;non-zero,die-on-fail"`

	EtcdAddr      string   `config:"authority;127.0.0.1:2379;local"`
	EtcdScheme    string   `config:"oneof(http,https);http;local"`
	EtcdKeyFile   string   `config:"file(must-exist);;local"`
	EtcdCertFile  string   `config:"file(must-exist);;local"`
	EtcdCaFile    string   `config:"file(must-exist);;local"`
	EtcdEndpoints []string `config:"endpoint-list;;local"`

	LogFilePath string `config:"file;/var/log/calico/typha.log;die-on-fail"`

	LogSeverityFile   string `config:"oneof(DEBUG,INFO,WARNING,ERROR,CRITICAL);INFO"`
	LogSeverityScreen string `config:"oneof(DEBUG,INFO,WARNING,ERROR,CRITICAL);INFO"`
	LogSeveritySys    string `config:"oneof(DEBUG,INFO,WARNING,ERROR,CRITICAL);INFO"`

	HealthEnabled bool   `config:"bool;false"`
	HealthHost    string `config:"host-address;localhost"`
	HealthPort    int    `config:"int(0,65535);9098"`

	PrometheusMetricsEnabled        bool   `config:"bool;false"`
	PrometheusMetricsHost           string `config:"host-address;"`
	PrometheusMetricsPort           int    `config:"int(0,65535);9093"`
	PrometheusGoMetricsEnabled      bool   `config:"bool;true"`
	PrometheusProcessMetricsEnabled bool   `config:"bool;true"`

	SnapshotCacheMaxBatchSize int `config:"int(1,);100"`

	ServerMaxMessageSize                 int           `config:"int(1,);100"`
	ServerMaxFallBehindSecs              time.Duration `config:"seconds;300"`
	ServerNewClientFallBehindGracePeriod time.Duration `config:"seconds;300"`
	ServerMinBatchingAgeThresholdSecs    time.Duration `config:"seconds;0.01"`
	ServerPingIntervalSecs               time.Duration `config:"seconds;10"`
	ServerPongTimeoutSecs                time.Duration `config:"seconds;60"`
	ServerPort                           int           `config:"port;0"`

	// Server-side TLS config for Typha's communication with Felix.  If any of these are
	// specified, they _all_ must be - except that either ClientCN or ClientURISAN may be left
	// unset - and Typha will then only accept secure (TLS) connections.  Each connecting client
	// (Felix) must present a certificate signed by a CA in CAFile, and with CN matching
	// ClientCN or URI SAN matching ClientURISAN.
	ServerKeyFile  string `config:"file(must-exist);;local"`
	ServerCertFile string `config:"file(must-exist);;local"`
	CAFile         string `config:"file(must-exist);;local"`
	ClientCN       string `config:"string;"`
	ClientURISAN   string `config:"string;"`

	DebugMemoryProfilePath  string `config:"file;;"`
	DebugDisableLogDropping bool   `config:"bool;false"`

	ConnectionRebalancingMode  string        `config:"oneof(none,kubernetes);none"`
	ConnectionDropIntervalSecs time.Duration `config:"seconds;1"`
	MaxConnectionsUpperLimit   int           `config:"int(1,);10000"`
	MaxConnectionsLowerLimit   int           `config:"int(1,);400"`
	K8sServicePollIntervalSecs time.Duration `config:"seconds;30"`
	K8sNamespace               string        `config:"string;kube-system"`
	K8sServiceName             string        `config:"string;calico-typha"`
	K8sPortName                string        `config:"string;calico-typha"`

	// State tracking.

	// nameToSource tracks where we loaded each config param from.
	sourceToRawConfig map[Source]map[string]string
	rawValues         map[string]string
}

type ProtoPort struct {
	Protocol string
	Port     uint16
}

// Load parses and merges the rawData from one particular source into this config object.
// If there is a config value already loaded from a higher-priority source, then
// the new value will be ignored (after validation).
func (config *Config) UpdateFrom(rawData map[string]string, source Source) (changed bool, err error) {
	log.Infof("Merging in config from %v: %v", source, rawData)
	// Defensively take a copy of the raw data, in case we've been handed
	// a mutable map by mistake.
	rawDataCopy := make(map[string]string)
	for k, v := range rawData {
		if v == "" {
			log.WithFields(log.Fields{
				"name":   k,
				"source": source,
			}).Info("Ignoring empty configuration parameter. Use value 'none' if " +
				"your intention is to explicitly disable the default value.")
			continue
		}
		rawDataCopy[k] = v
	}
	config.sourceToRawConfig[source] = rawDataCopy

	changed, err = config.resolve()
	return
}

func (config *Config) resolve() (changed bool, err error) {
	newRawValues := make(map[string]string)
	nameToSource := make(map[string]Source)
	for _, source := range SourcesInDescendingOrder {
	valueLoop:
		for rawName, rawValue := range config.sourceToRawConfig[source] {
			currentSource := nameToSource[rawName]
			param, ok := knownParams[strings.ToLower(rawName)]
			if !ok {
				if source >= currentSource {
					// Stash the raw value in case it's useful for
					// a plugin.  Since we don't know the canonical
					// name, use the raw name.
					newRawValues[rawName] = rawValue
					nameToSource[rawName] = source
				}
				log.WithField("raw name", rawName).Info(
					"Ignoring unknown config param.")
				continue valueLoop
			}
			metadata := param.GetMetadata()
			name := metadata.Name
			if metadata.Local && !source.Local() {
				log.Warningf("Ignoring local-only configuration for %v from %v",
					name, source)
				continue valueLoop
			}

			log.Infof("Parsing value for %v: %v (from %v)",
				name, rawValue, source)
			var value interface{}
			if strings.ToLower(rawValue) == "none" {
				// Special case: we allow a value of "none" to force the value to
				// the zero value for a field.  The zero value often differs from
				// the default value.  Typically, the zero value means "turn off
				// the feature".
				if metadata.NonZero {
					err = errors.New("Non-zero field cannot be set to none")
					log.Errorf(
						"Failed to parse value for %v: %v from source %v. %v",
						name, rawValue, source, err)
					return
				}
				value = metadata.ZeroValue
				log.Infof("Value set to 'none', replacing with zero-value: %#v.",
					value)
			} else {
				value, err = param.Parse(rawValue)
				if err != nil {
					logCxt := log.WithError(err).WithField("source", source)
					if metadata.DieOnParseFailure {
						logCxt.Error("Invalid (required) config value.")
						return
					} else {
						logCxt.WithField("default", metadata.Default).Warn(
							"Replacing invalid value with default")
						value = metadata.Default
						err = nil
					}
				}
			}

			log.Infof("Parsed value for %v: %v (from %v)",
				name, value, source)
			if source < currentSource {
				log.Infof("Skipping config value for %v from %v; "+
					"already have a value from %v", name,
					source, currentSource)
				continue
			}
			field := reflect.ValueOf(config).Elem().FieldByName(name)
			field.Set(reflect.ValueOf(value))
			newRawValues[name] = rawValue
			nameToSource[name] = source
		}
	}
	changed = !reflect.DeepEqual(newRawValues, config.rawValues)
	config.rawValues = newRawValues
	return
}

func (config *Config) DatastoreConfig() apiconfig.CalicoAPIConfig {
	// Special case for etcdv3 datastore, where we want to honour established
	// config mechanisms.
	if config.DatastoreType == "etcdv3" {
		// Build a CalicoAPIConfig with the etcd fields filled in from our config.
		// config.
		var etcdEndpoints string
		if len(config.EtcdEndpoints) == 0 {
			etcdEndpoints = config.EtcdScheme + "://" + config.EtcdAddr
		} else {
			etcdEndpoints = strings.Join(config.EtcdEndpoints, ",")
		}
		etcdCfg := apiconfig.EtcdConfig{
			EtcdEndpoints:  etcdEndpoints,
			EtcdKeyFile:    config.EtcdKeyFile,
			EtcdCertFile:   config.EtcdCertFile,
			EtcdCACertFile: config.EtcdCaFile,
		}
		return apiconfig.CalicoAPIConfig{
			Spec: apiconfig.CalicoAPIConfigSpec{
				DatastoreType: apiconfig.EtcdV3,
				EtcdConfig:    etcdCfg,
			},
		}
	}

	// Kubernetes mode, which is now the default for LoadClientConfigFromEnvironment so we let
	// it do its thing...
	cfg, err := apiconfig.LoadClientConfigFromEnvironment()
	if err != nil {
		log.WithError(err).Panic("Failed to create datastore config")
	}
	return *cfg
}

func (config *Config) requiringTLS() bool {
	// True if any of the TLS parameters are set.
	return config.ServerKeyFile+config.ServerCertFile+config.CAFile+config.ClientCN+config.ClientURISAN != ""
}

// Validate() performs cross-field validation.
func (config *Config) Validate() (err error) {
	if config.DatastoreType == "etcdv3" && len(config.EtcdEndpoints) == 0 {
		if config.EtcdScheme == "" {
			err = errors.New("EtcdEndpoints and EtcdScheme both missing")
		}
		if config.EtcdAddr == "" {
			err = errors.New("EtcdEndpoints and EtcdAddr both missing")
		}
	}

	// If any server-side TLS config parameters are specified, they _all_ must be - except that
	// either ClientCN or ClientURISAN may be left unset.
	if config.requiringTLS() {
		// Some TLS config specified.
		if config.ServerKeyFile == "" ||
			config.ServerCertFile == "" ||
			config.CAFile == "" ||
			(config.ClientCN == "" && config.ClientURISAN == "") {
			err = errors.New("If any Felix-Typha TLS config parameters are specified," +
				" they _all_ must be" +
				" - except that either ClientCN or ClientURISAN may be left unset.")
		}
	}
	return
}

var knownParams map[string]param

func loadParams() {
	knownParams = make(map[string]param)
	config := Config{}
	kind := reflect.TypeOf(config)
	metaRegexp := regexp.MustCompile(`^([^;(]+)(?:\(([^)]*)\))?;` +
		`([^;]*)(?:;` +
		`([^;]*))?$`)
	for ii := 0; ii < kind.NumField(); ii++ {
		field := kind.Field(ii)
		tag := field.Tag.Get("config")
		if tag == "" {
			continue
		}
		captures := metaRegexp.FindStringSubmatch(tag)
		if len(captures) == 0 {
			log.Panicf("Failed to parse metadata for config param %v", field.Name)
		}
		log.Debugf("%v: metadata captures: %#v", field.Name, captures)
		kind := captures[1]       // Type: "int|oneof|bool|port-list|..."
		kindParams := captures[2] // Parameters for the type: e.g. for oneof "http,https"
		defaultStr := captures[3] // Default value e.g "1.0"
		flags := captures[4]
		var param param
		var err error
		switch kind {
		case "bool":
			param = &BoolParam{}
		case "int":
			min := minInt
			max := maxInt
			if kindParams != "" {
				minAndMax := strings.Split(kindParams, ",")
				min, err = strconv.Atoi(minAndMax[0])
				if err != nil {
					log.Panicf("Failed to parse min value for %v", field.Name)
				}
				if minAndMax[1] != "" {
					max, err = strconv.Atoi(minAndMax[1])
					if err != nil {
						log.Panicf("Failed to parse max value for %v", field.Name)
					}
				}
			}
			param = &IntParam{Min: min, Max: max}
		case "int32":
			param = &Int32Param{}
		case "mark-bitmask":
			param = &MarkBitmaskParam{}
		case "float":
			param = &FloatParam{}
		case "seconds":
			param = &SecondsParam{}
		case "iface-list":
			param = &RegexpParam{Regexp: IfaceListRegexp,
				Msg: "invalid Linux interface name"}
		case "file":
			param = &FileParam{
				MustExist:  strings.Contains(kindParams, "must-exist"),
				Executable: strings.Contains(kindParams, "executable"),
			}
		case "authority":
			param = &RegexpParam{Regexp: AuthorityRegexp,
				Msg: "invalid URL authority"}
		case "ipv4":
			param = &Ipv4Param{}
		case "endpoint-list":
			param = &EndpointListParam{}
		case "port":
			param = &PortParam{}
		case "port-list":
			param = &PortListParam{}
		case "hostname":
			param = &RegexpParam{Regexp: HostnameRegexp,
				Msg: "invalid hostname"}
		case "oneof":
			options := strings.Split(kindParams, ",")
			lowerCaseToCanon := make(map[string]string)
			for _, option := range options {
				lowerCaseToCanon[strings.ToLower(option)] = option
			}
			param = &OneofListParam{
				lowerCaseOptionsToCanonical: lowerCaseToCanon}
		case "string":
			param = &RegexpParam{Regexp: StringRegexp,
				Msg: "invalid string"}
		case "host-address":
			param = &RegexpParam{Regexp: HostAddressRegexp,
				Msg: "invalid host address"}
		default:
			log.Panicf("Unknown type of parameter: %v", kind)
		}

		metadata := param.GetMetadata()
		metadata.Name = field.Name
		metadata.ZeroValue = reflect.ValueOf(config).FieldByName(field.Name).Interface()
		if strings.Contains(flags, "non-zero") {
			metadata.NonZero = true
		}
		if strings.Contains(flags, "die-on-fail") {
			metadata.DieOnParseFailure = true
		}
		if strings.Contains(flags, "local") {
			metadata.Local = true
		}

		if defaultStr != "" {
			if strings.Contains(flags, "skip-default-validation") {
				metadata.Default = defaultStr
			} else {
				// Parse the default value and save it in the metadata. Doing
				// that here ensures that we syntax-check the defaults now.
				defaultVal, err := param.Parse(defaultStr)
				if err != nil {
					log.Panicf("Invalid default value: %v", err)
				}
				metadata.Default = defaultVal
			}
		} else {
			metadata.Default = metadata.ZeroValue
		}
		knownParams[strings.ToLower(field.Name)] = param
	}
}

func (config *Config) RawValues() map[string]string {
	return config.rawValues
}

func New() *Config {
	if knownParams == nil {
		loadParams()
	}
	p := &Config{
		rawValues:         make(map[string]string),
		sourceToRawConfig: make(map[Source]map[string]string),
	}
	for _, param := range knownParams {
		param.setDefault(p)
	}
	return p
}

type param interface {
	GetMetadata() *Metadata
	Parse(raw string) (result interface{}, err error)
	setDefault(*Config)
}
