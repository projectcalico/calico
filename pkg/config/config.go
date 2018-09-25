package config

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	logutils "github.com/kelseyhightower/confd/pkg/log"
	"github.com/kelseyhightower/confd/pkg/resource/template"
	log "github.com/sirupsen/logrus"
)

var (
	configFile        = ""
	defaultConfigFile = "/etc/confd/confd.toml"
	confdir           string
	// config            Config // holds the global confd config.
	interval      int
	keepStageFile bool
	noop          bool
	onetime       bool
	prefix        string
	syncOnly      bool
	calicoconfig  string
)

// Copied from <felix>/config/config_params.go.
type TyphaConfig struct {
	Addr           string
	K8sServiceName string
	K8sNamespace   string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration

	// Client-side TLS config for confd's communication with Typha.  If any of these are
	// specified, they _all_ must be - except that either CN or URISAN may be left unset.
	// confd will then initiate a secure (TLS) connection to Typha.  Typha must present a
	// certificate signed by a CA in CAFile, and with CN matching CN or URI SAN matching
	// URISAN.
	KeyFile  string
	CertFile string
	CAFile   string
	CN       string
	URISAN   string
}

// A Config structure is used to configure confd.
type Config struct {
	ConfDir        string `toml:"confdir"`
	Interval       int    `toml:"interval"`
	Noop           bool   `toml:"noop"`
	Prefix         string `toml:"prefix"`
	SyncOnly       bool   `toml:"sync-only"`
	CalicoConfig   string `toml:"calicoconfig"`
	Onetime        bool   `toml:"onetime"`
	KeepStageFile  bool   `toml:"keep-stage-file"`
	Typha          TyphaConfig
	TemplateConfig template.Config
}

func init() {
	flag.StringVar(&confdir, "confdir", "/etc/confd", "confd conf directory")
	flag.StringVar(&configFile, "config-file", "", "the confd config file")
	flag.IntVar(&interval, "interval", 600, "backend polling interval")
	flag.BoolVar(&keepStageFile, "keep-stage-file", false, "keep staged files")
	flag.BoolVar(&noop, "noop", false, "only show pending changes")
	flag.BoolVar(&onetime, "onetime", false, "run once and exit")
	flag.StringVar(&prefix, "prefix", "", "key path prefix")
	flag.BoolVar(&syncOnly, "sync-only", false, "sync without check_cmd and reload_cmd")
	flag.StringVar(&calicoconfig, "calicoconfig", "", "Calico apiconfig file path")
}

// InitConfig initializes the confd configuration by first setting defaults,
// then overriding settings from the confd config file, then overriding
// settings from environment variables, and finally overriding
// settings from flags set on the command line.
// It returns an error if any.
func InitConfig(ignoreFlags bool) (*Config, error) {
	if configFile == "" {
		if _, err := os.Stat(defaultConfigFile); !os.IsNotExist(err) {
			configFile = defaultConfigFile
		}
	}
	// Set defaults.
	config := Config{
		ConfDir:  "/etc/confd",
		Interval: 600,
		Prefix:   "",
		Typha: TyphaConfig{
			// Non-zero defaults copied from <felix>/config/config_params.go.
			K8sNamespace: "kube-system",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
	}
	// Update config from the TOML configuration file.
	if configFile == "" {
		log.Info("Skipping confd config file.")
	} else {
		log.Info("Loading " + configFile)
		configBytes, err := ioutil.ReadFile(configFile)
		if err != nil {
			return nil, err
		}
		_, err = toml.Decode(string(configBytes), &config)
		if err != nil {
			return nil, err
		}
	}

	if !ignoreFlags {
		// Update config from commandline flags.
		processFlags(&config)
	}

	if level := os.Getenv("BGP_LOGSEVERITYSCREEN"); level != "" {
		// If specified, use the provided log level.
		logutils.SetLevel(level)
	} else {
		// Default to info level logs.
		logutils.SetLevel("info")
	}

	// Read Typha settings from the environment.
	readTyphaConfig(&config.Typha)

	return &config, nil
}

func getBackendNodesFromSRV(record, scheme string) ([]string, error) {
	nodes := make([]string, 0)

	// Ignore the CNAME as we don't need it.
	_, addrs, err := net.LookupSRV("", "", record)
	if err != nil {
		return nodes, err
	}
	for _, srv := range addrs {
		host := strings.TrimRight(srv.Target, ".")
		port := strconv.FormatUint(uint64(srv.Port), 10)
		nodes = append(nodes, fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, port)))
	}
	return nodes, nil
}

// processFlags iterates through each flag set on the command line and
// overrides corresponding configuration settings.
func processFlags(config *Config) {
	log.Info("Processing command line flags")
	v := ConfigVisitor{config: config}
	flag.Visit(v.setConfigFromFlag)
}

type ConfigVisitor struct {
	config *Config
}

func (c *ConfigVisitor) setConfigFromFlag(f *flag.Flag) {
	switch f.Name {
	case "confdir":
		c.config.ConfDir = confdir
	case "interval":
		c.config.Interval = interval
	case "noop":
		c.config.Noop = noop
	case "prefix":
		c.config.Prefix = prefix
	case "sync-only":
		c.config.SyncOnly = syncOnly
	case "calicoconfig":
		c.config.CalicoConfig = calicoconfig
	case "onetime":
		c.config.Onetime = onetime
	case "keep-stage-file":
		c.config.Onetime = keepStageFile
	}
}

func readTyphaConfig(typhaConfig *TyphaConfig) {
	// When Typha is in use, there will already be variables prefixed with FELIX_, so it's
	// convenient if confd honours those too.  However there may use cases for confd to
	// have independent settings, so honour CONFD_ also.  Longer-term it would be nice to
	// coalesce around CALICO_, so support that as well.
	supportedPrefixes := []string{"CONFD_", "FELIX_", "CALICO_"}
	kind := reflect.TypeOf(*typhaConfig)
	for ii := 0; ii < kind.NumField(); ii++ {
		field := kind.Field(ii)
		nameUpper := strings.ToUpper(field.Name)
		for _, prefix := range supportedPrefixes {
			varName := prefix + "TYPHA" + nameUpper
			if value := os.Getenv(varName); value != "" && value != "none" {
				log.Infof("Found %v=%v", varName, value)
				if field.Type.Name() == "Duration" {
					seconds, err := strconv.ParseFloat(value, 64)
					if err != nil {
						log.Error("Invalid float")
					}
					duration := time.Duration(seconds * float64(time.Second))
					reflect.ValueOf(typhaConfig).Elem().FieldByName(field.Name).Set(reflect.ValueOf(duration))
				} else {
					reflect.ValueOf(typhaConfig).Elem().FieldByName(field.Name).Set(reflect.ValueOf(value))
				}
				break
			}
		}
	}
}
