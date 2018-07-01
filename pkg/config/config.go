package config

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/kelseyhightower/confd/pkg/backends"
	logutils "github.com/kelseyhightower/confd/pkg/log"
	"github.com/kelseyhightower/confd/pkg/resource/template"
	log "github.com/sirupsen/logrus"
)

var (
	configFile        = ""
	defaultConfigFile = "/etc/confd/confd.toml"
	confdir           string
	// config            Config // holds the global confd config.
	interval       int
	keepStageFile  bool
	noop           bool
	onetime        bool
	prefix         string
	syncOnly       bool
	calicoconfig   string
	routereflector bool
)

// A Config structure is used to configure confd.
type Config struct {
	ConfDir        string `toml:"confdir"`
	Interval       int    `toml:"interval"`
	Noop           bool   `toml:"noop"`
	Prefix         string `toml:"prefix"`
	SyncOnly       bool   `toml:"sync-only"`
	CalicoConfig   string `toml:"calicoconfig"`
	RouteReflector bool   `toml:"routereflector"`
	Onetime        bool   `toml:"onetime"`
	KeepStageFile  bool   `toml:"keep-stage-file"`
	TemplateConfig template.Config
	BackendsConfig backends.Config
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
	flag.BoolVar(&routereflector, "routereflector", false, "generate config for a route reflector")
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
	case "routereflector":
		c.config.RouteReflector = routereflector
	case "onetime":
		c.config.Onetime = onetime
	case "keep-stage-file":
		c.config.Onetime = keepStageFile
	}
}
