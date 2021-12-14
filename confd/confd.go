package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/projectcalico/calico/confd/pkg/buildinfo"
	"github.com/projectcalico/calico/confd/pkg/config"
	"github.com/projectcalico/calico/confd/pkg/run"
	log "github.com/sirupsen/logrus"
)

var (
	printVersion bool
)

func main() {
	flag.BoolVar(&printVersion, "version", false, "print version and exit")
	flag.Parse()
	if printVersion {
		fmt.Printf("confd %s\n", buildinfo.GitVersion)
		os.Exit(0)
	}

	c, err := config.InitConfig(false)
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Infof("Config: %#v", c)

	// Run confd.
	run.Run(c)
}
