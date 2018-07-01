package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/kelseyhightower/confd/pkg/config"
	"github.com/kelseyhightower/confd/pkg/run"
	log "github.com/sirupsen/logrus"
)

var VERSION string

var (
	printVersion bool
)

func main() {
	flag.BoolVar(&printVersion, "version", false, "print version and exit")
	flag.Parse()
	if printVersion {
		fmt.Printf("confd %s\n", VERSION)
		os.Exit(0)
	}

	c, err := config.InitConfig(false)
	if err != nil {
		log.Fatal(err.Error())
	}

	// Run confd.
	run.Run(c)
}
