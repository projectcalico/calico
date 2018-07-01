package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kelseyhightower/confd/pkg/backends"
	"github.com/kelseyhightower/confd/pkg/resource/template"
	log "github.com/sirupsen/logrus"
)

var VERSION string

func main() {
	flag.Parse()
	if printVersion {
		fmt.Printf("confd %s\n", VERSION)
		os.Exit(0)
	}
	if err := initConfig(); err != nil {
		log.Fatal(err.Error())
	}

	log.Info("Starting calico-confd")
	storeClient, err := backends.New(backendsConfig)
	if err != nil {
		log.Fatal(err.Error())
	}

	templateConfig.StoreClient = storeClient
	if onetime {
		if err := template.Process(templateConfig); err != nil {
			log.Fatal(err.Error())
		}
		os.Exit(0)
	}

	stopChan := make(chan bool)
	doneChan := make(chan bool)
	errChan := make(chan error, 10)

	processor := template.WatchProcessor(templateConfig, stopChan, doneChan, errChan)
	go processor.Process()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case err := <-errChan:
			log.Error(err.Error())
		case s := <-signalChan:
			log.Info(fmt.Sprintf("Captured %v. Exiting...", s))
			close(doneChan)
		case <-doneChan:
			os.Exit(0)
		}
	}
}
