package run

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/kelseyhightower/confd/pkg/backends"
	"github.com/kelseyhightower/confd/pkg/config"
	"github.com/kelseyhightower/confd/pkg/resource/template"
	log "github.com/sirupsen/logrus"
)

func Run(config *config.Config) {
	log.Info("Starting calico-confd")
	backendConfig := backends.Config{
		Calicoconfig:   config.CalicoConfig,
		RouteReflector: config.RouteReflector,
	}
	storeClient, err := backends.New(backendConfig)
	if err != nil {
		log.Fatal(err.Error())
	}

	templateConfig := template.Config{
		ConfDir:       config.ConfDir,
		ConfigDir:     filepath.Join(config.ConfDir, "conf.d"),
		KeepStageFile: config.KeepStageFile,
		Noop:          config.Noop,
		Prefix:        config.Prefix,
		SyncOnly:      config.SyncOnly,
		TemplateDir:   filepath.Join(config.ConfDir, "templates"),
		StoreClient:   storeClient,
	}
	if config.Onetime {
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
