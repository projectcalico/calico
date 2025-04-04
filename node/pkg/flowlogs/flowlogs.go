package flowlogs

import (
	"fmt"
	"os"
	"path"
	"time"

	"github.com/projectcalico/calico/felix/collector/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/sirupsen/logrus"
)

func StartServerAndWatch() {
	err := ensureGoldmaneServerDirectory(goldmane.LocalGoldmaneServer)
	if err != nil {
		logrus.WithError(err).Error("Failed to create goldmane unix server")
		return
	}
	nodeServer := goldmane.NewNodeServer(goldmane.LocalGoldmaneServer)
	err = nodeServer.Run()
	if err != nil {
		logrus.WithError(err).Error("Failed to start node local goldmane server")
		return
	}

	for {
		flows := nodeServer.ListAndFlush()
		printFlows(flows)

		time.Sleep(time.Second)
	}
}

func printFlows(flows []*types.Flow) {
	for _, f := range flows {
		fmt.Printf("Src={NS: %s EP:%s PKT:%v BYTE:%v} Dst={NS:%s EP:%s PKT:%v BYTES:%v}\n",
			f.Key.SourceNamespace(), f.Key.SourceName(), f.PacketsIn, f.BytesIn,
			f.Key.DestNamespace(), f.Key.DestNamespace(), f.PacketsOut, f.BytesOut)
	}
}

func ensureGoldmaneServerDirectory(addr string) error {
	path := path.Dir(addr)
	// Check if goldmane unix server exists at the expected location.
	logrus.Info("Checking if goldmane unix server exists.")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logrus.WithField("path", path).Info("Goldmane unix server directory does not exist.")
		err := os.MkdirAll(path, 0o600)
		if err != nil {
			return err
		}
		logrus.WithField("path", path).Info("Created goldmane unix server directory.")
	}
	return nil
}
