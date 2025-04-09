package flowlogs

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/projectcalico/calico/felix/collector/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/sirupsen/logrus"
)

func StartServerAndWatch() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err := ensureGoldmaneSocketDirectory(goldmane.LocalGoldmaneServer)
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
		if ctx.Err() != nil {
			logrus.Info("Closing goldmane unix server")
			cleanupGoldmaneSocket()
			return
		}
		flows := nodeServer.ListAndFlush()
		for _, flow := range flows {
			fmt.Printf("%s\n", flowToString(flow))
		}
		time.Sleep(time.Second)
	}
}

func flowToString(f *types.Flow) string {
	output := fmt.Sprintf("Src={%s(%s/%s) %vP %vB} Dst={%s(%s/%s) %vP %vB} Proto=%s(%v) Action=%v",
		endpointTypeToString(f.Key.SourceType()), f.Key.SourceNamespace(), f.Key.SourceName(), f.PacketsIn, f.BytesIn,
		endpointTypeToString(f.Key.DestType()), f.Key.DestNamespace(), f.Key.DestName(), f.PacketsOut, f.BytesOut,
		f.Key.Proto(), f.Key.DestPort(),
		f.Key.Action(),
	)

	return output
}

func endpointTypeToString(ep proto.EndpointType) string {
	switch ep {
	case proto.EndpointType_WorkloadEndpoint:
		return "wep"
	case proto.EndpointType_HostEndpoint:
		return "hep"
	case proto.EndpointType_NetworkSet:
		return "ns"
	case proto.EndpointType_Network:
		return "net"
	default:
		panic(fmt.Sprintf("Unexpected endpoint type: %v", ep))
	}
}

func ensureGoldmaneSocketDirectory(addr string) error {
	path := path.Dir(addr)
	// Check if goldmane unix server exists at the expected location.
	logrus.Info("Checking if goldmane unix server exists.")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logrus.WithField("path", path).Info("Goldmane unix socket directory does not exist.")
		err := os.MkdirAll(path, 0o600)
		if err != nil {
			return err
		}
		logrus.WithField("path", path).Info("Created goldmane unix server directory.")
	}
	return nil
}

func cleanupGoldmaneSocket() {
	if goldmane.NodeSocketExists() {
		err := os.Remove(goldmane.LocalGoldmaneServer)
		if err != nil {
			logrus.WithError(err).Errorf("Failed to remove goldmane node socket")
		}
	}
}
