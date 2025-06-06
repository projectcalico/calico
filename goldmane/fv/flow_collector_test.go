package fv

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	goproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/goldmane/pkg/server"
	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

type testSink struct {
	sync.Mutex
	flows []*types.Flow
}

func (t *testSink) Receive(f *types.Flow) {
	t.Lock()
	defer t.Unlock()
	t.flows = append(t.flows, f)
}

func (t *testSink) flowReceivedFn(flow *proto.Flow) func() bool {
	return func() bool {
		t.Lock()
		defer t.Unlock()

		for _, f := range t.flows {
			if goproto.Equal(flow, types.FlowToProto(f)) {
				return true
			}
		}
		return false
	}
}

var (
	sink      *testSink
	collector server.FlowCollectorService
	cli       *client.FlowClient
	srv       *grpc.Server
	lis       net.Listener
)

type ServerSetupOption bool

const (
	StartServer ServerSetupOption = true
	NoServer    ServerSetupOption = false
)

func setupServer(t *testing.T) func() {
	// Configure the collector with a mock sink.
	sink = &testSink{}
	srv = grpc.NewServer()
	collector = server.NewFlowCollector(sink)
	collector.RegisterWith(srv)

	// Start the server. It will block until the listen socket is closed,
	// so run it in a goroutine.
	go func() {
		require.NoError(t, srv.Serve(lis))
	}()

	return func() {
		srv.Stop()
	}
}

// setupTest sets up a test environment for flow collection. If startServer is true, it will also start a server.
func setupTest(t *testing.T, srvOption ServerSetupOption) func() {
	// Register gomega with test.
	RegisterTestingT(t)
	logrus.SetLevel(logrus.DebugLevel)
	logCancel := logutils.RedirectLogrusToTestingT(t)

	// Create a socket listener.
	var err error
	lis, err = newSocketListener()
	require.NoError(t, err)

	var teardownServer func()
	if srvOption {
		// Start the server if configured to do so.
		teardownServer = setupServer(t)
	}

	// Create a new flow collector client.
	cli, err = client.NewFlowClient("unix://"+lis.Addr().String(), "", "", "")
	require.NoError(t, err)
	require.NotNil(t, cli)

	return func() {
		if teardownServer != nil {
			teardownServer()
		}
		lis.Close()
		logCancel()
		cli.Close()
	}
}

func newSocketListener() (net.Listener, error) {
	// Create a tmp file.
	d := os.TempDir()

	sock := fmt.Sprintf("%s/goldmane.sock", d)
	logrus.WithField("socket", sock).Info("Creating socket for test server")

	// Create a new listener on a local socket.
	return net.Listen("unix", sock)
}

// TestFlowCollection verifies that the client can send a flow to the server and that the server receives it.
func TestFlowCollection(t *testing.T) {
	defer setupTest(t, StartServer)()

	// Connect to the server. The entire test should complete within 5 seconds.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connected := cli.Connect(ctx)
	select {
	case <-connected:
		logrus.Info("Connected to server")
	case <-ctx.Done():
		require.Fail(t, "Timed out waiting for server connection")
	}

	// Send a flow update to the server.
	flow := testutils.NewRandomFlow(400)
	cli.Push(types.ProtoToFlow(flow))

	// Expect that it shows up in the Sink.
	require.Eventually(t, sink.flowReceivedFn(flow), 1*time.Second, 100*time.Millisecond, "Flow did not show up in sink")
}

// TestResyncOnConnect verifies that the client resends all flows that it is aware of when it reconnects to the server.
func TestResyncOnConnect(t *testing.T) {
	defer setupTest(t, NoServer)()

	// Create a bunch of flows.
	var flows []*proto.Flow
	for i := range 100 {
		flow := testutils.NewRandomFlow(int64(i))
		flows = append(flows, flow)
		cli.Push(types.ProtoToFlow(flow))
	}

	// Connect to the server. The entire test should complete within 5 seconds.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// We don't expect to connect on the first go, since the server is down.
	_ = cli.Connect(ctx)

	// The sink should not receive the flow yet, since the server is down.
	require.Never(t, sink.flowReceivedFn(flows[0]), 1*time.Second, 100*time.Millisecond, "Flow should not have been received yet")

	// Start a server, and expect the client to connect and send the flow.
	defer setupServer(t)()

	// We expect the client to reconnect and send the buffered flow.
	for _, flow := range flows {
		require.Eventually(t, sink.flowReceivedFn(flow), 5*time.Second, 100*time.Millisecond, "Flow did not show up in sink")
	}
}
