package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	nam "github.com/colabsaumoh/proto-udsuspver/nodeagentmgmt"
	wlh "github.com/colabsaumoh/proto-udsuspver/workloadhandler"
	mwi "github.com/colabsaumoh/proto-udsuspver/mgmtwlhintf"
	wlapi "github.com/colabsaumoh/proto-udsuspver/workloadapi"
)

const (
	MgmtApiPath        string = "/tmp/udsuspver/mgmt.sock"
	WorkloadApiUdsHome string = "/tmp/nodeagent"
)

var (
	CfgMgmtApiPath   string
	CfgWldApiUdsHome string

	RootCmd = &cobra.Command{
		Use:   "nodeagent",
		Short: "Node agent with both mgmt and workload api interfaces.",
		Long:  "Node agent with both mgmt and workload api interfaces.",
	}
)

func init() {
	RootCmd.PersistentFlags().StringVarP(&CfgMgmtApiPath, "mgmtpath", "m", MgmtApiPath, "Mgmt API Uds path")
	RootCmd.PersistentFlags().StringVarP(&CfgWldApiUdsHome, "wldpath", "w", WorkloadApiUdsHome, "Workload API home path")
}

func MgmtApi() {
	// initialize the workload api.
	wl := wlapi.NewWlAPIServer()
	// initialize the workload api handler with the workload api.
	wli := mwi.NewWlHandler(wl, wlh.NewServer)
	// finally initialize the node mgmt interface with workload handler.
	mgmtServer := nam.NewServer(CfgWldApiUdsHome, wli)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func(s *nam.Server, c chan os.Signal) {
		<-c
		s.Stop()
		s.WaitDone()
		os.Exit(1)
	}(mgmtServer, sigc)

	mgmtServer.Serve(true, CfgMgmtApiPath)
}

func main() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal(err)
	}

	// Check if the base directory exisits
	_, e := os.Stat(WorkloadApiUdsHome)
	if e != nil {
		log.Fatalf("WorkloadApi Directory not present (%v)", WorkloadApiUdsHome)
	}

	MgmtApi()

}
