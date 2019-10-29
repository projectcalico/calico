package commands

import (
	"fmt"
	"net"
	"testing"

	"github.com/projectcalico/felix/bpf/proxy/maps"
)

func TestNATDump(t *testing.T) {
	nat := maps.NATMapMem{
		maps.NewNATKey(net.IPv4(1, 1, 1, 1), 80, 6):   maps.NewNATValue(35, 2),
		maps.NewNATKey(net.IPv4(2, 1, 1, 1), 553, 17): maps.NewNATValue(107, 1),
		maps.NewNATKey(net.IPv4(3, 1, 1, 1), 553, 17): maps.NewNATValue(108, 1),
	}

	back := maps.NATBackendMapMem{
		maps.NewNATBackendKey(35, 0):  maps.NewNATBackendValue(net.IPv4(5, 5, 5, 5), 8080),
		maps.NewNATBackendKey(35, 1):  maps.NewNATBackendValue(net.IPv4(6, 6, 6, 6), 8080),
		maps.NewNATBackendKey(108, 0): maps.NewNATBackendValue(net.IPv4(3, 3, 3, 3), 553),
	}

	dumpNice(func(format string, i ...interface{}) { fmt.Printf(format, i...) }, nat, back)
}
