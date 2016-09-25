// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	etcd "github.com/coreos/etcd/client"
	"github.com/coreos/etcd/pkg/transport"
	bgpapi "github.com/osrg/gobgp/api"
	bgpconfig "github.com/osrg/gobgp/config"
	bgp "github.com/osrg/gobgp/packet/bgp"
	bgpserver "github.com/osrg/gobgp/server"
	bgptable "github.com/osrg/gobgp/table"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
)

const (
	HOSTNAME          = "HOSTNAME"
	ETCD_SCHEME       = "ETCD_SCHEME"
	ETCD_AUTHORITY    = "ETCD_AUTHORITY"
	ETCD_KEY_FILE     = "ETCD_KEY_FILE"
	ETCD_CERT_FILE    = "ETCD_CERT_FILE"
	ETCD_CA_CERT_FILE = "ETCD_CA_CERT_FILE"
	IP                = "IP"
	IP6               = "IP6"
	CALICO_PREFIX     = "/calico"
	CALICO_BGP        = CALICO_PREFIX + "/bgp/v1"
	CALICO_AGGR       = CALICO_PREFIX + "/ipam/v2/host"

	defaultDialTimeout = 30 * time.Second
)

func underscore(ip string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '.', ':':
			return '_'
		}
		return r
	}, ip)
}

func errorButKeyNotFound(err error) error {
	if e, ok := err.(etcd.Error); ok && e.Code == etcd.ErrorCodeKeyNotFound {
		return nil
	}
	return err
}

func getTransport() (*http.Transport, error) {
	cafile := os.Getenv(ETCD_CA_CERT_FILE)
	certfile := os.Getenv(ETCD_CERT_FILE)
	keyfile := os.Getenv(ETCD_KEY_FILE)

	tls := transport.TLSInfo{
		CAFile:   cafile,
		CertFile: certfile,
		KeyFile:  keyfile,
	}
	return transport.NewTransport(tls, defaultDialTimeout)
}

func getGlobalASN(api etcd.KeysAPI) (uint32, error) {
	res, err := api.Get(context.Background(), fmt.Sprintf("%s/global/as_num", CALICO_BGP), nil)
	if err != nil {
		return 0, err
	}
	asn, err := strconv.ParseUint(res.Node.Value, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(asn), nil
}

func getPeerASN(api etcd.KeysAPI, host string) (uint32, error) {
	res, err := api.Get(context.Background(), fmt.Sprintf("%s/host/%s/as_num", CALICO_BGP, host), nil)
	if errorButKeyNotFound(err) != nil {
		return 0, err
	}
	if res != nil && res.Node != nil {
		v, err := strconv.ParseUint(res.Node.Value, 10, 32)
		if err != nil {
			return 0, err
		}
		return uint32(v), nil
	}
	return getGlobalASN(api)

}

func getGlobalConfig(api etcd.KeysAPI) (*bgpconfig.Global, error) {
	asn, err := getGlobalASN(api)
	if err != nil {
		return nil, err
	}
	return &bgpconfig.Global{
		Config: bgpconfig.GlobalConfig{
			As:       asn,
			RouterId: os.Getenv(IP),
		},
	}, nil
}

func isMeshMode(api etcd.KeysAPI) (bool, error) {
	res, err := api.Get(context.Background(), fmt.Sprintf("%s/global/node_mesh", CALICO_BGP), nil)
	if err != nil {
		return false, err
	}
	m := &struct {
		Enabled bool `json:"enabled"`
	}{}
	if err := json.Unmarshal([]byte(res.Node.Value), m); err != nil {
		return false, err
	}
	return m.Enabled, nil
}

func getMeshNeighborConfigs(api etcd.KeysAPI) ([]*bgpconfig.Neighbor, error) {
	globalASN, err := getGlobalASN(api)
	if err != nil {
		return nil, err
	}
	res, err := api.Get(context.Background(), fmt.Sprintf("%s/host", CALICO_BGP), &etcd.GetOptions{Recursive: true})
	if err != nil {
		return nil, err
	}
	ns := make([]*bgpconfig.Neighbor, 0, len(res.Node.Nodes))
	for _, node := range res.Node.Nodes {
		var v4, v6 string
		peerASN := globalASN
		for _, v := range node.Nodes {
			path := strings.Split(v.Key, "/")
			key := path[len(path)-1]
			switch key {
			case "ip_addr_v4":
				v4 = v.Value
				if v4 == os.Getenv(IP) {
					v4 = ""
				}
			case "ip_addr_v6":
				v6 = v.Value
				if v6 == os.Getenv(IP6) {
					v6 = ""
				}
			case "as_num":
				asn, err := strconv.ParseUint(v.Value, 10, 32)
				if err != nil {
					return nil, err
				}
				peerASN = uint32(asn)
			default:
				log.Printf("unhandled key: %s", v.Key)
			}
		}
		if v4 != "" {
			id := strings.Replace(v4, ".", "_", -1)
			ns = append(ns, &bgpconfig.Neighbor{
				Config: bgpconfig.NeighborConfig{
					NeighborAddress: v4,
					PeerAs:          peerASN,
					Description:     fmt.Sprintf("Mesh_%s", id),
				},
			})
		}
		if v6 != "" {
			id := strings.Replace(v4, ":", "_", -1)
			ns = append(ns, &bgpconfig.Neighbor{
				Config: bgpconfig.NeighborConfig{
					NeighborAddress: v6,
					PeerAs:          peerASN,
					Description:     fmt.Sprintf("Mesh_%s", id),
				},
			})
		}
	}
	return ns, nil

}

func getNeighborConfigFromPeer(node *etcd.Node, neighborType string) (*bgpconfig.Neighbor, error) {
	m := &struct {
		IP  string `json:"ip"`
		ASN string `json:"as_num"`
	}{}
	if err := json.Unmarshal([]byte(node.Value), m); err != nil {
		return nil, err
	}
	asn, err := strconv.ParseUint(m.ASN, 10, 32)
	if err != nil {
		return nil, err
	}
	return &bgpconfig.Neighbor{
		Config: bgpconfig.NeighborConfig{
			NeighborAddress: m.IP,
			PeerAs:          uint32(asn),
			Description:     fmt.Sprintf("%s_%s", strings.Title(neighborType), underscore(m.IP)),
		},
	}, nil
}

func getNonMeshNeighborConfigs(api etcd.KeysAPI, neighborType, version string) ([]*bgpconfig.Neighbor, error) {
	var key string
	switch neighborType {
	case "global":
		key = fmt.Sprintf("%s/global/peer_%s", CALICO_BGP, version)
	case "node":
		key = fmt.Sprintf("%s/host/%s/peer_%s", CALICO_BGP, os.Getenv(HOSTNAME), version)
	default:
		return nil, fmt.Errorf("invalid neighbor type: %s", neighborType)
	}
	res, err := api.Get(context.Background(), key, &etcd.GetOptions{Recursive: true})
	if errorButKeyNotFound(err) != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	ns := make([]*bgpconfig.Neighbor, 0, len(res.Node.Nodes))
	for _, node := range res.Node.Nodes {
		var n *bgpconfig.Neighbor
		if n, err = getNeighborConfigFromPeer(node, neighborType); err != nil {
			return nil, err
		}
		ns = append(ns, n)
	}
	return ns, nil
}

func getGlobalNeighborConfigs(api etcd.KeysAPI) ([]*bgpconfig.Neighbor, error) {
	v4s, err := getNonMeshNeighborConfigs(api, "global", "v4")
	if err != nil {
		return nil, err
	}
	v6s, err := getNonMeshNeighborConfigs(api, "global", "v6")
	if err != nil {
		return nil, err
	}
	return append(v4s, v6s...), nil
}

func getNodeSpecificNeighborConfigs(api etcd.KeysAPI) ([]*bgpconfig.Neighbor, error) {
	v4s, err := getNonMeshNeighborConfigs(api, "node", "v4")
	if err != nil {
		return nil, err
	}
	v6s, err := getNonMeshNeighborConfigs(api, "node", "v6")
	if err != nil {
		return nil, err
	}
	return append(v4s, v6s...), nil
}

func getNeighborConfigs(api etcd.KeysAPI) ([]*bgpconfig.Neighbor, error) {
	var neighbors []*bgpconfig.Neighbor
	// --- Node-to-node mesh ---
	if mesh, err := isMeshMode(api); err == nil && mesh {
		ns, err := getMeshNeighborConfigs(api)
		if err != nil {
			return nil, err
		}
		neighbors = append(neighbors, ns...)
	} else if err != nil {
		return nil, err
	}
	// --- Global peers ---
	if ns, err := getGlobalNeighborConfigs(api); err != nil {
		return nil, err
	} else {
		neighbors = append(neighbors, ns...)
	}
	// --- Node-specific peers ---
	if ns, err := getNodeSpecificNeighborConfigs(api); err != nil {
		return nil, err
	} else {
		neighbors = append(neighbors, ns...)
	}
	return neighbors, nil
}

func makePath(key string, isWithdrawal bool) (*bgptable.Path, error) {
	path := strings.Split(key, "/")
	elems := strings.Split(path[len(path)-1], "-")
	if len(elems) != 2 {
		return nil, fmt.Errorf("invalid prefix format: %s", path[len(path)-1])
	}
	prefix := elems[0]
	masklen, err := strconv.ParseUint(elems[1], 10, 8)
	if err != nil {
		return nil, err
	}

	p := net.ParseIP(prefix)
	v4 := true
	if p == nil {
		return nil, fmt.Errorf("invalid prefix format: %s", key)
	} else if p.To4() == nil {
		v4 = false
	}

	var nlri bgp.AddrPrefixInterface
	if v4 {
		nlri = bgp.NewIPAddrPrefix(uint8(masklen), prefix)
	} else {
		nlri = bgp.NewIPv6AddrPrefix(uint8(masklen), prefix)
	}

	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
	}

	if v4 {
		attrs = append(attrs, bgp.NewPathAttributeNextHop(os.Getenv(IP)))
	} else {
		attrs = append(attrs, bgp.NewPathAttributeMpReachNLRI(os.Getenv(IP6), []bgp.AddrPrefixInterface{nlri}))
	}

	return bgptable.NewPath(nil, nlri, isWithdrawal, attrs, time.Now(), false), nil
}

func getAssignedPrefixes(api etcd.KeysAPI) ([]*bgptable.Path, error) {
	var ps []*bgptable.Path
	f := func(version string) error {
		res, err := api.Get(context.Background(), fmt.Sprintf("%s/%s/%s/block", CALICO_AGGR, os.Getenv(HOSTNAME), version), &etcd.GetOptions{Recursive: true})
		if err != nil {
			return err
		}
		for _, v := range res.Node.Nodes {
			path, err := makePath(v.Key, false)
			if err != nil {
				return err
			}
			ps = append(ps, path)
		}
		return nil
	}
	if os.Getenv(IP) != "" {
		if err := f("ipv4"); err != nil {
			return nil, err
		}
	}
	if os.Getenv(IP6) != "" {
		if err := f("ipv6"); err != nil {
			return nil, err
		}
	}
	return ps, nil
}

func watchPrefix(api etcd.KeysAPI, bgpServer *bgpserver.BgpServer) error {
	watcher := api.Watcher(fmt.Sprintf("%s/%s", CALICO_AGGR, os.Getenv(HOSTNAME)), &etcd.WatcherOptions{Recursive: true})
	for {
		var err error
		res, err := watcher.Next(context.Background())
		if err != nil {
			return err
		}
		var path *bgptable.Path
		if res.Action == "delete" {
			path, err = makePath(res.Node.Key, true)
		} else {
			path, err = makePath(res.Node.Key, false)
		}
		if err != nil {
			return err
		}
		if _, err := bgpServer.AddPath("", []*bgptable.Path{path}); err != nil {
			return err
		}
		log.Printf("add path: %s", path)
	}
}

func watchBGPConfig(api etcd.KeysAPI, bgpServer *bgpserver.BgpServer) error {
	watcher := api.Watcher(fmt.Sprintf("%s", CALICO_BGP), &etcd.WatcherOptions{
		Recursive: true,
	})
	for {
		res, err := watcher.Next(context.Background())
		if err != nil {
			return err
		}
		log.Printf("watch: %v", res)

		handleNonMeshNeighbor := func(neighborType string) error {
			switch res.Action {
			case "delete":
				n, err := getNeighborConfigFromPeer(res.PrevNode, neighborType)
				if err != nil {
					return err
				}
				return bgpServer.DeleteNeighbor(n)
			case "set":
				n, err := getNeighborConfigFromPeer(res.Node, neighborType)
				if err != nil {
					return err
				}
				return bgpServer.AddNeighbor(n)
			}
			log.Printf("unhandled action: %s", res.Action)
			return nil
		}

		key := res.Node.Key
		switch {
		case strings.HasPrefix(key, fmt.Sprintf("%s/global/peer_", CALICO_BGP)):
			err = handleNonMeshNeighbor("global")
		case strings.HasPrefix(key, fmt.Sprintf("%s/host/%s/peer_", CALICO_BGP, os.Getenv(HOSTNAME))):
			err = handleNonMeshNeighbor("node")
		case strings.HasPrefix(key, fmt.Sprintf("%s/host/%s", CALICO_BGP, os.Getenv(HOSTNAME))):
			log.Println("Local host config update. Restart")
			os.Exit(1)
		case strings.HasPrefix(key, fmt.Sprintf("%s/host", CALICO_BGP)):
			elems := strings.Split(key, "/")
			if len(elems) < 4 {
				log.Printf("unhandled key: %s", key)
				continue
			}
			deleteNeighbor := func(node *etcd.Node) error {
				n := &bgpconfig.Neighbor{
					Config: bgpconfig.NeighborConfig{
						NeighborAddress: node.Value,
					},
				}
				return bgpServer.DeleteNeighbor(n)
			}
			host := elems[len(elems)-2]
			switch elems[len(elems)-1] {
			case "ip_addr_v4", "ip_addr_v6":
				switch res.Action {
				case "delete":
					if err = deleteNeighbor(res.PrevNode); err != nil {
						return err
					}
				case "set":
					if res.PrevNode != nil {
						if err = deleteNeighbor(res.PrevNode); err != nil {
							return err
						}
					}
					asn, err := getPeerASN(api, host)
					if err != nil {
						return err
					}
					n := &bgpconfig.Neighbor{
						Config: bgpconfig.NeighborConfig{
							NeighborAddress: res.Node.Value,
							PeerAs:          asn,
							Description:     fmt.Sprintf("Mesh_%s", underscore(res.Node.Value)),
						},
					}
					if err = bgpServer.AddNeighbor(n); err != nil {
						return err
					}
				}
			case "as_num":
				var asn uint32
				if res.Action == "set" {
					v, err := strconv.ParseUint(res.Node.Value, 10, 32)
					if err != nil {
						return err
					}
					asn = uint32(v)
				} else {
					asn, err = getGlobalASN(api)
					if err != nil {
						return err
					}
				}
				for _, version := range []string{"v4", "v6"} {
					res, err := api.Get(context.Background(), fmt.Sprintf("%s/host/%s/ip_addr_%s", CALICO_BGP, host, version), nil)
					if errorButKeyNotFound(err) != nil {
						return err
					}
					if res == nil {
						continue
					}
					if err = deleteNeighbor(res.Node); err != nil {
						return err
					}
					ip := res.Node.Value
					n := &bgpconfig.Neighbor{
						Config: bgpconfig.NeighborConfig{
							NeighborAddress: ip,
							PeerAs:          asn,
							Description:     fmt.Sprintf("Mesh_%s", underscore(ip)),
						},
					}
					if err = bgpServer.AddNeighbor(n); err != nil {
						return err
					}
				}
			default:
				log.Printf("unhandled key: %s", key)
			}
		case strings.HasPrefix(key, fmt.Sprintf("%s/global/as_num", CALICO_BGP)):
			log.Println("Global AS number update. Restart")
			os.Exit(1)
		case strings.HasPrefix(key, fmt.Sprintf("%s/global/node_mesh", CALICO_BGP)):
			mesh, err := isMeshMode(api)
			if err != nil {
				return err
			}
			ns, err := getMeshNeighborConfigs(api)
			if err != nil {
				return err
			}
			for _, n := range ns {
				if mesh {
					err = bgpServer.AddNeighbor(n)
				} else {
					err = bgpServer.DeleteNeighbor(n)
				}
				if err != nil {
					return err
				}
			}
		}
		if err != nil {
			return err
		}
	}
}

func injectRoute(path *bgptable.Path) error {
	nexthop := path.GetNexthop()
	nlri := path.GetNlri()
	var family int
	var d string

	switch f := path.GetRouteFamily(); f {
	case bgp.RF_IPv4_UC:
		family = netlink.FAMILY_V4
		d = "0.0.0.0/0"
	case bgp.RF_IPv6_UC:
		family = netlink.FAMILY_V6
		d = "::/0"
	default:
		log.Printf("only supports injecting ipv4/ipv6 unicast route: %s", f)
		return nil
	}

	dst, _ := netlink.ParseIPNet(nlri.String())
	route := &netlink.Route{
		Dst: dst,
		Gw:  nexthop,
	}
	routes, _ := netlink.RouteList(nil, family)
	for _, route := range routes {
		if route.Dst != nil {
			d = route.Dst.String()
		}
		if d == dst.String() {
			err := netlink.RouteDel(&route)
			if err != nil {
				return err
			}
		}
	}
	if path.IsWithdraw {
		log.Printf("removed route %s from kernel", nlri)
		return nil
	}
	log.Printf("added route %s to kernel", nlri)
	return netlink.RouteAdd(route)
}

func monitorPath(watcher *bgpserver.Watcher) error {
	for {
		ev := <-watcher.Event()
		msg, ok := ev.(*bgpserver.WatchEventBestPath)
		if !ok {
			continue
		}
		for _, path := range msg.PathList {
			if path.IsLocal() {
				continue
			}
			if err := injectRoute(path); err != nil {
				return err
			}
		}
	}
}

func main() {

	logrus.SetLevel(logrus.DebugLevel)

	etcdAuthority := os.Getenv(ETCD_AUTHORITY)
	etcdScheme := os.Getenv(ETCD_SCHEME)
	if etcdScheme == "" {
		etcdScheme = "http"
	}

	transport, err := getTransport()
	if err != nil {
		log.Fatal(err)
	}

	config := etcd.Config{
		Endpoints: []string{fmt.Sprintf("%s://%s", etcdScheme, etcdAuthority)},
		Transport: transport,
	}

	cli, err := etcd.New(config)
	if err != nil {
		log.Fatal(err)
	}

	bgpServer := bgpserver.NewBgpServer()
	go bgpServer.Serve()

	bgpAPIServer := bgpapi.NewGrpcServer(bgpServer, ":50051")
	go bgpAPIServer.Serve()

	api := etcd.NewKeysAPI(cli)
	globalConfig, err := getGlobalConfig(api)
	if err != nil {
		log.Fatal(err)
	}

	if err := bgpServer.Start(globalConfig); err != nil {
		log.Fatal(err)
	}

	watcher := bgpServer.Watch(bgpserver.WatchBestPath())
	go func() {
		log.Fatal(monitorPath(watcher))
	}()

	paths, err := getAssignedPrefixes(api)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := bgpServer.AddPath("", paths); err != nil {
		log.Fatal(err)
	}

	go func() {
		log.Fatal(watchPrefix(api, bgpServer))
	}()

	neighborConfigs, err := getNeighborConfigs(api)
	if err != nil {
		log.Fatal(err)
	}

	for _, n := range neighborConfigs {
		if err = bgpServer.AddNeighbor(n); err != nil {
			log.Fatal(err)
		}
	}

	go func() {
		log.Fatal(watchBGPConfig(api, bgpServer))
	}()

	ch := make(chan struct{})
	<-ch
}
