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
	CALICO_PREFIX     = "/calico"
	CALICO_BGP        = CALICO_PREFIX + "/bgp/v1"
	CALICO_AGGR       = CALICO_PREFIX + "/ipam/v2/host"

	defaultDialTimeout = 30 * time.Second
)

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

func getNeighborConfigs(api etcd.KeysAPI) ([]*bgpconfig.Neighbor, error) {
	res, err := api.Get(context.Background(), fmt.Sprintf("%s/global/node_mesh", CALICO_BGP), nil)
	if err != nil {
		return nil, err
	}
	m := &struct {
		Enabled bool `json:"enabled"`
	}{}
	if err := json.Unmarshal([]byte(res.Node.Value), m); err != nil {
		return nil, err
	}
	if m.Enabled {
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
					if v6 == os.Getenv(IP) {
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
				ns = append(ns, &bgpconfig.Neighbor{
					Config: bgpconfig.NeighborConfig{
						NeighborAddress: v4,
						PeerAs:          peerASN,
					},
				})
			}
			if v6 != "" {
				ns = append(ns, &bgpconfig.Neighbor{
					Config: bgpconfig.NeighborConfig{
						NeighborAddress: v6,
						PeerAs:          peerASN,
					},
				})
			}
		}
		return ns, nil
	}
	return nil, nil
}

func makePath(key string, isWithdrawal bool) (*bgptable.Path, error) {

	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop(os.Getenv(IP)),
	}

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
	return bgptable.NewPath(nil, bgp.NewIPAddrPrefix(uint8(masklen), prefix), isWithdrawal, attrs, time.Now(), false), nil
}

func getAssignedPrefixes(api etcd.KeysAPI) ([]*bgptable.Path, error) {
	res, err := api.Get(context.Background(), fmt.Sprintf("%s/%s/ipv4/block", CALICO_AGGR, os.Getenv(HOSTNAME)), &etcd.GetOptions{Recursive: true})
	if err != nil {
		return nil, err
	}

	ps := make([]*bgptable.Path, 0, len(res.Node.Nodes))
	for _, v := range res.Node.Nodes {
		path, err := makePath(v.Key, false)
		if err != nil {
			return nil, err
		}
		ps = append(ps, path)
	}
	return ps, nil
}

func watchPrefix(api etcd.KeysAPI, bgpServer *bgpserver.BgpServer) error {
	watcher := api.Watcher(fmt.Sprintf("%s/%s/ipv4/block", CALICO_AGGR, os.Getenv(HOSTNAME)), &etcd.WatcherOptions{Recursive: true})
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

func watchNeighbor(api etcd.KeysAPI, bgpServer *bgpserver.BgpServer) error {
	watcher := api.Watcher(fmt.Sprintf("%s/host", CALICO_BGP), &etcd.WatcherOptions{Recursive: true})
	for {
		res, err := watcher.Next(context.Background())
		if err != nil {
			return err
		}
		log.Printf("watch neighbor: %v", res)
	}
}

func injectRoute(path *bgptable.Path) error {
	nexthop := path.GetNexthop()
	nlri := path.GetNlri()

	dst, _ := netlink.ParseIPNet(nlri.String())
	route := &netlink.Route{
		Dst: dst,
		Gw:  nexthop,
	}
	routes, _ := netlink.RouteList(nil, netlink.FAMILY_V4)
	for _, route := range routes {
		d := "0.0.0.0/0"
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
		log.Fatal(watchNeighbor(api, bgpServer))
	}()

	ch := make(chan struct{})
	<-ch
}
