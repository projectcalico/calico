// Copyright (c) 2016 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package node

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	"github.com/docopt/docopt-go"
	"golang.org/x/net/context"

	"github.com/olekukonko/tablewriter"
)

// Check for Word_<IP> where every octate is seperated by "_", regardless of IP protocols
// Example match: "Mesh_192_168_56_101"
var bgpPeerRegex, _ = regexp.Compile(`\w+_\d+_\d+_\d+_\d+`)

// Status prings status of the node and returns error (if any)
func Status(args []string) error {
	doc := `Usage:
calicoctl node status

Description:
  Display the status of the Calico node`

	// Note: This call is ignoring the error because error check happens at the level above
	// i.e at `node.go` before it calls `node.Status`. This call is just so help message gets
	// printed for this option
	_, _ = docopt.Parse(doc, args, true, "calicoctl", false, false)

	ctx := context.Background()

	if os.Getenv("DOCKER_API_VERSION") == "" {
		err := os.Setenv("DOCKER_API_VERSION", "1.16")
		if err != nil {
			log.Fatalf("Error setting DOCKER_API_VERSION: %v", err)
		}
	}

	dockerClient, err := client.NewEnvClient()
	if err != nil {
		return err
	}

	options := types.ContainerListOptions{All: true}
	containers, err := dockerClient.ContainerList(ctx, options)
	if err != nil {
		log.Fatalf("Error getting the container list: %v", err)
	}

	for _, c := range containers {
		if strings.Contains(c.Names[0], "calico-node") && c.State == "running" {

			fmt.Printf("calico-node container is running. Status: %s\n", c.Status)

			if os.Getuid() != 0 {
				fmt.Println("This command must be run as root.")
				os.Exit(1)
			}

			// Connect to the bird socket and get the data if calico-node container is running
			c, err := net.Dial("unix", "/var/run/calico/bird.ctl")
			if err != nil {
				log.Fatalf("Error connecting to the BIRD socket: %v", err)
			}
			defer c.Close()

			fmt.Println()

			_, _ = c.Write([]byte("show protocols\n"))
			if err != nil {
				log.Fatal("Error writing to BIRD socket:", err)
			}
			printBIRDResponse(c)

			return nil
		}
	}

	// Return and print message if calico-node is not running
	fmt.Println("calico-node container not running")
	return nil
}

func printBIRDResponse(r io.Reader) {
	buf := make([]byte, 1024)

	n, err := r.Read(buf[:])
	if err != nil {
		return
	}

	resp := string(buf[:n])
	drawTable(resp)
}

func drawTable(birdOut string) {
	data := [][]string{}

	ipSep := "."

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Peer address", "Peer type", "State", "Since", "Info"})

	for _, line := range strings.Split(birdOut, "\n") {

		s := bgpPeerRegex.FindString(line)

		if s != "" {
			col := []string{}
			fields := strings.Fields(line)[3:6]
			if strings.HasPrefix(s, "Mesh_") {
				s = s[5:]
				s = strings.Replace(s, "_", ipSep, -1)
				col = append(col, s)
				col = append(col, "node-to-node mesh")
				col = append(col, fields...)
			} else if strings.HasPrefix(s, "Node_") {
				s = s[5:]
				s = strings.Replace(s, "_", ipSep, -1)
				col = append(col, s)
				col = append(col, "node specific")
				col = append(col, fields...)
			} else if strings.HasPrefix(s, "Global_") {
				s = s[7:]
				s = strings.Replace(s, "_", ipSep, -1)
				col = append(col, s)
				col = append(col, "global")
				col = append(col, fields...)
			} else {
				// Did not match any of the pre-defined options for BIRD
				fmt.Println(errors.New("Error: Did not match any of the predefined options for BIRD"))
				break
			}
			data = append(data, col)
		}
	}

	for _, v := range data {
		table.Append(v)
	}
	table.Render()
}
