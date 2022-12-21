// Copyright (C) 2019 Cisco Systems Inc.
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
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

const (
	ConnRetries    = 10
	ConnRetryDelay = time.Second
)

func main() {
	var socket net.Conn
	var t tomb.Tomb
	var err error

	log := logrus.New()

	inFile := os.NewFile(3, "pipe1")
	outFile := os.NewFile(4, "pipe2")
	if inFile == nil || outFile == nil {
		log.Fatalf("Cannot open pipe FDs")
	}

	for i := 1; i <= ConnRetries; i++ {
		socket, err = net.Dial("unix", "/var/run/calico/felix-dataplane.sock")
		if err == nil {
			break
		} else if i < ConnRetries {
			log.WithError(err).Warnf("Try %d: Cannot open socket to agent (unix://%s)", i, "/var/run/calico/felix-dataplane.sock")
			time.Sleep(ConnRetryDelay)
		} else {
			log.WithError(err).Fatal("Could not open socket to agent")
		}
	}

	t.Go(func() error {
		io.Copy(socket, inFile)
		return errors.New("copying to agent stopped")
	})
	t.Go(func() error {
		io.Copy(outFile, socket)
		return errors.New("copying to felix stopped")
	})

	<-t.Dying()
	log.Info("Felix proxy exited")

}
