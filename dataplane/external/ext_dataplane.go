// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
//
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

// extdataplane implements the connection to an external dataplane driver, connected via
// a pair of pipes.
package extdataplane

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"os/exec"

	pb "github.com/gogo/protobuf/proto"
	log "github.com/sirupsen/logrus"

	_ "github.com/projectcalico/felix/config"
	"github.com/projectcalico/felix/proto"
)

// StartExtDataplaneDriver starts the given driver as a child process and returns a
// connection to it along with the command itself so that it may be monitored.
func StartExtDataplaneDriver(driverFilename string) (*extDataplaneConn, *exec.Cmd) {
	// Create a pair of pipes, one for sending messages to the dataplane
	// driver, the other for receiving.
	toDriverR, toDriverW, err := os.Pipe()
	if err != nil {
		log.WithError(err).Fatal("Failed to open pipe for dataplane driver")
	}
	fromDriverR, fromDriverW, err := os.Pipe()
	if err != nil {
		log.WithError(err).Fatal("Failed to open pipe for dataplane driver")
	}

	cmd := exec.Command(driverFilename)
	driverOut, err := cmd.StdoutPipe()
	if err != nil {
		log.WithError(err).Fatal("Failed to create pipe for dataplane driver")
	}
	driverErr, err := cmd.StderrPipe()
	if err != nil {
		log.WithError(err).Fatal("Failed to create pipe for dataplane driver")
	}
	go io.Copy(os.Stdout, driverOut)
	go io.Copy(os.Stderr, driverErr)
	cmd.ExtraFiles = []*os.File{toDriverR, fromDriverW}
	if err := cmd.Start(); err != nil {
		log.WithError(err).Fatal("Failed to start dataplane driver")
	}

	// Now the sub-process is running, close our copy of the file handles
	// for the child's end of the pipes.
	if err := toDriverR.Close(); err != nil {
		cmd.Process.Kill()
		log.WithError(err).Fatal("Failed to close parent's copy of pipe")
	}
	if err := fromDriverW.Close(); err != nil {
		cmd.Process.Kill()
		log.WithError(err).Fatal("Failed to close parent's copy of pipe")
	}
	dataplaneConnection := &extDataplaneConn{
		toDataplane:   toDriverW,
		fromDataplane: fromDriverR,
	}
	return dataplaneConnection, cmd
}

type extDataplaneConn struct {
	fromDataplane io.Reader
	toDataplane   io.Writer
	nextSeqNumber uint64
}

func (c *extDataplaneConn) RecvMessage() (msg interface{}, err error) {
	buf := make([]byte, 8)
	_, err = io.ReadFull(c.fromDataplane, buf)
	if err != nil {
		return
	}
	length := binary.LittleEndian.Uint64(buf)

	data := make([]byte, length)
	_, err = io.ReadFull(c.fromDataplane, data)
	if err != nil {
		return
	}

	envelope := proto.FromDataplane{}
	err = pb.Unmarshal(data, &envelope)
	if err != nil {
		return
	}
	log.WithField("envelope", envelope).Debug("Received message from dataplane.")

	switch payload := envelope.Payload.(type) {
	case *proto.FromDataplane_ProcessStatusUpdate:
		msg = payload.ProcessStatusUpdate
	case *proto.FromDataplane_WorkloadEndpointStatusUpdate:
		msg = payload.WorkloadEndpointStatusUpdate
	case *proto.FromDataplane_WorkloadEndpointStatusRemove:
		msg = payload.WorkloadEndpointStatusRemove
	case *proto.FromDataplane_HostEndpointStatusUpdate:
		msg = payload.HostEndpointStatusUpdate
	case *proto.FromDataplane_HostEndpointStatusRemove:
		msg = payload.HostEndpointStatusRemove
	default:
		log.WithField("payload", payload).Warn("Ignoring unknown message from dataplane")
	}

	return
}

func (fc *extDataplaneConn) SendMessage(msg interface{}) error {
	log.Debugf("Writing msg (%v) to felix: %#v", fc.nextSeqNumber, msg)
	// Wrap the payload message in an envelope so that protobuf takes care of deserialising
	// it as the correct type.
	envelope := &proto.ToDataplane{
		SequenceNumber: fc.nextSeqNumber,
	}
	fc.nextSeqNumber += 1
	switch msg := msg.(type) {
	case *proto.ConfigUpdate:
		envelope.Payload = &proto.ToDataplane_ConfigUpdate{msg}
	case *proto.InSync:
		envelope.Payload = &proto.ToDataplane_InSync{msg}
	case *proto.IPSetUpdate:
		envelope.Payload = &proto.ToDataplane_IpsetUpdate{msg}
	case *proto.IPSetDeltaUpdate:
		envelope.Payload = &proto.ToDataplane_IpsetDeltaUpdate{msg}
	case *proto.IPSetRemove:
		envelope.Payload = &proto.ToDataplane_IpsetRemove{msg}
	case *proto.ActivePolicyUpdate:
		envelope.Payload = &proto.ToDataplane_ActivePolicyUpdate{msg}
	case *proto.ActivePolicyRemove:
		envelope.Payload = &proto.ToDataplane_ActivePolicyRemove{msg}
	case *proto.ActiveProfileUpdate:
		envelope.Payload = &proto.ToDataplane_ActiveProfileUpdate{msg}
	case *proto.ActiveProfileRemove:
		envelope.Payload = &proto.ToDataplane_ActiveProfileRemove{msg}
	case *proto.HostEndpointUpdate:
		envelope.Payload = &proto.ToDataplane_HostEndpointUpdate{msg}
	case *proto.HostEndpointRemove:
		envelope.Payload = &proto.ToDataplane_HostEndpointRemove{msg}
	case *proto.WorkloadEndpointUpdate:
		envelope.Payload = &proto.ToDataplane_WorkloadEndpointUpdate{msg}
	case *proto.WorkloadEndpointRemove:
		envelope.Payload = &proto.ToDataplane_WorkloadEndpointRemove{msg}
	case *proto.HostMetadataUpdate:
		envelope.Payload = &proto.ToDataplane_HostMetadataUpdate{msg}
	case *proto.HostMetadataRemove:
		envelope.Payload = &proto.ToDataplane_HostMetadataRemove{msg}
	case *proto.IPAMPoolUpdate:
		envelope.Payload = &proto.ToDataplane_IpamPoolUpdate{msg}
	case *proto.IPAMPoolRemove:
		envelope.Payload = &proto.ToDataplane_IpamPoolRemove{msg}
	default:
		log.WithField("msg", msg).Panic("Unknown message type")
	}
	data, err := pb.Marshal(envelope)

	if err != nil {
		log.WithError(err).WithField("msg", msg).Panic(
			"Failed to marshal data to front end")
	}

	lengthBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lengthBytes, uint64(len(data)))
	var messageBuf bytes.Buffer
	messageBuf.Write(lengthBytes)
	messageBuf.Write(data)
	for {
		_, err := messageBuf.WriteTo(fc.toDataplane)
		if err == io.ErrShortWrite {
			log.Warn("Short write to dataplane driver; buffer full?")
			continue
		}
		if err != nil {
			return err
		}
		log.Debug("Wrote message to dataplane driver")
		break
	}
	return nil
}
