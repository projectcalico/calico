// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package collector

import (
	"sync"

	log "github.com/sirupsen/logrus"

	extdataplane "github.com/projectcalico/calico/felix/dataplane/external"
	"github.com/projectcalico/calico/felix/proto"
)

// dataplaneInfoReader reads dataplane information.
type dataplaneInfoReader struct {
	dataplaneInfoC chan *proto.ToDataplane
	infoC          chan interface{}
	seqNo          uint64

	stopC    chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewDataplaneInfoReader returns a new DataplaneInfoReader
func NewDataplaneInfoReader(c chan interface{}) *dataplaneInfoReader {
	return &dataplaneInfoReader{
		stopC:          make(chan struct{}),
		dataplaneInfoC: make(chan *proto.ToDataplane, 1000),
		infoC:          c,
	}
}

// Start starts the reader.
func (r *dataplaneInfoReader) Start() error {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.run()
	}()

	return nil
}

// Stop stops the reader.
func (r *dataplaneInfoReader) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopC)
	})
}

// DataplaneInfoChan returns the channel to read the dataplane info from.
func (r *dataplaneInfoReader) DataplaneInfoChan() <-chan *proto.ToDataplane {
	return r.dataplaneInfoC
}

// run reads dataplane messages and wraps them into proto.ToDataplane type before sending them to
// the dataplaneInfo channel.
func (r *dataplaneInfoReader) run() {
	for {
		select {
		case <-r.stopC:
			return
		case info := <-r.infoC:
			dp, err := extdataplane.WrapPayloadWithEnvelope(info, r.seqNo)
			if err != nil {
				log.WithError(err).Errorf("failed to wrap payload with envelope for sequence number: %d", r.seqNo)
				continue
			}
			r.seqNo++
			r.dataplaneInfoC <- dp
		}
	}
}
