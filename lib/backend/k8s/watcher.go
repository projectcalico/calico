package k8s

import (
	"context"
	"strconv"
	"sync/atomic"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

const (
	resultsBufSize = 100
)

// Watch entries in the datastore matching the resources specified by the ListInterface.
func (c *KubeClient) Watch(cxt context.Context, l model.ListInterface, revision string) (api.WatchInterface, error) {
	var rev int64
	if len(revision) != 0 {
		var err error
		rev, err = strconv.ParseInt(revision, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	wc := &watcher{
		client:     c,
		list:       l,
		initialRev: rev,
		resultChan: make(chan api.WatchEvent, resultsBufSize),
	}
	wc.ctx, wc.cancel = context.WithCancel(cxt)
	return wc, nil
}

// watcher implements watch.Interface.
type watcher struct {
	client     *KubeClient
	initialRev int64
	ctx        context.Context
	cancel     context.CancelFunc
	resultChan chan api.WatchEvent
	list       model.ListInterface
	terminated uint32
}

// Stop stops the watcher and releases associated resources.
// This calls through to the context cancel function.
func (wc *watcher) Stop() {
	wc.cancel()
}

// ResultChan returns a channel used to receive WatchEvents.
func (wc *watcher) ResultChan() <-chan api.WatchEvent {
	return wc.resultChan
}

// HasTerminated returns true when the watcher has completed termination processing.
func (wc *watcher) HasTerminated() bool {
	return atomic.LoadUint32(&wc.terminated) != 0
}
