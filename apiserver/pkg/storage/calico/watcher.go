// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package calico

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	k8swatch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/storage"

	"github.com/projectcalico/calico/libcalico-go/lib/options"
	cwatch "github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// watchChan implements watch.Interface.
type watchChan struct {
	resultChan chan watch.Event
	pred       storage.SelectionPredicate
	watcher    cwatch.Interface
	ctx        context.Context
	cancel     context.CancelFunc
}

func (rs *resourceStore) watchResource(ctx context.Context, resourceVersion string,
	p storage.SelectionPredicate, name, namespace string) (k8swatch.Interface, error) {
	opts := options.ListOptions{Name: name, Namespace: namespace, ResourceVersion: resourceVersion}
	ctx, cancel := context.WithCancel(ctx)
	lWatch, err := rs.watch(ctx, rs.client, opts)
	if err != nil {
		cancel()
		return nil, err
	}
	wc := &watchChan{
		resultChan: make(chan watch.Event),
		pred:       p,
		watcher:    lWatch,
		ctx:        ctx,
		cancel:     cancel,
	}
	go wc.run()
	return wc, nil
}

func (wc *watchChan) convertEvent(ce cwatch.Event) (res *watch.Event) {
	switch ce.Type {
	case cwatch.Added:
		aapiObject := convertToAAPI(ce.Object)
		if aapiObject == nil || !wc.filter(aapiObject) {
			return nil
		}
		res = &watch.Event{
			Type:   watch.Added,
			Object: aapiObject,
		}
	case cwatch.Deleted:
		aapiObject := convertToAAPI(ce.Previous)
		if aapiObject == nil || !wc.filter(aapiObject) {
			return nil
		}
		res = &watch.Event{
			Type:   watch.Deleted,
			Object: aapiObject,
		}
	case cwatch.Modified:
		aapiObject := convertToAAPI(ce.Object)
		if aapiObject == nil {
			return nil
		}
		if wc.acceptAll() {
			res = &watch.Event{
				Type:   watch.Modified,
				Object: aapiObject,
			}
			return res
		}
		oldAapiObject := convertToAAPI(ce.Previous)
		curObjPasses := wc.filter(aapiObject)
		oldObjPasses := wc.filter(oldAapiObject)
		switch {
		case curObjPasses && oldObjPasses:
			res = &watch.Event{
				Type:   watch.Modified,
				Object: aapiObject,
			}
		case curObjPasses && !oldObjPasses:
			res = &watch.Event{
				Type:   watch.Added,
				Object: aapiObject,
			}
		case !curObjPasses && oldObjPasses:
			res = &watch.Event{
				Type:   watch.Deleted,
				Object: oldAapiObject,
			}
		}
	case cwatch.Error:
		select {
		case <-wc.ctx.Done():
			// Any error received after we have cancelled this watcher should be ignored.
			return nil
		default:
			// Fall through if we have not cancelled this watcher.
		}
		var msg string
		if ce.Error != nil {
			msg = ce.Error.Error()
		}
		res = &watch.Event{
			Type: watch.Error,
			Object: &metav1.Status{
				Reason:  metav1.StatusReasonInternalError,
				Message: msg,
			},
		}
	}
	return res
}

func (wc *watchChan) run() {
	for e := range wc.watcher.ResultChan() {
		we := wc.convertEvent(e)
		if we != nil {
			wc.resultChan <- *we
			if we.Type == watch.Error {
				// We use wc.ctx to reap all goroutines. Under whatever condition, we should stop them all.
				// It's fine to double cancel.
				wc.cancel()
			}
		}
	}
	close(wc.resultChan)
}

// filter returns whether a result should be filtered in (true) or filtered out (false).
func (wc *watchChan) filter(obj runtime.Object) bool {
	matches, err := wc.pred.Matches(obj)
	return matches && err == nil
}

// acceptAll returns true if all results should be filtered in.
func (wc *watchChan) acceptAll() bool {
	return wc.pred.Empty()
}

func (wc *watchChan) Stop() {
	wc.cancel()
}

func (wc *watchChan) ResultChan() <-chan watch.Event {
	return wc.resultChan
}
