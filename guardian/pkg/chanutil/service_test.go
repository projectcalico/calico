package chanutil_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/pkg/chanutil"
)

func TestRequestHandlerContextCancelledInHungRequest(t *testing.T) {
	setupTest(t)

	errChan := chanutil.NewSyncedError()
	defer errChan.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	service := chanutil.NewService[any, any](1)
	hdlr := chanutil.NewRequestsHandler(ctx, func(ctx context.Context, req any) (any, error) {
		hungChan := make(chan struct{})
		defer close(hungChan)
		_, err := chanutil.ReadWithContext(ctx, hungChan)
		return struct{}{}, err
	})

	var wg sync.WaitGroup
	wg.Add(1)

	serviceErr := make(chan error)
	go func() {
		wg.Done()
		_, err := service.Send(struct{}{})
		serviceErr <- err
	}()

	req := <-service.Listen()
	hdlr.Add(req)
	hdlr.Fire()

	// Ensure that the request is being handled.
	wg.Wait()

	cancel()

	hdlr.WaitForShutdown()
	Expect(<-serviceErr).Should(Equal(context.Canceled))
	Expect(<-errChan.Error()).Should(Equal(context.Canceled))
}

func TestRequestHandlerStopAndRequeue(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	setupTest(t)

	errs := chanutil.NewSyncedError()
	defer errs.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	service := chanutil.NewService[any, any](1)

	pause := true
	hdlr := chanutil.NewRequestsHandler(ctx, func(ctx context.Context, req any) (any, error) {
		if pause {
			ch := make(chan struct{})
			defer close(ch)

			_, _ = chanutil.ReadWithContext(ctx, ch)
			return struct{}{}, errors.New("some error")
		}

		logrus.Debug("Request handled")
		return struct{}{}, nil
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = service.Send(struct{}{})
	}()
	go func() {
		defer wg.Done()
		_, _ = service.Send(struct{}{})
	}()

	req := <-service.Listen()
	hdlr.Add(req)
	req = <-service.Listen()
	hdlr.Add(req)

	hdlr.Fire()
	hdlr.StopAndRequeueRequests()

	pause = false
	hdlr.Fire()

	wg.Wait()
	cancel()
	hdlr.WaitForShutdown()
}
