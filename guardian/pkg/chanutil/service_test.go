package chanutil_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/guardian/pkg/chanutil"
)

func TestRequestHandlerContextCancelledInHungRequest(t *testing.T) {
	setupTest(t)

	errChan := chanutil.NewSyncedError()
	defer errChan.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	service := chanutil.NewService[any, any](1)
	hdlr := chanutil.NewRequestsHandler(ctx, errChan, func(ctx context.Context, req any) (any, error) {
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

func TestRequestHandler(t *testing.T) {
	setupTest(t)

	errs := chanutil.NewSyncedError()
	defer errs.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var returnErr error
	service := chanutil.NewService[any, any](1)
	hdlr := chanutil.NewRequestsHandler(ctx, errs, func(ctx context.Context, req any) (any, error) {
		return struct{}{}, returnErr
	})

	var wg sync.WaitGroup
	wg.Add(1)

	done := make(chan struct{})
	go func() {
		wg.Done()
		_, _ = service.Send(struct{}{})
		close(done)
	}()

	req := <-service.Listen()
	hdlr.Add(req)

	// Ensure that the request is being handled.
	wg.Wait()

	returnErr = errors.New("error")
	hdlr.Fire()
	Expect(<-errs.Error()).Should(Equal(returnErr))
	returnErr = nil
	hdlr.Fire()
	<-done
}
