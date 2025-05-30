package asyncutil_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/pkg/asyncutil"
	"github.com/projectcalico/calico/lib/std/chanutil"
)

func TestRequestHandlerContextCancelledInHungRequest(t *testing.T) {
	setupTest(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errBuff := asyncutil.NewErrorBuffer()
	defer errBuff.Close()

	cmdExec := asyncutil.NewCommandExecutor(ctx, errBuff, func(ctx context.Context, req any) (any, error) {
		hungChan := make(chan struct{})
		defer close(hungChan)
		_, err := chanutil.Read(ctx, hungChan)
		return struct{}{}, err
	})

	resultChan := cmdExec.Send(struct{}{})

	cancel()

	<-cmdExec.WaitForShutdown()
	_, err := (<-resultChan).Result()
	Expect(err).Should(Equal(context.Canceled))
}

func TestRequestHandlerStopAndRequeue(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	setupTest(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errBuff := asyncutil.NewErrorBuffer()
	defer errBuff.Close()

	pause := true
	var wg sync.WaitGroup
	wg.Add(2)
	cmdExec := asyncutil.NewCommandExecutor(ctx, errBuff, func(ctx context.Context, req any) (any, error) {
		if pause {
			wg.Done()

			ch := make(chan struct{})
			defer close(ch)

			_, err := chanutil.Read(ctx, ch)
			return struct{}{}, err
		}

		select {
		case <-ctx.Done():
			return struct{}{}, errors.New("Context should not be finished.")
		default:

		}

		logrus.Debug("Request handled")
		return struct{}{}, nil
	})

	result1 := cmdExec.Send(nil)
	result2 := cmdExec.Send(nil)

	wg.Wait()

	// We don't wait on the signal returned because we want to test the unhappy path where the user didn't wait on the
	// signal.
	cmdExec.DrainAndBacklog()
	pause = false
	cmdExec.Resume()

	_, err := (<-result1).Result()
	Expect(err).Should(BeNil())
	_, err = (<-result2).Result()
	Expect(err).Should(BeNil())

	cancel()
	logrus.Debug("Waiting for shutdown...")
	<-cmdExec.WaitForShutdown()
	logrus.Debug("Finished waiting for shutdown.")
}
