package asyncutil_test

import (
	"context"
	"sync"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/pkg/asyncutil"
)

func TestRequestHandlerContextCancelledInHungRequest(t *testing.T) {
	setupTest(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errBuff := asyncutil.NewAsyncErrorBuffer()
	defer errBuff.Close()

	cmdExec := asyncutil.NewCommandExecutor(ctx, errBuff, func(ctx context.Context, req any) (any, error) {
		hungChan := make(chan struct{})
		defer close(hungChan)
		_, err := asyncutil.ReadWithContext(ctx, hungChan)
		return struct{}{}, err
	})

	resultChan := cmdExec.Send(struct{}{})

	cancel()

	cmdExec.ShutdownSignaler().Receive()
	_, err := (<-resultChan).Result()
	Expect(err).Should(Equal(context.Canceled))
}

func TestRequestHandlerStopAndRequeue(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	setupTest(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errBuff := asyncutil.NewAsyncErrorBuffer()
	defer errBuff.Close()

	pause := true
	var wg sync.WaitGroup
	wg.Add(2)
	cmdExec := asyncutil.NewCommandExecutor(ctx, errBuff, func(ctx context.Context, req any) (any, error) {
		if pause {
			wg.Done()

			ch := make(chan struct{})
			defer close(ch)

			_, err := asyncutil.ReadWithContext(ctx, ch)
			return struct{}{}, err
		}

		logrus.Debug("Request handled")
		return struct{}{}, nil
	})

	result1 := cmdExec.Send(nil)
	result2 := cmdExec.Send(nil)

	wg.Wait()

	cmdExec.PauseExecution()
	pause = false
	cmdExec.ResumeExecution()

	cancel()

	cmdExec.ShutdownSignaler().Receive()
	_, err := (<-result1).Result()
	Expect(err).Should(BeNil())
	_, err = (<-result2).Result()
	Expect(err).Should(BeNil())
}
