package fv

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"testing"

	. "github.com/onsi/gomega"
)

func setup(t *testing.T) (context.Context, func()) {
	RegisterTestingT(t)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)

	// Use a channel to detect when the test is done
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		select {
		case <-sigs:
			fmt.Println("Interrupt received, ensuring cleanup...")
			// If interrupted, call t.Fail() to stop the test gracefully
		case <-ctx.Done():
			// If the test finishes naturally, return
		}
	}()
	return ctx, cancel
}
