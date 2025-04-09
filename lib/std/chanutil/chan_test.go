package chanutil_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/projectcalico/calico/lib/std/chanutil"
)

func TestChanUtil_Read_ContextCancelled(t *testing.T) {
	ch := make(chan string)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel the context immediately to force the context.Cancelled error.
	cancel()

	_, err := chanutil.Read(ctx, ch)
	if err == nil {
		t.Fatal("Expected and error to be returned.")
	} else if !errors.Is(err, context.Canceled) {
		t.Fatalf("Expected context canceled error, got '%s'", err)
	}
}

func TestChanUtil_Read_ChannelClosed(t *testing.T) {
	ch := make(chan string)
	close(ch)

	_, err := chanutil.Read(context.Background(), ch)
	if err == nil {
		t.Fatal("Expected and error to be returned.")
	} else if !errors.Is(err, chanutil.ErrChannelClosed) {
		t.Fatalf("Expected channel closed error, got '%s'", err)
	}
}

func TestChanUtil_Read_SuccessfulInPrefilledChan(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "foobar"

	v, err := chanutil.Read(context.Background(), ch)
	if err != nil {
		t.Fatal("Expected and error to be nil.")
	}
	if v != "foobar" {
		t.Fatalf("Expected value to be 'foobar', got '%s'", v)
	}
}

func TestChanUtil_ReadWithDeadline_ReturnsDeadlineExceeded(t *testing.T) {
	ch := make(chan string, 1)

	_, err := chanutil.ReadWithDeadline(context.Background(), ch, time.Millisecond*100)
	if err == nil {
		t.Fatal("Expected and error to be returned.")
	} else if !errors.Is(err, chanutil.ErrDeadlineExceeded) {
		t.Fatalf("Expected channel closed error, got '%s'", err)
	}
}

func TestChanUtil_ReadAllNonBlocking_ReturnsWhenChannelIsNotClosed(t *testing.T) {
	ch := make(chan string, 3)
	defer close(ch)

	ch <- "foo"
	ch <- "bar"
	ch <- "baz"

	all := chanutil.ReadAllNonBlocking(ch)
	if !slices.Equal([]string{"foo", "bar", "baz"}, all) {
		t.Fatalf("Expected all to be ['foo', 'bar', 'baz'], got '%v'", all)
	}
}
