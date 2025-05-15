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

func TestChanUtil_ReadNonBlocking_GeneralTests(t *testing.T) {
	tt := []struct {
		description string
		getChan     func() (chan string, func())
		value       string
		read        bool
	}{
		{
			description: "channel is open",
			getChan: func() (chan string, func()) {
				ch := make(chan string, 1)
				ch <- "foo"
				return ch, func() { close(ch) }
			},
			value: "foo",
			read:  true,
		},
		{
			description: "channel is open and empty",
			getChan: func() (chan string, func()) {
				ch := make(chan string)
				return ch, func() { close(ch) }
			},
			value: "",
			read:  false,
		},
		{
			description: "channel is closed",
			getChan: func() (chan string, func()) {
				ch := make(chan string, 1)
				defer close(ch)
				ch <- "foo"
				return ch, func() {}
			},
			value: "foo",
			read:  true,
		},
		{
			description: "channel is closed and empty",
			getChan: func() (chan string, func()) {
				ch := make(chan string, 1)
				close(ch)
				return ch, func() {}
			},
			value: "",
			read:  false,
		},
	}
	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			ch, done := tc.getChan()
			defer done()
			str, read := chanutil.ReadNonBlocking(ch)
			if tc.value != "" && str != tc.value {
				t.Fatalf("Expected value to be '%s', got '%s'", tc.value, str)
			}
			if tc.read != read {
				t.Fatalf("Expected read to be '%t', got '%t'", tc.read, read)
			}
		})
	}
}

func TestChanUtil_ReadAllNonBlocking_GeneralTests(t *testing.T) {
	tt := []struct {
		description    string
		getChan        func() (chan string, func())
		expectedValues []string
	}{
		{
			description: "channel is open",
			getChan: func() (chan string, func()) {
				ch := make(chan string, 3)
				ch <- "foo"
				ch <- "bar"
				ch <- "baz"
				return ch, func() { close(ch) }
			},
			expectedValues: []string{"foo", "bar", "baz"},
		},
		{
			description: "channel is open and empty",
			getChan: func() (chan string, func()) {
				ch := make(chan string, 3)
				return ch, func() { close(ch) }
			},
			expectedValues: []string{},
		},
		{
			description: "channel is closed",
			getChan: func() (chan string, func()) {
				ch := make(chan string, 3)
				defer close(ch)
				ch <- "foo"
				ch <- "bar"
				ch <- "baz"

				return ch, func() {}
			},
			expectedValues: []string{"foo", "bar", "baz"},
		},
	}
	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			ch, done := tc.getChan()
			defer done()

			values := chanutil.ReadAllNonBlocking(ch)
			if len(tc.expectedValues) > 0 {
				if !slices.Equal(tc.expectedValues, values) {
					t.Fatalf("Expected all to be ['foo', 'bar', 'baz'], got '%v'", values)
				}
			} else if len(values) > 0 {
				t.Fatalf("Expected all to be empty, got '%v'", values)
			}
		})
	}
}

func TestChanUtil_Clear(t *testing.T) {
	tt := []struct {
		description string
		getChan     func() (chan string, func())
	}{
		{
			description: "channel is open and empty",
			getChan: func() (chan string, func()) {
				ch := make(chan string, 3)
				ch <- "foo"
				ch <- "bar"
				ch <- "baz"
				return ch, func() { close(ch) }
			},
		},
		{
			description: "channel is open and has one item",
			getChan: func() (chan string, func()) {
				ch := make(chan string, 3)
				ch <- "foo"
				return ch, func() { close(ch) }
			},
		},
		{
			description: "channel is open and has two item",
			getChan: func() (chan string, func()) {
				ch := make(chan string, 3)
				ch <- "foo"
				ch <- "bar"
				return ch, func() { close(ch) }
			},
		},
		{
			description: "channel is closed and empty",
			getChan: func() (chan string, func()) {
				ch := make(chan string, 3)
				close(ch)
				return ch, func() {}
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			ch, done := tc.getChan()
			defer done()

			chanutil.Clear(ch)
			if len(ch) > 0 {
				t.Fatalf("Expected channel to be empty, got length '%v'", len(ch))
			}
		})
	}
}
