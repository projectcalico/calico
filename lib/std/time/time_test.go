// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package time_test

import (
	"testing"

	"github.com/projectcalico/calico/lib/std/time"
)

func TestResolve(t *testing.T) {
	now := time.Now()

	t.Run("relative", func(t *testing.T) {
		cases := []struct {
			name      string
			input     string
			wantDelta time.Duration
		}{
			{"now", "now", 0},
			{"now - 0", "now - 0", 0},
			{"now - 15m", "now - 15m", 15 * time.Minute},
			{"no-space now-10m", "now-10m", 10 * time.Minute},
			{"now-100h", "now-100h", 100 * time.Hour},
			{"now-3d", "now-3d", 3 * 24 * time.Hour},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				s := tc.input
				got, echo, err := time.Resolve(now, &s)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got == nil {
					t.Fatal("expected resolved time, got nil")
				}
				if delta := now.Sub(*got); delta != tc.wantDelta {
					t.Errorf("delta = %v, want %v", delta, tc.wantDelta)
				}
				if echo != tc.input {
					t.Errorf("echo = %v, want %v", echo, tc.input)
				}
			})
		}
	})

	t.Run("relative errors", func(t *testing.T) {
		cases := []struct {
			name  string
			input string
		}{
			{"missing unit (now-32)", "now-32"},
			{"bad unit (now-xxx)", "now-xxx"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				s := tc.input
				got, echo, err := time.Resolve(now, &s)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if got != nil {
					t.Errorf("expected nil time, got %v", got)
				}
				if echo != nil {
					t.Errorf("expected nil echo, got %v", echo)
				}
			})
		}
	})

	t.Run("RFC3339", func(t *testing.T) {
		nowUTC := time.Now().UTC()
		s := nowUTC.Add(-5 * time.Second).UTC().Format(time.RFC3339)
		got, echo, err := time.Resolve(nowUTC, &s)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("expected resolved time, got nil")
		}
		// Compare in whole seconds — nowUTC keeps sub-second precision
		// that the RFC3339-formatted string dropped.
		if delta := nowUTC.Sub(*got) / time.Second; delta != 5 {
			t.Errorf("delta seconds = %v, want 5", delta)
		}
		if echo != got.Unix() {
			t.Errorf("echo = %v, want %v", echo, got.Unix())
		}
	})

	t.Run("nil or empty", func(t *testing.T) {
		cases := []struct {
			name  string
			input *string
		}{
			{"nil", nil},
			{"empty", ptr("")},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, echo, err := time.Resolve(now, tc.input)
				if err != nil || got != nil || echo != nil {
					t.Errorf("expected all-nil for %s input, got (%v, %v, %v)", tc.name, got, echo, err)
				}
			})
		}
	})
}

func ptr(s string) *string { return &s }
