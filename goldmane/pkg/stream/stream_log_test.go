// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stream_test

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/projectcalico/calico/goldmane/pkg/stream"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

func TestStreamLogsCarryStreamID(t *testing.T) {
	hooks := logrus.StandardLogger().ReplaceHooks(make(logrus.LevelHooks))
	defer logrus.StandardLogger().ReplaceHooks(hooks)
	hook := test.NewGlobal()
	level := logrus.GetLevel()
	logrus.SetLevel(logrus.DebugLevel)
	defer logrus.SetLevel(level)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sm := stream.NewStreamManager()
	go sm.Run(ctx)

	s := <-sm.Register(&proto.FlowStreamRequest{}, 1)
	if s == nil {
		t.Fatal("nil stream")
	}
	s.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range hook.AllEntries() {
			if e.Message != "Stream context done" {
				continue
			}
			if got, ok := e.Data["id"].(string); !ok || got != s.ID() {
				t.Fatalf("expected id field %q, got %#v", s.ID(), e.Data["id"])
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("never saw the stream's context-done log")
}
