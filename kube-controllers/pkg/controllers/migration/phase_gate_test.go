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

package migration

import (
	"context"
	"fmt"
	"sync"
	"time"

	rtclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// phaseGate blocks the controller's status updates at specified phase transitions,
// allowing the test to observe intermediate states. It works by intercepting
// SubResourceUpdate calls on the rtClient — when the controller writes a
// DatastoreMigration status update, the gate blocks until the test releases
// that phase.
type phaseGate struct {
	mu    sync.Mutex
	gates map[DatastoreMigrationPhase]chan struct{}

	// reached is closed when the controller first attempts a status update
	// for a given phase. Tests wait on this to know the controller has
	// arrived at a phase before inspecting state.
	reached map[DatastoreMigrationPhase]chan struct{}
}

// newPhaseGate creates a gate that blocks the controller at each of the
// specified phases. Call waitForPhase to block until the controller reaches
// a phase, then release to let it continue.
func newPhaseGate(phases ...DatastoreMigrationPhase) *phaseGate {
	pg := &phaseGate{
		gates:   make(map[DatastoreMigrationPhase]chan struct{}),
		reached: make(map[DatastoreMigrationPhase]chan struct{}),
	}
	for _, p := range phases {
		pg.gates[p] = make(chan struct{})
		pg.reached[p] = make(chan struct{})
	}
	return pg
}

// intercept should be called from the SubResourceUpdate interceptor. It blocks
// if the object is a DatastoreMigration transitioning to a gated phase.
func (pg *phaseGate) intercept(obj rtclient.Object) {
	dm, ok := obj.(*DatastoreMigration)
	if !ok {
		return
	}
	phase := dm.Status.Phase
	pg.mu.Lock()
	reachedCh, gated := pg.reached[phase]
	gateCh := pg.gates[phase]
	pg.mu.Unlock()

	if !gated {
		return
	}

	// Signal that the controller has reached this phase.
	select {
	case <-reachedCh:
	default:
		close(reachedCh)
	}

	// Block until the test releases this phase.
	<-gateCh
}

// waitForPhase blocks until the controller has reached the given phase (i.e.,
// attempted a status update with that phase).
func (pg *phaseGate) waitForPhase(phase DatastoreMigrationPhase, timeout time.Duration) error {
	pg.mu.Lock()
	ch, ok := pg.reached[phase]
	pg.mu.Unlock()
	if !ok {
		return fmt.Errorf("phase %s is not gated", phase)
	}
	select {
	case <-ch:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timed out waiting for phase %s", phase)
	}
}

// release allows the controller to proceed past the given phase.
func (pg *phaseGate) release(phase DatastoreMigrationPhase) {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	if ch, ok := pg.gates[phase]; ok {
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
}

// wrapClient returns a new WithWatch client that intercepts SubResourceUpdate
// calls through the phase gate. All other operations pass through to the
// underlying client.
func (pg *phaseGate) wrapClient(c rtclient.WithWatch) rtclient.WithWatch {
	return interceptor.NewClient(c, interceptor.Funcs{
		SubResourceUpdate: func(
			ctx context.Context,
			client rtclient.Client,
			subResourceName string,
			obj rtclient.Object,
			opts ...rtclient.SubResourceUpdateOption,
		) error {
			err := client.SubResource(subResourceName).Update(ctx, obj, opts...)
			if err != nil {
				return err
			}

			// Gate after the update succeeds so the phase is persisted and
			// observable by the test before we block.
			pg.intercept(obj)
			return nil
		},
	})
}
