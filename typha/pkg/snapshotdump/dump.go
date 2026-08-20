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

// Package snapshotdump connects to a Typha instance as a sync client and dumps
// the snapshot it serves for one or more syncer types.  It is the reusable core
// behind the "calico typha client dump" command and the per-Typha collection
// step in "calicoctl cluster diags".
package snapshotdump

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// Config controls a dump run.
type Config struct {
	// Server is the "host:port" of the Typha to connect to.
	Server string
	// SyncerTypes is the ordered list of syncer types to dump.  Each is dumped
	// over its own sequential connection.  If empty, all known types are dumped.
	SyncerTypes []syncproto.SyncerType
	// Format selects the output encoding.
	Format Format
	// Out is where the encoded snapshot stream is written.
	Out io.Writer

	// ClientOpts carries the connection options (TLS material, timeouts).  Its
	// SyncerType field is ignored; it is set per syncer type during the dump.
	ClientOpts syncclient.Options

	// IdleTimeout bounds how long we wait for a syncer type's snapshot.  If no
	// updates arrive for this long and the server has not yet reported InSync,
	// we stop that syncer type, record a "timed-out" status in its end marker,
	// and move on — so a stuck or never-in-sync Typha can't hang the dump
	// forever.  The timer is reset by every batch of updates, so a large but
	// healthy snapshot that keeps streaming will not time out.  A value <= 0
	// disables the bound (wait indefinitely).
	IdleTimeout time.Duration

	// Identification reported to Typha in the handshake.
	MyVersion  string
	MyHostname string
}

// Dump connects to the configured Typha and streams each syncer type's snapshot
// to cfg.Out.  Types are dumped sequentially, each over its own connection that
// is closed once the snapshot is complete (the server reports InSync).
//
// Dump always flushes whatever it managed to emit, even on error, so a partial
// dump is still usable in a diagnostics bundle.  If one syncer type fails, the
// failure is recorded in that section's "end" marker and the dump continues
// with the remaining types; the first such error is returned at the end.
func Dump(ctx context.Context, cfg Config) (retErr error) {
	if cfg.Out == nil {
		return errors.New("snapshotdump: Out must be set")
	}
	types := cfg.SyncerTypes
	if len(types) == 0 {
		types = syncproto.AllSyncerTypes[:]
	}

	em, err := newEmitter(cfg.Out, cfg.Format)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := em.Close(); cerr != nil && retErr == nil {
			retErr = cerr
		}
	}()

	for _, st := range types {
		if err := em.begin(string(st)); err != nil {
			return fmt.Errorf("failed to write snapshot for %s: %w", st, err)
		}
		res := dumpOne(ctx, cfg, st, em)
		if res.err != nil {
			if retErr == nil {
				retErr = fmt.Errorf("failed to dump syncer type %s: %w", st, res.err)
			}
			log.WithError(res.err).WithField("syncerType", st).Warn("Failed to dump syncer type")
		} else if res.timedOut {
			log.WithFields(log.Fields{
				"syncerType":  st,
				"numKVs":      res.count,
				"idleTimeout": cfg.IdleTimeout,
			}).Warn("Timed out waiting for snapshot to reach in-sync; emitting partial data")
		}
		if err := em.end(string(st), res.count, res.status); err != nil {
			return fmt.Errorf("failed to write snapshot for %s: %w", st, err)
		}
		// Honour cancellation between types.
		if ctx.Err() != nil {
			if retErr == nil {
				retErr = ctx.Err()
			}
			return retErr
		}
	}
	return retErr
}

// dumpResult is the outcome of dumping a single syncer type.
type dumpResult struct {
	count    int
	status   string // recorded in the section's "end" marker
	timedOut bool
	err      error // hard error (connect/write); a timeout is not a hard error
}

// dumpOne connects as a single syncer type, streams every KV of the snapshot
// into the emitter, and returns once the server reports InSync, the idle
// timeout fires, or the context is cancelled.
func dumpOne(ctx context.Context, cfg Config, st syncproto.SyncerType, em *emitter) dumpResult {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cb := &dumpCallback{
		em:       em,
		section:  string(st),
		done:     make(chan struct{}),
		activity: make(chan struct{}, 1),
	}

	opts := cfg.ClientOpts
	opts.SyncerType = st

	disc := discovery.New(discovery.WithAddrOverride(cfg.Server))
	client := syncclient.New(disc, cfg.MyVersion, cfg.MyHostname, "calico typha client dump", cb, &opts)
	if err := client.Start(cctx); err != nil {
		return dumpResult{status: "error: " + err.Error(), err: err}
	}

	outcome := waitForSnapshot(ctx, cb.done, cb.activity, cfg.IdleTimeout)

	// Close the connection and wait for the client to finish before reading
	// cb.count/cb.writeErr (avoids racing with the callback goroutine).
	cancel()
	client.Finished.Wait()

	return resultForOutcome(outcome, cb.count, cb.writeErr, ctx.Err(), cfg.IdleTimeout)
}

// resultForOutcome maps the wait outcome and the callback's final state to a
// dumpResult.  A write error encountered while streaming is a hard failure no
// matter how the wait ended: the emitted snapshot is incomplete, so it must be
// reported as an error rather than masked by a "timed-out" or "cancelled"
// status (which would produce a corrupt/partial dump with no error marker).
func resultForOutcome(outcome waitOutcome, count int, writeErr, ctxErr error, idleTimeout time.Duration) dumpResult {
	if writeErr != nil {
		return dumpResult{count: count, status: "error: " + writeErr.Error(), err: writeErr}
	}
	switch outcome {
	case outcomeIdleTimeout:
		return dumpResult{
			count:    count,
			status:   fmt.Sprintf("timed-out: no updates for %s and not in-sync", idleTimeout),
			timedOut: true,
		}
	case outcomeCancelled:
		return dumpResult{count: count, status: "cancelled", err: ctxErr}
	default: // outcomeInSync
		return dumpResult{count: count, status: "in-sync"}
	}
}

type waitOutcome int

const (
	outcomeInSync waitOutcome = iota
	outcomeIdleTimeout
	outcomeCancelled
)

// waitForSnapshot blocks until the snapshot completes (done is closed), the
// connection goes idle for longer than idle (no activity received and not yet
// done), or the context is cancelled.  Each receive on activity resets the idle
// timer, so a snapshot that keeps streaming never times out.  An idle value
// <= 0 disables the idle bound.
func waitForSnapshot(ctx context.Context, done, activity <-chan struct{}, idle time.Duration) waitOutcome {
	if idle <= 0 {
		select {
		case <-done:
			return outcomeInSync
		case <-ctx.Done():
			return outcomeCancelled
		}
	}

	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case <-done:
			return outcomeInSync
		case <-ctx.Done():
			return outcomeCancelled
		case <-activity:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(idle)
		case <-timer.C:
			return outcomeIdleTimeout
		}
	}
}

// dumpCallback receives updates for one syncer type and streams them into the
// emitter.  Typha delivers the whole snapshot before it reports InSync, so by
// the time OnStatusUpdated(InSync) fires every snapshot KV has already been
// emitted.  All callbacks for a given client are invoked from a single
// goroutine, so no locking is needed within the callback.
type dumpCallback struct {
	em       *emitter
	section  string
	count    int
	writeErr error

	done     chan struct{}
	activity chan struct{}
	closed   bool
}

// ping notifies the idle watchdog that the connection made progress.  It is
// non-blocking: the watchdog only needs to know that *some* activity happened
// since it last looked, so a full buffer (an un-drained earlier ping) is fine.
func (c *dumpCallback) ping() {
	select {
	case c.activity <- struct{}{}:
	default:
	}
}

func (c *dumpCallback) OnStatusUpdated(status api.SyncStatus) {
	c.ping()
	if status == api.InSync && !c.closed {
		c.closed = true
		close(c.done)
	}
}

func (c *dumpCallback) OnUpdates(updates []api.Update) {
	c.ping()
	if c.writeErr != nil {
		return
	}
	for _, u := range updates {
		if err := c.em.kv(c.section, u); err != nil {
			c.writeErr = err
			return
		}
		c.count++
	}
}
