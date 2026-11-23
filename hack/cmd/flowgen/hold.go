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

package main

// Hold and listen modes: long-lived connections, so that the collector tracks a large set of live
// flows and its sweep re-evaluates them, rather than a stream of short ones.
//
//	flowgen -mode listen -listen-ports 9000            # in the sink, whose local routes make every test address local
//	flowgen -mode hold -connections 100000 -rate 2000 -hold-port 9000 -duration 30m
//
// A sink pod can also run `flowgen -mode listen -duration 0` as its main process.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/projectcalico/calico/app-policy/policyscale"
)

// holdConfig is what hold mode needs beyond the flow sampler.
type holdConfig struct {
	connections int
	rate        int
	duration    time.Duration
	dialTimeout time.Duration
	interval    time.Duration
	payload     []byte
	port        int
	shards      int
	targets     []net.IP
}

// holdStats counts hold mode's connections.
type holdStats struct {
	opened, failed, closed atomic.Uint64
}

func (s *holdStats) open() uint64 { return s.opened.Load() - s.closed.Load() }

// holdResult is hold mode's summary.
type holdResult struct {
	opened, openAtEnd, failed, closed uint64
	elapsed                           time.Duration
}

// runHold opens cfg.connections TCP connections at cfg.rate per second to the destinations of the
// flows draw returns (or the targets in turn), on cfg.port when set, and keeps them open until the
// run ends, writing the payload on each every interval so that conntrack and the collector see
// them active. A connection the peer closes is counted and not replaced.
func runHold(draw func() *policyscale.Flow, cfg holdConfig, stop <-chan os.Signal, out io.Writer) holdResult {
	raiseFileLimit(out)
	dst := destination(cfg.targets)
	if cfg.port > 0 {
		generated := dst
		dst = func(f *policyscale.Flow) string {
			host, _, _ := net.SplitHostPort(generated(f))
			return net.JoinHostPort(host, strconv.Itoa(cfg.port))
		}
	}

	var stats holdStats
	done := make(chan struct{})
	shards := make([]chan net.Conn, cfg.shards)
	var keepers sync.WaitGroup
	for i := range shards {
		shards[i] = make(chan net.Conn, 64)
		// Stagger the shards' writes over the interval rather than writing every connection at
		// once.
		offset := cfg.interval * time.Duration(i) / time.Duration(cfg.shards)
		keepers.Go(func() { keepAlive(shards[i], done, offset, cfg.interval, cfg.payload, &stats) })
	}

	work := make(chan *policyscale.Flow, cfg.shards*4)
	var dialers sync.WaitGroup
	var next atomic.Uint64
	for range cfg.shards {
		dialers.Go(func() {
			for f := range work {
				c, err := net.DialTimeout("tcp", dst(f), cfg.dialTimeout)
				if err != nil {
					if stats.failed.Add(1) == 1 {
						logf(out, "flowgen: first failure: %v\n", err)
					}
					continue
				}
				stats.opened.Add(1)
				shards[next.Add(1)%uint64(len(shards))] <- c
			}
		})
	}

	var deadline <-chan time.Time
	if cfg.duration > 0 {
		deadline = time.After(cfg.duration)
	}
	report := time.NewTicker(time.Second)
	defer report.Stop()
	const ticksPerSecond = 100
	pace := time.NewTicker(time.Second / ticksPerSecond)
	defer pace.Stop()

	start := time.Now()
	logf(out, "flowgen: hold %d connections, opening %d/s, writing %d bytes on each every %s", cfg.connections, cfg.rate, len(cfg.payload), cfg.interval)
	if len(cfg.targets) > 0 {
		logf(out, ", %d destination addresses", len(cfg.targets))
	}
	if cfg.port > 0 {
		logf(out, ", port %d", cfg.port)
	}
	logf(out, "\n")
	var lastOpened uint64
	tick := 0
	queued := 0
run:
	for {
		select {
		case <-pace.C:
			n := flowsForTick(cfg.rate, ticksPerSecond, tick)
			tick++
			for ; n > 0 && queued < cfg.connections; n-- {
				work <- draw()
				queued++
			}
			if queued == cfg.connections && work != nil {
				close(work)
				work = nil
			}
		case <-report.C:
			o := stats.opened.Load()
			logf(out, "%6.0fs  open=%d  opened=%d (%.0f/s)  failed=%d  closed=%d\n",
				time.Since(start).Seconds(), stats.open(), o, float64(o-lastOpened), stats.failed.Load(), stats.closed.Load())
			lastOpened = o
		case <-deadline:
			break run
		case <-stop:
			break run
		}
	}
	if work != nil {
		close(work)
	}
	dialers.Wait()
	open := stats.open()
	close(done)
	keepers.Wait()
	res := holdResult{opened: stats.opened.Load(), openAtEnd: open, failed: stats.failed.Load(), closed: stats.closed.Load(), elapsed: time.Since(start)}
	logf(out, "flowgen: hold done in %s: opened %d, %d still open at the end, failed %d, closed by the peer %d\n",
		res.elapsed.Round(time.Millisecond), res.opened, res.openAtEnd, res.failed, res.closed)
	return res
}

// keepAlive owns one shard of the held connections: it takes new ones from add, writes the
// payload on each every interval, and closes them all when done is closed.
func keepAlive(add <-chan net.Conn, done <-chan struct{}, offset, interval time.Duration, payload []byte, stats *holdStats) {
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	timer := time.NewTimer(offset + interval)
	defer timer.Stop()
	for {
		select {
		case c := <-add:
			conns = append(conns, c)
		case <-timer.C:
			kept := conns[:0]
			for _, c := range conns {
				_ = c.SetWriteDeadline(time.Now().Add(time.Second))
				if _, err := c.Write(payload); err != nil {
					_ = c.Close()
					stats.closed.Add(1)
					continue
				}
				kept = append(kept, c)
			}
			clear(conns[len(kept):])
			conns = kept
			timer.Reset(interval)
		case <-done:
			// The dialers have stopped; take any connection still on its way to this shard.
			for {
				select {
				case c := <-add:
					conns = append(conns, c)
				default:
					return
				}
			}
		}
	}
}

// listen opens a TCP listener on each of the ports. Port 0 picks a free one.
func listen(addr string, ports []int) ([]net.Listener, error) {
	var listeners []net.Listener
	for _, p := range ports {
		ln, err := net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(p)))
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return nil, err
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
}

type listenResult struct {
	accepted, openAtEnd, bytes uint64
	elapsed                    time.Duration
}

// serveListeners accepts TCP connections on the listeners and holds them open, reading and
// discarding whatever arrives, until the run ends, then closes the listeners.
func serveListeners(listeners []net.Listener, duration time.Duration, stop <-chan os.Signal, out io.Writer) listenResult {
	raiseFileLimit(out)
	var nAccepted, closed, failures, bytes atomic.Uint64
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()
	var ports []string
	for _, ln := range listeners {
		ports = append(ports, ln.Addr().String())
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					// Out of file descriptors, say: back off rather than spin.
					if failures.Add(1) == 1 {
						logf(out, "flowgen: first accept failure: %v\n", err)
					}
					time.Sleep(10 * time.Millisecond)
					continue
				}
				nAccepted.Add(1)
				go func() {
					buf := make([]byte, 256)
					for {
						n, err := c.Read(buf)
						bytes.Add(uint64(n))
						if err != nil {
							break
						}
					}
					_ = c.Close()
					closed.Add(1)
				}()
			}
		}()
	}

	var deadline <-chan time.Time
	if duration > 0 {
		deadline = time.After(duration)
	}
	report := time.NewTicker(time.Second)
	defer report.Stop()
	start := time.Now()
	logf(out, "flowgen: listening on %s\n", strings.Join(ports, ", "))
	var lastAccepted uint64
run:
	for {
		select {
		case <-report.C:
			a := nAccepted.Load()
			logf(out, "%6.0fs  open=%d  accepted=%d (%.0f/s)  closed=%d  accept-failures=%d\n",
				time.Since(start).Seconds(), a-closed.Load(), a, float64(a-lastAccepted), closed.Load(), failures.Load())
			lastAccepted = a
		case <-deadline:
			break run
		case <-stop:
			break run
		}
	}
	res := listenResult{accepted: nAccepted.Load(), bytes: bytes.Load(), elapsed: time.Since(start)}
	res.openAtEnd = res.accepted - closed.Load()
	logf(out, "flowgen: listen done in %s: accepted %d, %d still open at the end, read %d bytes\n",
		res.elapsed.Round(time.Millisecond), res.accepted, res.openAtEnd, res.bytes)
	return res
}

// parsePorts reads a list of ports and ranges: "9000", "80,443", "8000-8010".
func parsePorts(s string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("bad port %q", part)
		}
		last := first
		if isRange {
			if last, err = strconv.Atoi(hi); err != nil {
				return nil, fmt.Errorf("bad port range %q", part)
			}
		}
		if first < 1 || last > 65535 || first > last {
			return nil, fmt.Errorf("bad port range %q", part)
		}
		for p := first; p <= last; p++ {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports in %q", s)
	}
	return ports, nil
}

// raiseFileLimit lifts the open-file limit to its hard maximum: each held connection is a file.
func raiseFileLimit(out io.Writer) {
	var l syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &l); err != nil {
		return
	}
	if l.Cur < l.Max {
		l.Cur = l.Max
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &l); err != nil {
			logf(out, "flowgen: could not raise the open-file limit: %v\n", err)
		}
	}
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &l); err == nil {
		logf(out, "flowgen: open-file limit %d\n", l.Cur)
	}
}
