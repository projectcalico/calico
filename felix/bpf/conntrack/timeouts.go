// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package conntrack

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type Timeouts struct {
	CreationGracePeriod time.Duration

	TCPSynSent     time.Duration
	TCPEstablished time.Duration
	TCPFinsSeen    time.Duration
	TCPResetSeen   time.Duration

	UDPTimeout time.Duration

	// GenericTimeout is the timeout for IP protocols that we don't know.
	GenericTimeout time.Duration

	ICMPTimeout time.Duration
}

// EntryExpired checks whether a given conntrack table entry for a given
// protocol and time, is expired.
//
// WARNING: this implementation is duplicated in the conntrack_cleanup.c BPF
// program.
func (t *Timeouts) EntryExpired(nowNanos int64, proto uint8, entry ValueInterface) (reason string, expired bool) {
	age := time.Duration(nowNanos - entry.LastSeen())
	switch proto {
	case ProtoTCP:
		dsr := entry.IsForwardDSR()
		data := entry.Data()
		rstSeen := data.RSTSeen()
		if rstSeen && age > t.TCPResetSeen {
			return "RST seen", true
		}
		finsSeen := (dsr && data.FINsSeenDSR()) || data.FINsSeen()
		if finsSeen && age > t.TCPFinsSeen {
			// Both legs have been finished, tear down.
			return "FINs seen", true
		}
		if data.Established() || dsr {
			if entry.RSTSeen() != 0 && age > 2*60*time.Second {
				return "no traffic on conn with RST with residual traffic for too long", true
			}
			if age > t.TCPEstablished {
				return "no traffic on established flow for too long", true
			}
		} else {
			if age > t.TCPSynSent {
				return "no traffic on pre-established flow for too long", true
			}
		}
		return "", false
	case ProtoICMP, ProtoICMP6:
		if age > t.ICMPTimeout {
			return "no traffic on ICMP flow for too long", true
		}
	case ProtoUDP:
		if age > t.UDPTimeout {
			return "no traffic on UDP flow for too long", true
		}
	default:
		if age > t.GenericTimeout {
			return "no traffic on generic IP flow for too long", true
		}
	}
	return "", false
}

func DefaultTimeouts() Timeouts {
	return Timeouts{
		CreationGracePeriod: 10 * time.Second,
		TCPSynSent:          20 * time.Second,
		TCPEstablished:      time.Hour,
		TCPFinsSeen:         30 * time.Second,
		TCPResetSeen:        40 * time.Second,
		UDPTimeout:          60 * time.Second,
		GenericTimeout:      600 * time.Second,
		ICMPTimeout:         5 * time.Second,
	}
}

var linuxSysctls = map[string]string{
	"TCPSynSent":     "nf_conntrack_tcp_timeout_syn_sent",
	"TCPEstablished": "nf_conntrack_tcp_timeout_established",
	"TCPFinsSeen":    "nf_conntrack_tcp_timeout_time_wait",
	"GenericTimeout": "nf_conntrack_generic_timeout",
	"ICMPTimeout":    "nf_conntrack_icmp_timeout",
}

func GetTimeouts(config map[string]string) Timeouts {
	t := DefaultTimeouts()

	v := reflect.ValueOf(&t)
	v = v.Elem()

	for key, value := range config {
		field := v.FieldByName(key)
		if !field.IsValid() {
			log.WithField("value", key).Warn("Not a valid BPF conntrack timeout, skipping")
			continue
		}

		d, err := time.ParseDuration(value)
		if err == nil {
			log.WithFields(log.Fields{"name": key, "value": d}).Info("BPF conntrack timeout set")
			field.SetInt(int64(d))
			continue
		}

		if value == "Auto" {
			sysctl := linuxSysctls[key]
			if sysctl != "" {
				seconds, err := readSecondsFromFile(sysctl)
				if err == nil {
					d := time.Duration(seconds) * time.Second
					log.WithFields(log.Fields{"name": key, "value": d}).Infof("BPF conntrack timeout set from %s", sysctl)
					field.SetInt(int64(d))
					continue
				}
			}
		}

		log.WithField("value", key).Warnf("Not a valid BPF conntrack timeout value, using default %s",
			time.Duration(field.Int()))
	}

	fields := make(log.Fields)

	tt := reflect.TypeOf(t)

	for i := 0; i < v.NumField(); i++ {
		fields[tt.Field(i).Name] = v.Field(i).Interface()
	}

	log.WithFields(fields).Infof("BPF conntrack timers")

	return t
}

func readSecondsFromFile(nfTimeout string) (int, error) {
	filePath := "/proc/sys/net/netfilter/" + nfTimeout

	file, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		seconds, err := strconv.Atoi(line)
		if err != nil {
			return 0, fmt.Errorf("error converting the value to an integer: %w", err)
		}

		return seconds, nil
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("error reading from file: %w", err)
	}

	return 0, fmt.Errorf("file is empty or cannot read a line")
}
