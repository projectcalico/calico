//go:build !windows
// +build !windows

// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.
package nfnetlink

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/nfnetlink/nfnl"
	"github.com/projectcalico/calico/nfnetlink/pkt"
)

const (
	IPv4Proto = 0x800
	IPv6Proto = 0x86DD
)

const (
	ProtoIcmp = 1
	ProtoTcp  = 6
	ProtoUdp  = 17
)

const AggregationDuration = time.Duration(10) * time.Millisecond

var (
	counterVecMessagesReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_nflog_netlink_messages_received",
		Help: "Total number of netlink envelope messages received broken down by group.",
	}, []string{"groupNum"})
	counterVecNFLOGSReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_nflog_logs_received",
		Help: "Total number of individual NFLOG messages received broken down by group.",
	}, []string{"groupNum"})
	counterVecBufferOverruns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_nflog_buffer_overruns",
		Help: "Total number of times that the kernel's NFLOG buffer overran causing NFLOGs to be dropped.",
	}, []string{"groupNum"})
	counterVecChanWaitTime = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_nflog_block_time_seconds",
		Help: "Total amount of time the NFLOG reader has spent blocking waiting " +
			"to send data to the NFLOG aggregator.",
	}, []string{"groupNum"})
	counterVecParseErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_nflog_parse_errors",
		Help: "Total number of errors encountered when parsing NFLOG messages.",
	}, []string{"groupNum"})
	counterVecAggregatesCreated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_nflog_aggregates_created",
		Help: "Total number of NFLOG aggregates created.",
	}, []string{"groupNum"})
	counterVecAggregatesFlushed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_nflog_aggregates_flushed",
		Help: "Total number of NFLOG aggregates flushed to the flow logs collector.",
	}, []string{"groupNum"})
)

func init() {
	prometheus.MustRegister(
		counterVecMessagesReceived,
		counterVecNFLOGSReceived,
		counterVecBufferOverruns,
		counterVecChanWaitTime,
		counterVecParseErrors,
		counterVecAggregatesCreated,
		counterVecAggregatesFlushed,
	)
}

var (
	rll = logutils.NewRateLimitedLogger(logutils.OptInterval(time.Minute))
)

func SubscribeDNS(groupNum int, bufSize int, callback func(data []byte, timestamp uint64), done <-chan struct{}) error {
	log.Infof("Subscribe to NFLOG group %v for DNS responses", groupNum)
	resChan, err := openAndReadNFNLSocket(groupNum, bufSize, done, 2000, true, false)
	if err != nil {
		return err
	}
	parseAndReturnDNSResponses(groupNum, resChan, callback)
	return nil
}

func NflogSubscribe(groupNum int, bufSize int, ch chan<- map[NflogPacketTuple]*NflogPacketAggregate, done <-chan struct{}, includeConnTrack bool) error {
	resChan, err := openAndReadNFNLSocket(groupNum, bufSize, done, 2*cap(ch), false, includeConnTrack)
	if err != nil {
		return err
	}
	parseAndAggregateFlowLogs(groupNum, resChan, ch)
	return nil
}

func openAndReadNFNLSocket(
	groupNum int, bufSize int, done <-chan struct{}, chanCap int, immediateFlush bool, includeConnTrack bool,
) (chan [][]byte, error) {
	sock, err := nl.Subscribe(syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}

	nlMsgType := nfnl.NFNL_SUBSYS_ULOG<<8 | nfnl.NFULNL_MSG_CONFIG
	nlMsgFlags := syscall.NLM_F_REQUEST

	// Globally unbind NFLOG from the protocol family.  Not sure why this is
	// done: it also affects other users of NFLOG!
	req := nl.NewNetlinkRequest(nlMsgType, nlMsgFlags)
	nfgenmsg := nfnl.NewNfGenMsg(syscall.AF_INET, nfnl.NFNETLINK_V0, 0)
	req.AddData(nfgenmsg)
	nflogcmd := nfnl.NewNflogMsgConfigCmd(nfnl.NFULNL_CFG_CMD_PF_UNBIND)
	nfattr := nl.NewRtAttr(nfnl.NFULA_CFG_CMD, nflogcmd.Serialize())
	req.AddData(nfattr)
	if err := sock.Send(req); err != nil {
		return nil, err
	}

	// Globally bind NFLOG to the protocol family.
	req = nl.NewNetlinkRequest(nlMsgType, nlMsgFlags)
	nfgenmsg = nfnl.NewNfGenMsg(syscall.AF_INET, nfnl.NFNETLINK_V0, 0)
	req.AddData(nfgenmsg)
	nflogcmd = nfnl.NewNflogMsgConfigCmd(nfnl.NFULNL_CFG_CMD_PF_BIND)
	nfattr = nl.NewRtAttr(nfnl.NFULA_CFG_CMD, nflogcmd.Serialize())
	req.AddData(nfattr)
	if err := sock.Send(req); err != nil {
		return nil, err
	}

	// Bind our socket to the group number so we get the expected messages.
	req = nl.NewNetlinkRequest(nlMsgType, nlMsgFlags)
	nfgenmsg = nfnl.NewNfGenMsg(syscall.AF_INET, nfnl.NFNETLINK_V0, groupNum)
	req.AddData(nfgenmsg)
	nflogcmd = nfnl.NewNflogMsgConfigCmd(nfnl.NFULNL_CFG_CMD_BIND)
	nfattr = nl.NewRtAttr(nfnl.NFULA_CFG_CMD, nflogcmd.Serialize())
	req.AddData(nfattr)
	if err := sock.Send(req); err != nil {
		return nil, err
	}

	// Set the packet copy mode; we need to receive a prefix of the packet.
	req = nl.NewNetlinkRequest(nlMsgType, nlMsgFlags)
	nfgenmsg = nfnl.NewNfGenMsg(syscall.AF_UNSPEC, nfnl.NFNETLINK_V0, groupNum)
	req.AddData(nfgenmsg)
	nflogcfg := nfnl.NewNflogMsgConfigMode(0xFF, nfnl.NFULNL_COPY_PACKET)
	nfattr = nl.NewRtAttr(nfnl.NFULA_CFG_MODE, nflogcfg.Serialize())
	req.AddData(nfattr)
	if err := sock.Send(req); err != nil {
		return nil, err
	}

	if includeConnTrack {
		// Ask NFLOG to append the conntrack entry to the packet metadata, so
		// that we can see any NAT.
		req = nl.NewNetlinkRequest(nlMsgType, nlMsgFlags)
		nfgenmsg = nfnl.NewNfGenMsg(syscall.AF_UNSPEC, nfnl.NFNETLINK_V0, groupNum)
		req.AddData(nfgenmsg)
		nflogct := nfnl.NewNflogMsgConfigFlag(nfnl.NFULNL_CFG_F_CONNTRACK)
		nfattr = nl.NewRtAttr(nfnl.NFULA_CFG_FLAGS, nflogct.Serialize())
		req.AddData(nfattr)
		if err := sock.Send(req); err != nil {
			return nil, err
		}
	}

	// Set the kernel's SKB buffer size.  This needs to be no bigger than the
	// kernel/netlink library limits.
	const kernelBufSzLimit = 131072
	const bufSizeLimit = min(nl.RECEIVE_BUFFER_SIZE, kernelBufSzLimit)
	if bufSize > bufSizeLimit {
		log.WithField("bufSize", bufSize).Warnf("Reducing NFLOG buffer size to kernel/netlink limit (%d).", bufSizeLimit)
		bufSize = bufSizeLimit
	}
	req = nl.NewNetlinkRequest(nlMsgType, nlMsgFlags)
	nfgenmsg = nfnl.NewNfGenMsg(syscall.AF_UNSPEC, nfnl.NFNETLINK_V0, groupNum)
	req.AddData(nfgenmsg)
	nflogbufsiz := nfnl.NewNflogMsgConfigBufSiz(bufSize)
	nfattr = nl.NewRtAttr(nfnl.NFULA_CFG_NLBUFSIZ, nflogbufsiz.Serialize())
	req.AddData(nfattr)
	if err := sock.Send(req); err != nil {
		return nil, err
	}

	if immediateFlush {
		// Disable the kernel's batching delay so that it sends every NFLOG
		// immediately.  This minimises latency for things like DNS logs.
		req = nl.NewNetlinkRequest(nlMsgType, nlMsgFlags)
		nfgenmsg = nfnl.NewNfGenMsg(syscall.AF_UNSPEC, nfnl.NFNETLINK_V0, groupNum)
		req.AddData(nfgenmsg)
		timeout := nfnl.NewNflogMsgConfigBufSiz(0)
		nfattr = nl.NewRtAttr(nfnl.NFULA_CFG_TIMEOUT, timeout.Serialize())
		req.AddData(nfattr)
		if err := sock.Send(req); err != nil {
			return nil, err
		}
	}

	go func() {
		<-done
		sock.Close()
	}()

	// Channel to pass raw netlink messages for further processing. We keep it at
	// twice the size of the processor's outgoing channel so that reading netlink
	// messages from the socket can be buffered until they can be consumed.
	resChan := make(chan [][]byte, chanCap)
	// Start a goroutine for receiving netlink messages from the kernel.
	go func() {
		logCtx := log.WithFields(log.Fields{
			"groupNum": groupNum,
		})
		groupNumStr := fmt.Sprint(groupNum)
		msgsReceived := counterVecMessagesReceived.WithLabelValues(groupNumStr)
		nflogsReceived := counterVecNFLOGSReceived.WithLabelValues(groupNumStr)
		numOverruns := counterVecBufferOverruns.WithLabelValues(groupNumStr)
		chanWait := counterVecChanWaitTime.WithLabelValues(groupNumStr)
		var lastChanDelay time.Duration

	Recvloop:
		for {
			var res [][]byte
			msgs, _, err := sock.Receive()
			if err != nil {
				switch err := err.(type) {
				case syscall.Errno:
					if err == syscall.ENOBUFS {
						logCtx.WithField("chanDelay", lastChanDelay).Warnf(
							"NFLOG buffer overrun (ENOBUFS), some NFLOG messages lost.")
						numOverruns.Inc()
						continue
					} else if err.Temporary() {
						logCtx.Warnf("NflogSubscribe Receive: %v", err)
						continue
					}
				default:
					logCtx.Fatalf("NflogSubscribe Receive: %v", err)
				}
			}
			msgsReceived.Inc()
			nflogsReceived.Add(float64(len(msgs)))
			for _, m := range msgs {
				mType := m.Header.Type
				if mType == syscall.NLMSG_DONE {
					break
				}
				if mType == syscall.NLMSG_ERROR {
					native := binary.LittleEndian
					err := int32(native.Uint32(m.Data[0:4]))
					logCtx.Warnf("NLMSG_ERROR: %v", syscall.Errno(-err))
					continue Recvloop
				}
				res = append(res, m.Data)
			}
			chanWaitStart := time.Now()
			resChan <- res
			lastChanDelay = time.Since(chanWaitStart)
			chanWait.Add(lastChanDelay.Seconds())
		}
	}()

	return resChan, nil
}

func parseAndAggregateFlowLogs(groupNum int, resChan <-chan [][]byte, ch chan<- map[NflogPacketTuple]*NflogPacketAggregate) {
	// Start another goroutine for parsing netlink messages into nflog objects
	go func() {
		defer close(ch)
		logCtx := rll.WithFields(log.Fields{
			"groupNum": groupNum,
		})

		groupNumStr := fmt.Sprint(groupNum)
		numParseErrors := counterVecParseErrors.WithLabelValues(groupNumStr)
		numAggregatesCreated := counterVecAggregatesCreated.WithLabelValues(groupNumStr)
		numAggregatesFlushed := counterVecAggregatesFlushed.WithLabelValues(groupNumStr)

		// We batch NFLOG objects and send them to the subscriber every
		// "AggregationDuration" time interval.
		sendTicker := time.NewTicker(AggregationDuration)
		// Batching is done like so:
		// For each NflogPacketTuple if it's a prefix we've already seen we update
		// packet and byte counters on exising NflogPrefix and discard the parsed
		// packet.
		aggregate := make(map[NflogPacketTuple]*NflogPacketAggregate)
		for {
			select {
			case res := <-resChan:
				for _, m := range res {
					msg := nfnl.DeserializeNfGenMsg(m)
					nflogPacket, err := parseNflog(m[msg.Len():])
					if err != nil {
						logCtx.Warnf("Error parsing NFLOG %v", err)
						numParseErrors.Inc()
						continue
					}
					var pktAggr *NflogPacketAggregate
					updatePrefix := true
					pktAggr, seen := aggregate[nflogPacket.Tuple]
					if seen {
						for i, prefix := range pktAggr.Prefixes {
							if prefix.Equals(&nflogPacket.Prefix) {
								prefix.Packets++
								prefix.Bytes += nflogPacket.Bytes
								pktAggr.Prefixes[i] = prefix
								updatePrefix = false
								break
							}
						}
						// We reached here, so we didn't find a prefix. Appending this prefix
						// is handled below.
					} else {
						pktAggr = &NflogPacketAggregate{
							Tuple: nflogPacket.Tuple,
						}
						numAggregatesCreated.Inc()
					}
					if updatePrefix {
						pktAggr.Prefixes = append(pktAggr.Prefixes, nflogPacket.Prefix)
						aggregate[nflogPacket.Tuple] = pktAggr
					}

					// Copy across any pre-DNAT info, if newly discovered through a CT message.
					if !pktAggr.IsDNAT && nflogPacket.IsDNAT {
						pktAggr.IsDNAT = true
						pktAggr.OriginalTuple = nflogPacket.OriginalTuple
					}
				}
			case <-sendTicker.C:
				if len(aggregate) == 0 {
					continue
				}

				// Don't block when trying to send to slow receivers.
				// In case of slow receivers, simply continue aggregating and
				// retry sending next time around.
				select {
				case ch <- aggregate:
					numAggregatesFlushed.Add(float64(len(aggregate)))
					aggregate = make(map[NflogPacketTuple]*NflogPacketAggregate)
				default:
				}
			}
		}
	}()
}

func parseAndReturnDNSResponses(groupNum int, resChan <-chan [][]byte, callback func(data []byte, timestamp uint64)) {
	// Start another goroutine for parsing netlink messages into DNS response data.
	go func() {
		logCtx := log.WithFields(log.Fields{
			"groupNum": groupNum,
		})
		logCtx.Debug("Start DNS response capture loop")
		for {
			select {
			case res := <-resChan:
				logCtx.Debugf("%v messages from DNS response channel", len(res))
				for _, m := range res {
					msg := nfnl.DeserializeNfGenMsg(m)
					packetData, timestamp, err := getNflogPacketData(m[msg.Len():])
					if err != nil {
						logCtx.Warnf("Error parsing NFLOG %v", err)
						continue
					}
					logCtx.Debugf("DNS response length %v", len(packetData))
					callback(packetData, timestamp)
				}
			}
		}
	}()
}

func getNflogPacketData(m []byte) (packetData []byte, timestamp uint64, err error) {
	var attrs [nfnl.NFULA_MAX]nfnl.NetlinkNetfilterAttr
	n, err := nfnl.ParseNetfilterAttr(m, attrs[:])
	if err != nil {
		return
	}
	for idx := 0; idx < n; idx++ {
		attr := attrs[idx]
		attrType := int(attr.Attr.Type) & nfnl.NLA_TYPE_MASK
		switch attrType {
		case nfnl.NFULA_TIMESTAMP:
			log.Debugf("DNS-LATENCY: NFULA_TIMESTAMP: %T %v", attr.Value, attr.Value)
			var tv unix.Timeval
			// NFLOG attributes are big-endian; see for example
			// https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/nflog.h
			err := binary.Read(bytes.NewReader(attr.Value), binary.BigEndian, &tv)
			if err != nil {
				log.WithError(err).Panic("binary.Read failed")
			}
			log.Debugf("DNS-LATENCY: tv=%v", tv)
			timestamp = uint64(tv.Usec*1000 + tv.Sec*1000000000)
		case nfnl.NFULA_PAYLOAD:
			packetData = attr.Value
		default:
			// Ignore attributes we don't care about.
		}
	}
	return
}

func parseNflog(m []byte) (NflogPacket, error) {
	nflogPacket := NflogPacket{}
	var attrs [nfnl.NFULA_MAX]nfnl.NetlinkNetfilterAttr
	n, err := nfnl.ParseNetfilterAttr(m, attrs[:])
	if err != nil {
		return nflogPacket, err
	}

	for idx := 0; idx < n; idx++ {
		attr := attrs[idx]
		attrType := int(attr.Attr.Type) & nfnl.NLA_TYPE_MASK
		native := binary.BigEndian
		switch attrType {
		case nfnl.NFULA_PACKET_HDR:
			nflogPacket.Header.HwProtocol = int(native.Uint16(attr.Value[0:2]))
			nflogPacket.Header.Hook = int(attr.Value[2])
		case nfnl.NFULA_MARK:
			nflogPacket.Mark = int(native.Uint32(attr.Value[0:4]))
		case nfnl.NFULA_PAYLOAD:
			parsePacketHeader(&nflogPacket.Tuple, nflogPacket.Header.HwProtocol, attr.Value)
			nflogPacket.Bytes = len(attr.Value)
		case nfnl.NFULA_PREFIX:
			p := NflogPrefix{Len: len(attr.Value) - 1}
			copy(p.Prefix[:], attr.Value[:len(attr.Value)-1])
			nflogPacket.Prefix = p
		case nfnl.NFULA_GID:
			nflogPacket.Gid = int(native.Uint32(attr.Value[0:4]))
		case nfnl.NFULA_CT:
			err := parseConntrack(&nflogPacket, attr.Value)
			if err != nil {
				// Not returning error, flow log may still be useful without CT.
				rll.WithError(err).Warn("Failed to parse conntrack entry.")
			}
		default:
			// Skip attributes we don't need.
		}
	}
	nflogPacket.Prefix.Packets = 1
	nflogPacket.Prefix.Bytes = nflogPacket.Bytes
	return nflogPacket, nil
}

func parsePacketHeader(tuple *NflogPacketTuple, hwProtocol int, nflogPayload []byte) {
	switch hwProtocol {
	case IPv4Proto:
		ipHeader := pkt.ParseIPv4Header(nflogPayload)
		copy(tuple.Src[:], ipHeader.Saddr.To16()[:16])
		copy(tuple.Dst[:], ipHeader.Daddr.To16()[:16])
		tuple.Proto = int(ipHeader.Protocol)
		parseLayer4Header(tuple, nflogPayload[ipHeader.IHL:])
	case IPv6Proto:
		ipHeader := pkt.ParseIPv6Header(nflogPayload)
		copy(tuple.Src[:], ipHeader.Saddr.To16()[:16])
		copy(tuple.Dst[:], ipHeader.Daddr.To16()[:16])
		tuple.Proto = int(ipHeader.NextHeader)
		parseLayer4Header(tuple, nflogPayload[pkt.IPv6HeaderLen:])
	}
}

func parseLayer4Header(tuple *NflogPacketTuple, l4payload []byte) {
	switch tuple.Proto {
	case ProtoIcmp:
		header := pkt.ParseICMPHeader(l4payload)
		tuple.L4Src.Id = int(header.Id)
		tuple.L4Dst.Type = int(header.Type)
		tuple.L4Dst.Code = int(header.Code)
	case ProtoTcp:
		header := pkt.ParseTCPHeader(l4payload)
		tuple.L4Src.Port = int(header.Source)
		tuple.L4Dst.Port = int(header.Dest)
	case ProtoUdp:
		header := pkt.ParseUDPHeader(l4payload)
		tuple.L4Src.Port = int(header.Source)
		tuple.L4Dst.Port = int(header.Dest)
	}
}

func parseConntrack(packet *NflogPacket, ct []byte) error {
	cte, err := conntrackEntryFromNfAttrs(ct[:], syscall.AF_INET)
	if err != nil {
		return err
	}
	if cte.IsDNAT() {
		packet.OriginalTuple = cte.OriginalTuple
		packet.IsDNAT = true
	}
	return nil
}
