//go:build !windows
// +build !windows

// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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

package nfnl

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

const (
	NFNETLINK_V0 = iota
)

const (
	NFNL_SUBSYS_NONE = iota
	NFNL_SUBSYS_CTNETLINK
	NFNL_SUBSYS_CTNETLINK_EXP
	NFNL_SUBSYS_QUEUE
	NFNL_SUBSYS_ULOG
	NFNL_SUBSYS_COUNT
)

const NLA_TYPE_MASK = ^(int(syscall.NLA_F_NESTED | syscall.NLA_F_NET_BYTEORDER))

const (
	SizeofNfGenMsg = 0x4
	SizeofNfAttr   = syscall.SizeofNlAttr
)

type NlMsghdr struct {
	syscall.NlMsghdr
}

func DeserializeNlMsghdr(b []byte) *NlMsghdr {
	return (*NlMsghdr)(unsafe.Pointer(&b[0:syscall.SizeofNlMsghdr][0]))
}

func (msg *NlMsghdr) Serialize() []byte {
	return (*(*[syscall.SizeofNlMsghdr]byte)(unsafe.Pointer(msg)))[:]
}

func (msg *NlMsghdr) Len() int {
	return syscall.SizeofNlMsghdr
}

type NfGenMsg struct {
	Family  uint8
	Version uint8
	ResId   uint16
}

func htons(num uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, num)
	return binary.LittleEndian.Uint16(data)
}

func NewNfGenMsg(family int, version int, resId int) *NfGenMsg {
	return &NfGenMsg{
		Family:  uint8(family),
		Version: uint8(version),
		ResId:   htons(uint16(resId)),
	}
}

func DeserializeNfGenMsg(b []byte) *NfGenMsg {
	return (*NfGenMsg)(unsafe.Pointer(&b[0:SizeofNfGenMsg][0]))
}

func (msg *NfGenMsg) Len() int {
	return SizeofNfGenMsg
}

func (msg *NfGenMsg) Serialize() []byte {
	return (*(*[SizeofNfGenMsg]byte)(unsafe.Pointer(msg)))[:]
}

func nfaAlignOf(attrlen int) int {
	return (attrlen + syscall.NLA_ALIGNTO - 1) & ^(syscall.NLA_ALIGNTO - 1)
}

type NfAttr struct {
	syscall.NlAttr
}

func DeserializeNfAttr(b []byte) *NfAttr {
	return (*NfAttr)(unsafe.Pointer(&b[0:SizeofNfAttr][0]))
}

func (msg *NfAttr) Serialize() []byte {
	return (*(*[SizeofNfAttr]byte)(unsafe.Pointer(msg)))[:]
}

func (msg *NfAttr) Len() int {
	return SizeofNfAttr
}

type NetlinkNetfilterAttr struct {
	Attr  NfAttr
	Value []byte
}

func ParseNetfilterAttr(b []byte, attrs []NetlinkNetfilterAttr) (int, error) {
	j := 0
	for len(b) >= SizeofNfAttr {
		a, vbuf, alen, err := netlinkNetfilterAttrAndValue(b)
		if err != nil {
			return 0, err
		}
		ra := NetlinkNetfilterAttr{Attr: *a, Value: vbuf[:int(a.NlAttr.Len)-SizeofNfAttr]}
		attrs[j] = ra
		b = b[alen:]
		j++
	}
	return j, nil
}

func netlinkNetfilterAttrAndValue(b []byte) (*NfAttr, []byte, int, error) {
	a := DeserializeNfAttr(b)
	if int(a.NlAttr.Len) < SizeofNfAttr || int(a.NlAttr.Len) > len(b) {
		return nil, nil, 0, syscall.EINVAL
	}
	return a, b[SizeofNfAttr:], nfaAlignOf(int(a.NlAttr.Len)), nil
}
