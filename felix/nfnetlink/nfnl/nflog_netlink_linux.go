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
	"unsafe"
)

const (
	SizeofNflogMsgPktHdr       = 0x4
	SizeofNflogMsgPktHw        = 0xC
	SizeofNflogMsgPktTimestamp = 0x10
	SizeofNflogMsgConfigCmd    = 0x1
	SizeofNflogMsgConfigBufSiz = 0x4
	SizeofNflogMsgConfigMode   = 0x6
	SizeofNflogMsgConfigFlag   = 0x2
)

type NflogMsgPktHdr struct {
	_ uint16 // hwProtocol
	_ uint8  // hook
	_ uint8  // pad
}

type NflogMsgPktHw struct {
	_ uint16   // hwAddrlen
	_ uint16   // pad
	_ [8]uint8 //hwAddr
}

type NflogMsgPktTimestamp struct {
	_ uint64 // sec
	_ uint64 // usec
}

type NflogMsgConfigCmd struct {
	command uint8
}

func NewNflogMsgConfigCmd(command int) *NflogMsgConfigCmd {
	return &NflogMsgConfigCmd{
		command: uint8(command),
	}
}

func DeserializeNflogMsgConfigCmd(b []byte) *NflogMsgConfigCmd {
	return (*NflogMsgConfigCmd)(unsafe.Pointer(&b[0:SizeofNflogMsgConfigCmd][0]))
}

func (msg *NflogMsgConfigCmd) Len() int {
	return SizeofNflogMsgConfigCmd
}

func (msg *NflogMsgConfigCmd) Serialize() []byte {
	return (*(*[SizeofNflogMsgConfigCmd]byte)(unsafe.Pointer(msg)))[:]
}

type NflogMsgConfigMode struct {
	copyRange uint32
	copyMode  uint8
	_pad      uint8
}

func NewNflogMsgConfigMode(copyRange int, copyMode int) *NflogMsgConfigMode {
	return &NflogMsgConfigMode{
		copyRange: uint32(copyRange),
		copyMode:  uint8(copyMode),
	}
}

func DeserializeNflogMsgConfigMode(b []byte) *NflogMsgConfigMode {
	return (*NflogMsgConfigMode)(unsafe.Pointer(&b[0:SizeofNflogMsgConfigMode][0]))
}

func (msg *NflogMsgConfigMode) Len() int {
	return SizeofNflogMsgConfigMode
}

func (msg *NflogMsgConfigMode) Serialize() []byte {
	return (*(*[SizeofNflogMsgConfigMode]byte)(unsafe.Pointer(msg)))[:]
}

type NflogMsgConfigBufSiz struct {
	bufsiz uint32
}

func NewNflogMsgConfigBufSiz(bufsiz int) *NflogMsgConfigBufSiz {
	return &NflogMsgConfigBufSiz{
		bufsiz: uint32(bufsiz),
	}
}

func DeserializeNflogMsgConfigBufSiz(b []byte) *NflogMsgConfigBufSiz {
	return (*NflogMsgConfigBufSiz)(unsafe.Pointer(&b[0:SizeofNflogMsgConfigBufSiz][0]))
}

func (msg *NflogMsgConfigBufSiz) Len() int {
	return SizeofNflogMsgConfigBufSiz
}

func (msg *NflogMsgConfigBufSiz) Serialize() []byte {
	return (*(*[SizeofNflogMsgConfigBufSiz]byte)(unsafe.Pointer(msg)))[:]
}

type NflogMsgConfigFlag struct {
	flag uint16
}

func NewNflogMsgConfigFlag(flag int) *NflogMsgConfigFlag {
	return &NflogMsgConfigFlag{
		flag: htons(uint16(flag)),
	}
}

func DeserializeNflogMsgConfigFlag(b []byte) *NflogMsgConfigFlag {
	return (*NflogMsgConfigFlag)(unsafe.Pointer(&b[0:SizeofNflogMsgConfigFlag][0]))
}

func (msg *NflogMsgConfigFlag) Len() int {
	return SizeofNflogMsgConfigFlag
}

func (msg *NflogMsgConfigFlag) Serialize() []byte {
	return (*(*[SizeofNflogMsgConfigFlag]byte)(unsafe.Pointer(msg)))[:]
}
