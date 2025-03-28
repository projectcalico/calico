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

// Message Types
const (
	NFULNL_MSG_PACKET = iota
	NFULNL_MSG_CONFIG

	NFULNL_MSG_MAX
)

const NFULNL_PREFIXLEN = 30

// Attributes
const (
	NFULA_UNSPEC = iota
	NFULA_PACKET_HDR
	NFULA_MARK
	NFULA_TIMESTAMP
	NFULA_IFINDEX_INDEV
	NFULA_IFINDEX_OUTDEV // 5
	NFULA_IFINDEX_PHYSINDEV
	NFULA_IFINDEX_PHYSOUTDEV
	NFULA_HWADDR
	NFULA_PAYLOAD
	NFULA_PREFIX // 10
	NFULA_UID
	NFULA_SEQ
	NFULA_SEQ_GLOBAL
	NFULA_GID
	NFULA_HWTYPE
	NFULA_HWHEADER
	NFULA_HWLEN
	NFULA_CT      // 18
	NFULA_CT_INFO // 19
	NFULA_VLAN
	NFULA_L2HDR

	__NFULA_MAX
)
const NFULA_MAX = __NFULA_MAX - 1

// Config Commands
const (
	NFULNL_CFG_CMD_NONE = iota
	NFULNL_CFG_CMD_BIND
	NFULNL_CFG_CMD_UNBIND
	NFULNL_CFG_CMD_PF_BIND
	NFULNL_CFG_CMD_PF_UNBIND
)

// Attribute Configuration
const (
	NFULA_CFG_UNSPEC = iota
	NFULA_CFG_CMD
	NFULA_CFG_MODE
	NFULA_CFG_NLBUFSIZ
	NFULA_CFG_TIMEOUT
	NFULA_CFG_QTHRESH
	NFULA_CFG_FLAGS
	__NFULA_CFG_MAX
)
const NFULA_CFG_MAX = __NFULA_CFG_MAX - 1

const (
	NFULNL_COPY_NONE   = 0x00
	NFULNL_COPY_META   = 0x01
	NFULNL_COPY_PACKET = 0x02
)

const (
	NFULNL_CFG_F_SEQ        = 0x0001
	NFULNL_CFG_F_SEQ_GLOBAL = 0x0002
	NFULNL_CFG_F_CONNTRACK  = 0x0004
)
