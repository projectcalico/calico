// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package asm

type Helper int32

// noinspection GoUnusedConst
const (
	HelperUnspec                 Helper = 0
	HelperMapLookupElem          Helper = 1
	HelperMapUpdateElem          Helper = 2
	HelperMapDeleteElem          Helper = 3
	HelperProbeRead              Helper = 4
	HelperKtimeGetNs             Helper = 5
	HelperTracePrintk            Helper = 6
	HelperGetPrandomU32          Helper = 7
	HelperGetSmpProcessorId      Helper = 8
	HelperSkbStoreBytes          Helper = 9
	HelperL3CsumReplace          Helper = 10
	HelperL4CsumReplace          Helper = 11
	HelperTailCall               Helper = 12
	HelperCloneRedirect          Helper = 13
	HelperGetCurrentPidTgid      Helper = 14
	HelperGetCurrentUidGid       Helper = 15
	HelperGetCurrentComm         Helper = 16
	HelperGetCgroupClassid       Helper = 17
	HelperSkbVlanPush            Helper = 18
	HelperSkbVlanPop             Helper = 19
	HelperSkbGetTunnelKey        Helper = 20
	HelperSkbSetTunnelKey        Helper = 21
	HelperPerfEventRead          Helper = 22
	HelperRedirect               Helper = 23
	HelperGetRouteRealm          Helper = 24
	HelperPerfEventOutput        Helper = 25
	HelperSkbLoadBytes           Helper = 26
	HelperGetStackid             Helper = 27
	HelperCsumDiff               Helper = 28
	HelperSkbGetTunnelOpt        Helper = 29
	HelperSkbSetTunnelOpt        Helper = 30
	HelperSkbChangeProto         Helper = 31
	HelperSkbChangeType          Helper = 32
	HelperSkbUnderCgroup         Helper = 33
	HelperGetHashRecalc          Helper = 34
	HelperGetCurrentTask         Helper = 35
	HelperProbeWriteUser         Helper = 36
	HelperCurrentTaskUnderCgroup Helper = 37
	HelperSkbChangeTail          Helper = 38
	HelperSkbPullData            Helper = 39
	HelperCsumUpdate             Helper = 40
	HelperSetHashInvalid         Helper = 41
	HelperGetNumaNodeId          Helper = 42
	HelperSkbChangeHead          Helper = 43
	HelperXdpAdjustHead          Helper = 44
	HelperProbeReadStr           Helper = 45
	HelperGetSocketCookie        Helper = 46
	HelperGetSocketUid           Helper = 47
	HelperSetHash                Helper = 48
	HelperSetsockopt             Helper = 49
	HelperSkbAdjustRoom          Helper = 50
	HelperRedirectMap            Helper = 51
	HelperSkRedirectMap          Helper = 52
	HelperSockMapUpdate          Helper = 53
	HelperXdpAdjustMeta          Helper = 54
	HelperPerfEventReadValue     Helper = 55
	HelperPerfProgReadValue      Helper = 56
	HelperGetsockopt             Helper = 57
	HelperOverrideReturn         Helper = 58
	HelperSockOpsCbFlagsSet      Helper = 59
	HelperMsgRedirectMap         Helper = 60
	HelperMsgApplyBytes          Helper = 61
	HelperMsgCorkBytes           Helper = 62
	HelperMsgPullData            Helper = 63
	HelperBind                   Helper = 64
	HelperXdpAdjustTail          Helper = 65
	HelperSkbGetXfrmState        Helper = 66
	HelperGetStack               Helper = 67
	HelperSkbLoadBytesRelative   Helper = 68
	HelperFibLookup              Helper = 69
	HelperSockHashUpdate         Helper = 70
	HelperMsgRedirectHash        Helper = 71
	HelperSkRedirectHash         Helper = 72
	HelperLwtPushEncap           Helper = 73
	HelperLwtSeg6StoreBytes      Helper = 74
	HelperLwtSeg6AdjustSrh       Helper = 75
	HelperLwtSeg6Action          Helper = 76
	HelperRcRepeat               Helper = 77
	HelperRcKeydown              Helper = 78
	HelperSkbCgroupId            Helper = 79
	HelperGetCurrentCgroupId     Helper = 80
	HelperGetLocalStorage        Helper = 81
	HelperSkSelectReuseport      Helper = 82
	HelperSkbAncestorCgroupId    Helper = 83
	HelperSkLookupTcp            Helper = 84
	HelperSkLookupUdp            Helper = 85
	HelperSkRelease              Helper = 86
	HelperMapPushElem            Helper = 87
	HelperMapPopElem             Helper = 88
	HelperMapPeekElem            Helper = 89
	HelperMsgPushData            Helper = 90
	HelperMsgPopData             Helper = 91
	HelperRcPointerRel           Helper = 92
	HelperSpinLock               Helper = 93
	HelperSpinUnlock             Helper = 94
	HelperSkFullsock             Helper = 95
	HelperTcpSock                Helper = 96
	HelperSkbEcnSetCe            Helper = 97
	HelperGetListenerSock        Helper = 98
	HelperSkcLookupTcp           Helper = 99
	HelperTcpCheckSyncookie      Helper = 100
	HelperSysctlGetName          Helper = 101
	HelperSysctlGetCurrentValue  Helper = 102
	HelperSysctlGetNewValue      Helper = 103
	HelperSysctlSetNewValue      Helper = 104
	HelperStrtol                 Helper = 105
	HelperStrtoul                Helper = 106
	HelperSkStorageGet           Helper = 107
	HelperSkStorageDelete        Helper = 108
	HelperSendSignal             Helper = 109
	HelperTcpGenSyncookie        Helper = 110
	HelperSkbOutput              Helper = 111
	HelperProbeReadUser          Helper = 112
	HelperProbeReadKernel        Helper = 113
	HelperProbeReadUserStr       Helper = 114
	HelperProbeReadKernelStr     Helper = 115
)
