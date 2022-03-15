// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALICO_TCV6_H__
#define __CALICO_TCV6_H__

SEC("classifier/tc/prologue_v6")
int calico_tc_v6(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering IPv6 prologue program\n");
	// TODO: Replace this logic with the proper implementation, and finally a tail call
	// to the policy program
	return TC_ACT_SHOT;
}

SEC("classifier/tc/accept_v6")
int calico_tc_v6_skb_accepted_entrypoint(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering IPv6 accepted program\n");
	// TODO: Implement the logic for accepted packets by the policy program
	// We should not reach here since no tail call happens to this program
	return TC_ACT_SHOT;
}

SEC("classifier/tc/icmp_v6")
int calico_tc_v6_skb_send_icmp_replies(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering IPv6 icmp program\n");
	// TODO: Implement the logic for accepted icmp packets by the policy program
	// We should not reach here since no tail call happens to this program
	return TC_ACT_SHOT;
}

SEC("classifier/tc/drop_v6")
int calico_tc_v6_skb_drop(struct __sk_buff *skb)
{
	CALI_DEBUG("Entering IPv6 drop program\n");
	// TODO: Implement the logic for dropped packets by the policy program
	// We should not reach here since no tail call happens to this program
	return TC_ACT_SHOT;
}

#endif /* __CALICO_TCV6_H__ */
