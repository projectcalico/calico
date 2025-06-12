// Project Calico BPF dataplane programs.
// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_IP_V4_FRAGMENT_H__
#define __CALI_IP_V4_FRAGMENT_H__

#include "ip_addr.h"

struct frags4_key {
	ipv4_addr_t src;
	ipv4_addr_t dst;
	__u16 id;
	__u16 offset;
};

#define MAX_FRAG 1504 /* requires multiple of 8 */

struct frags4_value {
	__u16 more_frags:1;
	__u16 len;
	__u32 __pad;
	char data[MAX_FRAG];
};

CALI_MAP(cali_v4_frags, 2, BPF_MAP_TYPE_LRU_HASH, struct frags4_key, struct frags4_value, 10000, 0)

CALI_MAP(cali_v4_frgtmp, 2,
		BPF_MAP_TYPE_PERCPU_ARRAY,
		__u32, struct frags4_value,
		1, 0)

CALI_MAP(cali_v4_frgfwd, 2, BPF_MAP_TYPE_LRU_HASH, struct frags4_fwd_key, __u32, 10000, 0)

struct frags4_fwd_key {
	ipv4_addr_t src;
	ipv4_addr_t dst;
	__u32 ifindex; /* The stream of fragments may be crossing multiple devices */
	__u16 id;
	__u16 __pad;
};

static CALI_BPF_INLINE struct frags4_value *frags4_get_scratch()
{
	__u32 key = 0;
	return cali_v4_frgtmp_lookup_elem(&key);
}

static CALI_BPF_INLINE bool frags4_try_assemble(struct cali_tc_ctx *ctx)
{
	struct frags4_key k = {
		.src = ip_hdr(ctx)->saddr,
		.dst = ip_hdr(ctx)->daddr,
		.id = ip_hdr(ctx)->id,
	};

	int i, tot_len = 0;

	for (i = 0; i < 10; i++) {
		struct frags4_value *v = cali_v4_frags_lookup_elem(&k);

		if (!v) {
			CALI_DEBUG("Missing IP fragment at offset %d", k.offset);
			return false;
		}

		tot_len += v->len;

		if(!v->more_frags) {
			goto assemble;
		}

		k.offset += v->len;
	}

	return false;

assemble:
	CALI_DEBUG("IP FRAG: Found all fragments!");

	int off = skb_l4hdr_offset(ctx);
	int err = bpf_skb_change_tail(ctx->skb, off + tot_len,  0);
	if (err) {
		CALI_DEBUG("IP FRAG: bpf_skb_change_tail (len=%d) failed (err=%d)", tot_len, err);
		goto out;
	}

	k.offset = 0;

	for (i = 0; i < 10; i++) {
		struct frags4_value *v = cali_v4_frags_lookup_elem(&k);

		if (!v) {
			CALI_DEBUG("IP FRAG: Missing IP fragment at offset %d", k.offset);
			goto out;
		}

		__u16 len = v->len;
		if (len == 0 || len > MAX_FRAG) {
			goto out;
		}
		CALI_DEBUG("IP FRAG: copy %d bytes to %d", len, off);
		if (bpf_skb_store_bytes(ctx->skb, off, v->data, len, 0)) {
			CALI_DEBUG("IP FRAG: Failed to copy bytes");
			goto out;
		}

		bool last = !v->more_frags;
		cali_v4_frags_delete_elem(&k);

		if(last) {
			break;
		}

		k.offset += v->len;
		off += v->len;
	}

	if (parse_packet_ip(ctx) != PARSING_OK) {
		goto out;
	}

	/* recalculate IP csum of the restored IP header */
	ip_hdr(ctx)->check = 0;
	ip_hdr(ctx)->frag_off = 0;
	ip_hdr(ctx)->tot_len =  bpf_htons(ip_hdr(ctx)->ihl*4 + tot_len);

	__wsum ip_csum = bpf_csum_diff(0, 0, (__u32 *)ctx->ip_header, sizeof(struct iphdr), 0);
	int ret = bpf_l3_csum_replace(ctx->skb, skb_iphdr_offset(ctx) + offsetof(struct iphdr, check), 0, ip_csum, 0);
	if (ret) {
		CALI_DEBUG("IP FRAG: set L3 csum failed");
		goto out;
	}

	/* No need to recalculate L4 csum as the concatenated data should be intact. In
	 * case of TCP/UDP, the pseudo IP header used to calculate the checksum does not
	 * change src/dst IP, protocol and UDP/TCP length stay the same.
	 */

	if (parse_packet_ip(ctx) != PARSING_OK) {
		goto out;
	}

	return true;
out:
	return false;
}

static CALI_BPF_INLINE bool frags4_handle(struct cali_tc_ctx *ctx)
{
	struct frags4_value *v = frags4_get_scratch();

	if (!v) {
		goto out;
	}

	struct frags4_key k = {
		.src = ip_hdr(ctx)->saddr,
		.dst = ip_hdr(ctx)->daddr,
		.id = ip_hdr(ctx)->id,
		.offset = 8 * bpf_ntohs(ip_hdr(ctx)->frag_off) & 0x1fff,

	};

	int i;
	int r_off = skb_l4hdr_offset(ctx);
	bool more_frags = bpf_ntohs(ip_hdr(ctx)->frag_off) & 0x2000;

	/* When we get a fragment, it may be large than the storage in the map.
	 * We may need to break it into multiple fragments to be able to store
	 * it.
	 */
	for (i = 0; i < 10; i++) {
		int sz = MAX_FRAG;
		if (r_off + sz >= ctx->skb->len) {
			sz = ctx->skb->len - r_off;
		}
		if (sz > MAX_FRAG) {
			sz = MAX_FRAG;
		}
		if (sz <= 0) {
			goto out;
		}

		if (bpf_skb_load_bytes(ctx->skb, r_off, v->data, sz)) {
			CALI_DEBUG("IP FRAG: failed to read data");
			goto out;
		}
		v->len = (__u16)sz;
		v->more_frags = more_frags || r_off + sz < ctx->skb->len;
		CALI_DEBUG("IP FRAG: frg off %d", k.offset);
		CALI_DEBUG("IP FRAG: frg size %d r_off %d", sz, r_off);

		if (cali_v4_frags_update_elem(&k, v, 0)) {
			CALI_DEBUG("IP FRAG: Failed to save IP fragment.");
			goto out;
		}

		r_off += sz;
		k.offset += sz;
		if (r_off >= ctx->skb->len) {
			break;
		}
	}

	if (!frags4_try_assemble(ctx)) {
		goto out;
	}


	return true;

out:
	return false;
}

static CALI_BPF_INLINE void frags4_record_ct(struct cali_tc_ctx *ctx)
{
	struct frags4_fwd_key k = {
		.src = ip_hdr(ctx)->saddr,
		.dst = ip_hdr(ctx)->daddr,
		.ifindex = ctx->skb->ifindex,
		.id = ip_hdr(ctx)->id,
	};

	__u32 v = 0;

	cali_v4_frgfwd_update_elem(&k, &v, 0);
	CALI_DEBUG("IP FRAG: created ct from " IP_FMT " to " IP_FMT,
			debug_ip(ctx->state->ip_src), debug_ip(ctx->state->ip_dst));
}

static CALI_BPF_INLINE void frags4_remove_ct(struct cali_tc_ctx *ctx)
{
	struct frags4_fwd_key k = {
		.src = ip_hdr(ctx)->saddr,
		.dst = ip_hdr(ctx)->daddr,
		.ifindex = ctx->skb->ifindex,
		.id = ip_hdr(ctx)->id,
	};

	cali_v4_frgfwd_delete_elem(&k);
	CALI_DEBUG("IP FRAG: killed ct from " IP_FMT " to " IP_FMT,
			debug_ip(ctx->state->ip_src), debug_ip(ctx->state->ip_dst));
}

static CALI_BPF_INLINE bool frags4_lookup_ct(struct cali_tc_ctx *ctx)
{
	struct frags4_fwd_key k = {
		.src = ip_hdr(ctx)->saddr,
		.dst = ip_hdr(ctx)->daddr,
		.ifindex = ctx->skb->ifindex,
		.id = ip_hdr(ctx)->id,
	};

	CALI_DEBUG("IP FRAG: lookup ct from " IP_FMT " to " IP_FMT,
			debug_ip(ctx->state->ip_src), debug_ip(ctx->state->ip_dst));
	return cali_v4_frgfwd_lookup_elem(&k) != NULL;
}

#endif /* __CALI_IP_V4_FRAGMENT_H__ */
