// Project Calico BPF dataplane programs.
// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

#ifndef __CALI_METADATA_H__
#define __CALI_METADATA_H__

/* A struct to share information between TC and XDP programs.
 * The struct must be 4 byte aligned, based on
 * samples/bpf/xdp2skb_meta_kern.c code in the Kernel source. */
struct cali_metadata {
	// Flags from cali_metadata_flags
	__u32  flags;
}__attribute__((aligned(4)));

enum cali_metadata_flags {
	// METADATA_ACCEPTED_BY_XDP is set if the packet is already accepted by XDP
	CALI_META_ACCEPTED_BY_XDP = 0x80,
};

#if CALI_F_XDP
// Set metadata to be received by TC programs
static CALI_BPF_INLINE int xdp2tc_set_metadata(struct cali_tc_ctx *ctx, __u32 flags)
{
#ifndef IPVER6
		/* XXX */
#ifndef UNITTEST
		struct cali_metadata *metadata;
		// Reserve space in-front of xdp_md.meta for metadata.
		// Drivers not supporting data_meta will fail here.
		int ret = bpf_xdp_adjust_meta(ctx->xdp, -(int)sizeof(*metadata));
		if (ret < 0) {
			CALI_DEBUG("Failed to add space for metadata: %d\n", ret);
			goto error;
		}

		if (ctx->xdp->data_meta + sizeof(struct cali_metadata) > ctx->xdp->data) {
			CALI_DEBUG("No enough space for metadata\n");
			goto error;
		}

		metadata = (void *)(unsigned long)ctx->xdp->data_meta;

		CALI_DEBUG("Set metadata for TC: %d\n", flags);
		metadata->flags = flags;
		goto metadata_ok;
#else
	/* In our unit testing we can't use XDP metadata, so we use one of the DSCP
	 * bits to indicate that the packet has been accepted.*/
	if (skb_refresh_validate_ptrs(ctx, UDP_SIZE)) {
		CALI_DEBUG("Too short\n");
		goto error;
	}

	CALI_DEBUG("IP TOS: %d\n", ip_hdr(ctx)->tos);
	ip_hdr(ctx)->tos |= CALI_META_ACCEPTED_BY_XDP;
	CALI_DEBUG("Set IP TOS: %d\n", ip_hdr(ctx)->tos);
	goto metadata_ok;
#endif
#endif

error:
	return -1;

metadata_ok:
	return 0;
}
#else /* CALI_F_XDP */

// Fetch metadata set by XDP program. If not set or on error return 0.
static CALI_BPF_INLINE __u32 xdp2tc_get_metadata(struct __sk_buff *skb) {
#ifndef IPVER6
		/* XXX */
	struct cali_metadata *metadata;
#ifndef UNITTEST
	metadata = (void *)(unsigned long)skb->data_meta;

	if (skb->data_meta + sizeof(struct cali_metadata) > skb->data) {
		CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, "No metadata is shared by XDP\n");
		goto no_metadata;
	}

	CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, "Received metadata from XDP: %d\n", metadata->flags);
	goto metadata_ok;
#else
	struct cali_tc_ctx ctx = {
		.skb = skb,
		.ipheader_len = IP_SIZE,
	};

	if (skb_refresh_validate_ptrs(&ctx, UDP_SIZE)) {
		CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, "Too short\n");
		goto no_metadata;
	}

	CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, "IP TOS: %d\n", ip_hdr(&ctx)->tos);
	struct cali_metadata unittest_metadata = {};
	unittest_metadata.flags = ip_hdr(&ctx)->tos;
	metadata = &unittest_metadata;
	ip_hdr(&ctx)->tos &= (~CALI_META_ACCEPTED_BY_XDP);
	CALI_LOG_IF(CALI_LOG_LEVEL_DEBUG, "Set IP TOS: %d\n", ip_hdr(&ctx)->tos);
	goto metadata_ok;
#endif /* UNITTEST */

no_metadata:
	return 0;

metadata_ok:
	return metadata->flags;
#else
	return 0;
#endif
}

#endif /* CALI_F_XDP */

#endif /* __CALI_METADATA_H__ */
