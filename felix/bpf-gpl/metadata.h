// Project Calico BPF dataplane programs.
// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

// Set metadata to be received by TC programs
static CALI_BPF_INLINE int xdp2tc_set_metadata(struct xdp_md *xdp, __u32 flags) {
	if (CALI_F_XDP) {
#ifndef UNITTEST
		struct cali_metadata *metadata;
		// Reserve space in-front of xdp_md.meta for metadata.
		// Drivers not supporting data_meta will fail here.
		int ret = bpf_xdp_adjust_meta(xdp, -(int)sizeof(*metadata));
		if (ret < 0) {
			CALI_DEBUG("Failed to add space for metadata: %d\n", ret);
			return PARSING_ERROR;
		}

		if (xdp->data_meta + sizeof(struct cali_metadata) > xdp->data) {
			CALI_DEBUG("No enough space for metadata\n");
			return PARSING_ERROR;
		}

		metadata = (void *)(unsigned long)xdp->data_meta;

		CALI_DEBUG("Set metadata for TC: %d\n", flags);
		metadata->flags = flags;
		return PARSING_OK;
#else
	/* In our unit testing we can't use XDP metadata, so we use one of the DSCP
	 * bits to indicate that the packet has been accepted.*/
	struct cali_tc_ctx ctx = {
		.xdp = xdp,
	};

	if (skb_refresh_validate_ptrs(&ctx, UDP_SIZE)) {
		CALI_DEBUG("Too short\n");
		return PARSING_ERROR;
	}

	CALI_DEBUG("IP TOS: %d\n", ctx.ip_header->tos);
	ctx.ip_header->tos |= CALI_META_ACCEPTED_BY_XDP;
	CALI_DEBUG("Set IP TOS: %d\n", ctx.ip_header->tos);
	return PARSING_OK;
#endif
	} else {
		CALI_DEBUG("Setting metadata is not supported in TC\n");
		return PARSING_ERROR;
	}
}

// Fetch metadata set by XDP program. If not set or on error return 0.
static CALI_BPF_INLINE __u32 xdp2tc_get_metadata(struct __sk_buff *skb) {
	if (CALI_F_FROM_HEP && !CALI_F_XDP) {
#ifndef UNITTEST
		struct cali_metadata *metadata = (void *)(unsigned long)skb->data_meta;

		if (skb->data_meta + sizeof(struct cali_metadata) > skb->data) {
			CALI_DEBUG("No metadata is shared by XDP\n");
			return 0;
		}

		CALI_DEBUG("Received metadata from XDP: %d\n", metadata->flags);
		return metadata->flags;
#else
	struct cali_tc_ctx ctx = {
		.skb = skb,
	};

	if (skb_refresh_validate_ptrs(&ctx, UDP_SIZE)) {
		CALI_DEBUG("Too short\n");
		return PARSING_ERROR;
	}

	CALI_DEBUG("IP TOS: %d\n", ctx.ip_header->tos);
	__u32 metadata = ctx.ip_header->tos;
	ctx.ip_header->tos &= (~CALI_META_ACCEPTED_BY_XDP);
	CALI_DEBUG("Set IP TOS: %d\n", ctx.ip_header->tos);
	return metadata;
#endif
	} else {
		CALI_DEBUG("Fetching metadata from XDP not supported in this hook\n");
		return 0;
	}
}

#endif
