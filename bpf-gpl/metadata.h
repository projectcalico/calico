// Project Calico BPF dataplane programs.
// Copyright (c) 2021 Tigera, Inc. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#ifndef __CALI_METADATA_H__
#define __CALI_METADATA_H__

/* A struct to share information between TC and XDP programs.
 * The struct must be 4 byte aligned, based on
 * samples/bpf/xdp2skb_meta_kern.c code in the Kernel source. */
struct cali_metadata {
	// Flags from parsing_metadata_flags
	__u32  flags;
}__attribute__((aligned(4)));

enum cali_metadata_flags {
	// METADATA_ACCEPTED_BY_XDP is set if the packet is already accepted by XDP
	CALI_META_ACCEPTED_BY_XDP = 0x01,
};

// Set metadata to be received by TC programs
static CALI_BPF_INLINE int xdp2tc_set_metadata(struct xdp_md *xdp, __u32 flags) {
	if (CALI_F_XDP) {
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
	} else {
		CALI_DEBUG("Setting metadata in TC no supported\n");
		return PARSING_ERROR;
	}
}

// Fetch metadata set by XDP program. If not set or on error return 0.
static CALI_BPF_INLINE __u32 xdp2tc_get_metadata(struct __sk_buff *skb) {
	if (CALI_F_FROM_HEP && !CALI_F_XDP) {
		struct cali_metadata *metadata = (void *)(unsigned long)skb->data_meta;

		if (skb->data_meta + sizeof(struct cali_metadata) > skb->data) {
			CALI_DEBUG("No metadata is shared by XDP\n");
			return 0;
		}

		CALI_DEBUG("Received metadata from XDP: %d\n", metadata->flags);
		return metadata->flags;
	} else {
		CALI_DEBUG("Fetching metadata from XDP not supported in this hook\n");
		return 0;
	}
}

#endif
