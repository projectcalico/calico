#ifndef __CALI_ALLOWSOURCES_H__
#define __CALI_ALLOWSOURCES_H__

#include <linux/in.h>
#include "bpf.h"

#define IPV4_ADDR_BITS 32
#define IPV6_ADDR_BITS 128
#define IFINDEX_BITS 32

// WARNING: must be kept in sync with the definitions in bpf/allowsources/map.go
struct allow_sources_key {
    __u32 prefixlen;
    __u32 ifindex;
    ipv46_addr_t addr;
} __attribute__((packed));


#ifdef IPVER6
CALI_MAP_NAMED(cali_v6_sprefix, cali_sprefix,,
#else
CALI_MAP_NAMED(cali_v4_sprefix, cali_sprefix,,
#endif
    BPF_MAP_TYPE_LPM_TRIE,
    struct allow_sources_key,
    __u32,
    1024*1024,
    BPF_F_NO_PREALLOC)

static CALI_BPF_INLINE bool cali_allowsource_lookup(ipv46_addr_t *addr, __u32 ifindex)
{
    struct allow_sources_key k;
#ifdef IPVER6
    k.prefixlen = IPV6_ADDR_BITS + IFINDEX_BITS;
#else
    k.prefixlen = IPV4_ADDR_BITS + IFINDEX_BITS;
#endif
    k.addr = *addr;
    k.ifindex = ifindex;
    return cali_sprefix_lookup_elem(&k);
}

# endif /* __CALI_ALLOWSOURCES_H__ */
