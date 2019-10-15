#ifndef __CALICO_POLICY_H__
#define __CALICO_POLICY_H__

struct port_range {
       __u64 ip_set_id;
       __u16 min, max;
};

struct cidr {
       __be32 mask, addr;
};

#define RULE_MATCH(id, test, negate) do { \
		if ((negate) ? (test) : !(test)) { \
			/* Match failed, skip to next rule. */ \
			CALICO_DEBUG_AT("  rule didn't match -> fall through\n"); \
			goto rule_no_match_ ## id; \
		} \
	} while (false)

#define RULE_MATCH_PROTOCOL(id, negate, protocol_number) \
	CALICO_DEBUG_AT("  check protocol %d (pkt) == %d (rule)\n", (int)ip_proto, (int)protocol_number); \
	RULE_MATCH(id, (protocol_number) == ip_proto, negate)

#define RULE_MATCH_PORT_RANGES(id, negate, saddr_or_daddr, sport_or_dport, ...) do { \
		struct port_range port_ranges[] = {__VA_ARGS__}; \
		bool match = false; \
		_Pragma("clang loop unroll(full)") \
		for (int i = 0; i < (sizeof(port_ranges)/sizeof(struct port_range)); i++) { \
			if (port_ranges[i].ip_set_id == 0) {\
				/* Normal port match*/ \
				CALICO_DEBUG_AT("  check " #sport_or_dport " against %d <= %d (pkt) <= %d\n", \
								(int)port_ranges[i].min, (int)(sport_or_dport), (int)port_ranges[i].max); \
				if ((sport_or_dport) >= port_ranges[i].min && (sport_or_dport) <= port_ranges[i].max) { \
					match = true; \
					break; \
				} \
			} else {\
				/* Named port match; actually maps through to an IP set */ \
				CALICO_DEBUG_AT("  look up " #saddr_or_daddr ":port (%x:%d) in IP set %llx\n", \
						        be32_to_host(saddr_or_daddr), (int)(sport_or_dport), port_ranges[i].ip_set_id); \
				union ip4_set_bpf_lpm_trie_key k; \
				k.ip.mask = sizeof(struct ip4setkey)*8 ; \
				k.ip.set_id = host_to_be64(port_ranges[i].ip_set_id); \
				k.ip.addr = saddr_or_daddr; \
				k.ip.port = (sport_or_dport); \
				k.ip.protocol = ip_proto; \
				k.ip.pad = 0; \
				if (bpf_map_lookup_elem(&calico_ip_sets, &k)) { \
					match=true; \
					break; \
				} \
			}\
		} \
		RULE_MATCH(id, match, negate); \
	} while (false)

#define RULE_MATCH_CIDRS(id, negate, saddr_or_daddr, ...) do { \
		struct cidr cidrs[] = {__VA_ARGS__}; \
		bool match = false; \
		_Pragma("clang loop unroll(full)") \
		for (int i = 0; i < (sizeof(cidrs)/sizeof(struct cidr)); i++) { \
			if ((saddr_or_daddr & host_to_be32(cidrs[i].mask)) == \
			      host_to_be32(cidrs[i].addr)) { \
				match = true; \
				break; \
			} \
		} \
		RULE_MATCH(id, match, negate); \
	} while (false)

#define RULE_MATCH_IP_SET(id, negate, saddr_or_daddr, ip_set_id) do { \
		CALICO_DEBUG_AT("  look up " #saddr_or_daddr " (%x) in IP set " #ip_set_id "\n", be32_to_host(saddr_or_daddr)); \
		bool match = false; \
		union ip4_set_bpf_lpm_trie_key k; \
		k.ip.mask = sizeof(struct ip4setkey)*8 ; \
		k.ip.set_id = host_to_be64(ip_set_id); \
		k.ip.addr = saddr_or_daddr; \
		k.ip.protocol = 0; \
		k.ip.port = 0; \
		k.ip.pad = 0; \
		if (bpf_map_lookup_elem(&calico_ip_sets, &k)) { \
			match=true; \
		} \
		RULE_MATCH(id, match, negate); \
	} while (false)


#define RULE_START(id) \
	CALICO_DEBUG_AT("Rule " #id " \n");

#define RULE_END(id, action) \
	CALICO_DEBUG_AT("  MATCH -> " #action "\n"); \
	goto action; /* Reach here if the rule matched. */ \
	rule_no_match_ ## id: do {;} while (false)


#endif /* __CALICO_POLICY_H__ */
