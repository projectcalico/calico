#include "tc.c"

static CALI_BPF_INLINE int calico_unittest_entry (struct __sk_buff *skb);

__attribute__((section("calico_unittest"))) int unittest(struct __sk_buff *skb)
{
	return calico_unittest_entry(skb);
}
