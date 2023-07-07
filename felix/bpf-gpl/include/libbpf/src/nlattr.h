/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * NETLINK      Netlink attributes
 *
 * Copyright (c) 2003-2013 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __LIBBPF_NLATTR_H
#define __LIBBPF_NLATTR_H

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>

/* avoid multiple definition of netlink features */
#define __LINUX_NETLINK_H

/**
 * Standard attribute types to specify validation policy
 */
enum {
	LIBBPF_NLA_UNSPEC,	/**< Unspecified type, binary data chunk */
	LIBBPF_NLA_U8,		/**< 8 bit integer */
	LIBBPF_NLA_U16,		/**< 16 bit integer */
	LIBBPF_NLA_U32,		/**< 32 bit integer */
	LIBBPF_NLA_U64,		/**< 64 bit integer */
	LIBBPF_NLA_STRING,	/**< NUL terminated character string */
	LIBBPF_NLA_FLAG,	/**< Flag */
	LIBBPF_NLA_MSECS,	/**< Micro seconds (64bit) */
	LIBBPF_NLA_NESTED,	/**< Nested attributes */
	__LIBBPF_NLA_TYPE_MAX,
};

#define LIBBPF_NLA_TYPE_MAX (__LIBBPF_NLA_TYPE_MAX - 1)

/**
 * @ingroup attr
 * Attribute validation policy.
 *
 * See section @core_doc{core_attr_parse,Attribute Parsing} for more details.
 */
struct libbpf_nla_policy {
	/** Type of attribute or LIBBPF_NLA_UNSPEC */
	uint16_t	type;

	/** Minimal length of payload required */
	uint16_t	minlen;

	/** Maximal length of payload allowed */
	uint16_t	maxlen;
};

struct libbpf_nla_req {
	struct nlmsghdr nh;
	union {
		struct ifinfomsg ifinfo;
		struct tcmsg tc;
		struct genlmsghdr gnl;
	};
	char buf[128];
};

/**
 * @ingroup attr
 * Iterate over a stream of attributes
 * @arg pos	loop counter, set to current attribute
 * @arg head	head of attribute stream
 * @arg len	length of attribute stream
 * @arg rem	initialized to len, holds bytes currently remaining in stream
 */
#define libbpf_nla_for_each_attr(pos, head, len, rem) \
	for (pos = head, rem = len; \
	     nla_ok(pos, rem); \
	     pos = nla_next(pos, &(rem)))

/**
 * libbpf_nla_data - head of payload
 * @nla: netlink attribute
 */
static inline void *libbpf_nla_data(const struct nlattr *nla)
{
	return (void *)nla + NLA_HDRLEN;
}

static inline uint8_t libbpf_nla_getattr_u8(const struct nlattr *nla)
{
	return *(uint8_t *)libbpf_nla_data(nla);
}

static inline uint16_t libbpf_nla_getattr_u16(const struct nlattr *nla)
{
	return *(uint16_t *)libbpf_nla_data(nla);
}

static inline uint32_t libbpf_nla_getattr_u32(const struct nlattr *nla)
{
	return *(uint32_t *)libbpf_nla_data(nla);
}

static inline uint64_t libbpf_nla_getattr_u64(const struct nlattr *nla)
{
	return *(uint64_t *)libbpf_nla_data(nla);
}

static inline const char *libbpf_nla_getattr_str(const struct nlattr *nla)
{
	return (const char *)libbpf_nla_data(nla);
}

/**
 * libbpf_nla_len - length of payload
 * @nla: netlink attribute
 */
static inline int libbpf_nla_len(const struct nlattr *nla)
{
	return nla->nla_len - NLA_HDRLEN;
}

int libbpf_nla_parse(struct nlattr *tb[], int maxtype, struct nlattr *head,
		     int len, struct libbpf_nla_policy *policy);
int libbpf_nla_parse_nested(struct nlattr *tb[], int maxtype,
			    struct nlattr *nla,
			    struct libbpf_nla_policy *policy);

int libbpf_nla_dump_errormsg(struct nlmsghdr *nlh);

static inline struct nlattr *nla_data(struct nlattr *nla)
{
	return (struct nlattr *)((void *)nla + NLA_HDRLEN);
}

static inline struct nlattr *req_tail(struct libbpf_nla_req *req)
{
	return (struct nlattr *)((void *)req + NLMSG_ALIGN(req->nh.nlmsg_len));
}

static inline int nlattr_add(struct libbpf_nla_req *req, int type,
			     const void *data, int len)
{
	struct nlattr *nla;

	if (NLMSG_ALIGN(req->nh.nlmsg_len) + NLA_ALIGN(NLA_HDRLEN + len) > sizeof(*req))
		return -EMSGSIZE;
	if (!!data != !!len)
		return -EINVAL;

	nla = req_tail(req);
	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + len;
	if (data)
		memcpy(nla_data(nla), data, len);
	req->nh.nlmsg_len = NLMSG_ALIGN(req->nh.nlmsg_len) + NLA_ALIGN(nla->nla_len);
	return 0;
}

static inline struct nlattr *nlattr_begin_nested(struct libbpf_nla_req *req, int type)
{
	struct nlattr *tail;

	tail = req_tail(req);
	if (nlattr_add(req, type | NLA_F_NESTED, NULL, 0))
		return NULL;
	return tail;
}

static inline void nlattr_end_nested(struct libbpf_nla_req *req,
				     struct nlattr *tail)
{
	tail->nla_len = (void *)req_tail(req) - (void *)tail;
}

#endif /* __LIBBPF_NLATTR_H */
