/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * Internal libbpf helpers.
 *
 * Copyright (c) 2019 Facebook
 */

#ifndef __LIBBPF_LIBBPF_INTERNAL_H
#define __LIBBPF_LIBBPF_INTERNAL_H

#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <linux/err.h>
#include <fcntl.h>
#include <unistd.h>
#include "relo_core.h"

/* make sure libbpf doesn't use kernel-only integer typedefs */
#pragma GCC poison u8 u16 u32 u64 s8 s16 s32 s64

/* prevent accidental re-addition of reallocarray() */
#pragma GCC poison reallocarray

#include "libbpf.h"
#include "btf.h"

#ifndef EM_BPF
#define EM_BPF 247
#endif

#ifndef R_BPF_64_64
#define R_BPF_64_64 1
#endif
#ifndef R_BPF_64_ABS64
#define R_BPF_64_ABS64 2
#endif
#ifndef R_BPF_64_ABS32
#define R_BPF_64_ABS32 3
#endif
#ifndef R_BPF_64_32
#define R_BPF_64_32 10
#endif

#ifndef SHT_LLVM_ADDRSIG
#define SHT_LLVM_ADDRSIG 0x6FFF4C03
#endif

/* if libelf is old and doesn't support mmap(), fall back to read() */
#ifndef ELF_C_READ_MMAP
#define ELF_C_READ_MMAP ELF_C_READ
#endif

/* Older libelf all end up in this expression, for both 32 and 64 bit */
#ifndef ELF64_ST_VISIBILITY
#define ELF64_ST_VISIBILITY(o) ((o) & 0x03)
#endif

#define BTF_INFO_ENC(kind, kind_flag, vlen) \
	((!!(kind_flag) << 31) | ((kind) << 24) | ((vlen) & BTF_MAX_VLEN))
#define BTF_TYPE_ENC(name, info, size_or_type) (name), (info), (size_or_type)
#define BTF_INT_ENC(encoding, bits_offset, nr_bits) \
	((encoding) << 24 | (bits_offset) << 16 | (nr_bits))
#define BTF_TYPE_INT_ENC(name, encoding, bits_offset, bits, sz) \
	BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_INT, 0, 0), sz), \
	BTF_INT_ENC(encoding, bits_offset, bits)
#define BTF_MEMBER_ENC(name, type, bits_offset) (name), (type), (bits_offset)
#define BTF_PARAM_ENC(name, type) (name), (type)
#define BTF_VAR_SECINFO_ENC(type, offset, size) (type), (offset), (size)
#define BTF_TYPE_FLOAT_ENC(name, sz) \
	BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_FLOAT, 0, 0), sz)
#define BTF_TYPE_DECL_TAG_ENC(value, type, component_idx) \
	BTF_TYPE_ENC(value, BTF_INFO_ENC(BTF_KIND_DECL_TAG, 0, 0), type), (component_idx)
#define BTF_TYPE_TYPE_TAG_ENC(value, type) \
	BTF_TYPE_ENC(value, BTF_INFO_ENC(BTF_KIND_TYPE_TAG, 0, 0), type)

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef min
# define min(x, y) ((x) < (y) ? (x) : (y))
#endif
#ifndef max
# define max(x, y) ((x) < (y) ? (y) : (x))
#endif
#ifndef offsetofend
# define offsetofend(TYPE, FIELD) \
	(offsetof(TYPE, FIELD) + sizeof(((TYPE *)0)->FIELD))
#endif
#ifndef __alias
#define __alias(symbol) __attribute__((alias(#symbol)))
#endif

/* Check whether a string `str` has prefix `pfx`, regardless if `pfx` is
 * a string literal known at compilation time or char * pointer known only at
 * runtime.
 */
#define str_has_pfx(str, pfx) \
	(strncmp(str, pfx, __builtin_constant_p(pfx) ? sizeof(pfx) - 1 : strlen(pfx)) == 0)

/* suffix check */
static inline bool str_has_sfx(const char *str, const char *sfx)
{
	size_t str_len = strlen(str);
	size_t sfx_len = strlen(sfx);

	if (sfx_len > str_len)
		return false;
	return strcmp(str + str_len - sfx_len, sfx) == 0;
}

/* Symbol versioning is different between static and shared library.
 * Properly versioned symbols are needed for shared library, but
 * only the symbol of the new version is needed for static library.
 * Starting with GNU C 10, use symver attribute instead of .symver assembler
 * directive, which works better with GCC LTO builds.
 */
#if defined(SHARED) && defined(__GNUC__) && __GNUC__ >= 10

#define DEFAULT_VERSION(internal_name, api_name, version) \
	__attribute__((symver(#api_name "@@" #version)))
#define COMPAT_VERSION(internal_name, api_name, version) \
	__attribute__((symver(#api_name "@" #version)))

#elif defined(SHARED)

#define COMPAT_VERSION(internal_name, api_name, version) \
	asm(".symver " #internal_name "," #api_name "@" #version);
#define DEFAULT_VERSION(internal_name, api_name, version) \
	asm(".symver " #internal_name "," #api_name "@@" #version);

#else /* !SHARED */

#define COMPAT_VERSION(internal_name, api_name, version)
#define DEFAULT_VERSION(internal_name, api_name, version) \
	extern typeof(internal_name) api_name \
	__attribute__((alias(#internal_name)));

#endif

extern void libbpf_print(enum libbpf_print_level level,
			 const char *format, ...)
	__attribute__((format(printf, 2, 3)));

#define __pr(level, fmt, ...)	\
do {				\
	libbpf_print(level, "libbpf: " fmt, ##__VA_ARGS__);	\
} while (0)

#define pr_warn(fmt, ...)	__pr(LIBBPF_WARN, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)	__pr(LIBBPF_INFO, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)	__pr(LIBBPF_DEBUG, fmt, ##__VA_ARGS__)

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

struct bpf_link {
	int (*detach)(struct bpf_link *link);
	void (*dealloc)(struct bpf_link *link);
	char *pin_path;		/* NULL, if not pinned */
	int fd;			/* hook FD, -1 if not applicable */
	bool disconnected;
};

/*
 * Re-implement glibc's reallocarray() for libbpf internal-only use.
 * reallocarray(), unfortunately, is not available in all versions of glibc,
 * so requires extra feature detection and using reallocarray() stub from
 * <tools/libc_compat.h> and COMPAT_NEED_REALLOCARRAY. All this complicates
 * build of libbpf unnecessarily and is just a maintenance burden. Instead,
 * it's trivial to implement libbpf-specific internal version and use it
 * throughout libbpf.
 */
static inline void *libbpf_reallocarray(void *ptr, size_t nmemb, size_t size)
{
	size_t total;

#if __has_builtin(__builtin_mul_overflow)
	if (unlikely(__builtin_mul_overflow(nmemb, size, &total)))
		return NULL;
#else
	if (size == 0 || nmemb > ULONG_MAX / size)
		return NULL;
	total = nmemb * size;
#endif
	return realloc(ptr, total);
}

/* Copy up to sz - 1 bytes from zero-terminated src string and ensure that dst
 * is zero-terminated string no matter what (unless sz == 0, in which case
 * it's a no-op). It's conceptually close to FreeBSD's strlcpy(), but differs
 * in what is returned. Given this is internal helper, it's trivial to extend
 * this, when necessary. Use this instead of strncpy inside libbpf source code.
 */
static inline void libbpf_strlcpy(char *dst, const char *src, size_t sz)
{
	size_t i;

	if (sz == 0)
		return;

	sz--;
	for (i = 0; i < sz && src[i]; i++)
		dst[i] = src[i];
	dst[i] = '\0';
}

__u32 get_kernel_version(void);

struct btf;
struct btf_type;

struct btf_type *btf_type_by_id(const struct btf *btf, __u32 type_id);
const char *btf_kind_str(const struct btf_type *t);
const struct btf_type *skip_mods_and_typedefs(const struct btf *btf, __u32 id, __u32 *res_id);

static inline enum btf_func_linkage btf_func_linkage(const struct btf_type *t)
{
	return (enum btf_func_linkage)(int)btf_vlen(t);
}

static inline __u32 btf_type_info(int kind, int vlen, int kflag)
{
	return (kflag << 31) | (kind << 24) | vlen;
}

enum map_def_parts {
	MAP_DEF_MAP_TYPE	= 0x001,
	MAP_DEF_KEY_TYPE	= 0x002,
	MAP_DEF_KEY_SIZE	= 0x004,
	MAP_DEF_VALUE_TYPE	= 0x008,
	MAP_DEF_VALUE_SIZE	= 0x010,
	MAP_DEF_MAX_ENTRIES	= 0x020,
	MAP_DEF_MAP_FLAGS	= 0x040,
	MAP_DEF_NUMA_NODE	= 0x080,
	MAP_DEF_PINNING		= 0x100,
	MAP_DEF_INNER_MAP	= 0x200,
	MAP_DEF_MAP_EXTRA	= 0x400,

	MAP_DEF_ALL		= 0x7ff, /* combination of all above */
};

struct btf_map_def {
	enum map_def_parts parts;
	__u32 map_type;
	__u32 key_type_id;
	__u32 key_size;
	__u32 value_type_id;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 numa_node;
	__u32 pinning;
	__u64 map_extra;
};

int parse_btf_map_def(const char *map_name, struct btf *btf,
		      const struct btf_type *def_t, bool strict,
		      struct btf_map_def *map_def, struct btf_map_def *inner_def);

void *libbpf_add_mem(void **data, size_t *cap_cnt, size_t elem_sz,
		     size_t cur_cnt, size_t max_cnt, size_t add_cnt);
int libbpf_ensure_mem(void **data, size_t *cap_cnt, size_t elem_sz, size_t need_cnt);

static inline bool libbpf_is_mem_zeroed(const char *p, ssize_t len)
{
	while (len > 0) {
		if (*p)
			return false;
		p++;
		len--;
	}
	return true;
}

static inline bool libbpf_validate_opts(const char *opts,
					size_t opts_sz, size_t user_sz,
					const char *type_name)
{
	if (user_sz < sizeof(size_t)) {
		pr_warn("%s size (%zu) is too small\n", type_name, user_sz);
		return false;
	}
	if (!libbpf_is_mem_zeroed(opts + opts_sz, (ssize_t)user_sz - opts_sz)) {
		pr_warn("%s has non-zero extra bytes\n", type_name);
		return false;
	}
	return true;
}

#define OPTS_VALID(opts, type)						      \
	(!(opts) || libbpf_validate_opts((const char *)opts,		      \
					 offsetofend(struct type,	      \
						     type##__last_field),     \
					 (opts)->sz, #type))
#define OPTS_HAS(opts, field) \
	((opts) && opts->sz >= offsetofend(typeof(*(opts)), field))
#define OPTS_GET(opts, field, fallback_value) \
	(OPTS_HAS(opts, field) ? (opts)->field : fallback_value)
#define OPTS_SET(opts, field, value)		\
	do {					\
		if (OPTS_HAS(opts, field))	\
			(opts)->field = value;	\
	} while (0)

#define OPTS_ZEROED(opts, last_nonzero_field)				      \
({									      \
	ssize_t __off = offsetofend(typeof(*(opts)), last_nonzero_field);     \
	!(opts) || libbpf_is_mem_zeroed((const void *)opts + __off,	      \
					(opts)->sz - __off);		      \
})

enum kern_feature_id {
	/* v4.14: kernel support for program & map names. */
	FEAT_PROG_NAME,
	/* v5.2: kernel support for global data sections. */
	FEAT_GLOBAL_DATA,
	/* BTF support */
	FEAT_BTF,
	/* BTF_KIND_FUNC and BTF_KIND_FUNC_PROTO support */
	FEAT_BTF_FUNC,
	/* BTF_KIND_VAR and BTF_KIND_DATASEC support */
	FEAT_BTF_DATASEC,
	/* BTF_FUNC_GLOBAL is supported */
	FEAT_BTF_GLOBAL_FUNC,
	/* BPF_F_MMAPABLE is supported for arrays */
	FEAT_ARRAY_MMAP,
	/* kernel support for expected_attach_type in BPF_PROG_LOAD */
	FEAT_EXP_ATTACH_TYPE,
	/* bpf_probe_read_{kernel,user}[_str] helpers */
	FEAT_PROBE_READ_KERN,
	/* BPF_PROG_BIND_MAP is supported */
	FEAT_PROG_BIND_MAP,
	/* Kernel support for module BTFs */
	FEAT_MODULE_BTF,
	/* BTF_KIND_FLOAT support */
	FEAT_BTF_FLOAT,
	/* BPF perf link support */
	FEAT_PERF_LINK,
	/* BTF_KIND_DECL_TAG support */
	FEAT_BTF_DECL_TAG,
	/* BTF_KIND_TYPE_TAG support */
	FEAT_BTF_TYPE_TAG,
	/* memcg-based accounting for BPF maps and progs */
	FEAT_MEMCG_ACCOUNT,
	/* BPF cookie (bpf_get_attach_cookie() BPF helper) support */
	FEAT_BPF_COOKIE,
	/* BTF_KIND_ENUM64 support and BTF_KIND_ENUM kflag support */
	FEAT_BTF_ENUM64,
	/* Kernel uses syscall wrapper (CONFIG_ARCH_HAS_SYSCALL_WRAPPER) */
	FEAT_SYSCALL_WRAPPER,
	__FEAT_CNT,
};

int probe_memcg_account(void);
bool kernel_supports(const struct bpf_object *obj, enum kern_feature_id feat_id);
int bump_rlimit_memlock(void);

int parse_cpu_mask_str(const char *s, bool **mask, int *mask_sz);
int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);
int libbpf__load_raw_btf(const char *raw_types, size_t types_len,
			 const char *str_sec, size_t str_len);
int btf_load_into_kernel(struct btf *btf, char *log_buf, size_t log_sz, __u32 log_level);

struct btf *btf_get_from_fd(int btf_fd, struct btf *base_btf);
void btf_get_kernel_prefix_kind(enum bpf_attach_type attach_type,
				const char **prefix, int *kind);

struct btf_ext_info {
	/*
	 * info points to the individual info section (e.g. func_info and
	 * line_info) from the .BTF.ext. It does not include the __u32 rec_size.
	 */
	void *info;
	__u32 rec_size;
	__u32 len;
	/* optional (maintained internally by libbpf) mapping between .BTF.ext
	 * section and corresponding ELF section. This is used to join
	 * information like CO-RE relocation records with corresponding BPF
	 * programs defined in ELF sections
	 */
	__u32 *sec_idxs;
	int sec_cnt;
};

#define for_each_btf_ext_sec(seg, sec)					\
	for (sec = (seg)->info;						\
	     (void *)sec < (seg)->info + (seg)->len;			\
	     sec = (void *)sec + sizeof(struct btf_ext_info_sec) +	\
		   (seg)->rec_size * sec->num_info)

#define for_each_btf_ext_rec(seg, sec, i, rec)				\
	for (i = 0, rec = (void *)&(sec)->data;				\
	     i < (sec)->num_info;					\
	     i++, rec = (void *)rec + (seg)->rec_size)

/*
 * The .BTF.ext ELF section layout defined as
 *   struct btf_ext_header
 *   func_info subsection
 *
 * The func_info subsection layout:
 *   record size for struct bpf_func_info in the func_info subsection
 *   struct btf_sec_func_info for section #1
 *   a list of bpf_func_info records for section #1
 *     where struct bpf_func_info mimics one in include/uapi/linux/bpf.h
 *     but may not be identical
 *   struct btf_sec_func_info for section #2
 *   a list of bpf_func_info records for section #2
 *   ......
 *
 * Note that the bpf_func_info record size in .BTF.ext may not
 * be the same as the one defined in include/uapi/linux/bpf.h.
 * The loader should ensure that record_size meets minimum
 * requirement and pass the record as is to the kernel. The
 * kernel will handle the func_info properly based on its contents.
 */
struct btf_ext_header {
	__u16	magic;
	__u8	version;
	__u8	flags;
	__u32	hdr_len;

	/* All offsets are in bytes relative to the end of this header */
	__u32	func_info_off;
	__u32	func_info_len;
	__u32	line_info_off;
	__u32	line_info_len;

	/* optional part of .BTF.ext header */
	__u32	core_relo_off;
	__u32	core_relo_len;
};

struct btf_ext {
	union {
		struct btf_ext_header *hdr;
		void *data;
	};
	struct btf_ext_info func_info;
	struct btf_ext_info line_info;
	struct btf_ext_info core_relo_info;
	__u32 data_size;
};

struct btf_ext_info_sec {
	__u32	sec_name_off;
	__u32	num_info;
	/* Followed by num_info * record_size number of bytes */
	__u8	data[];
};

/* The minimum bpf_func_info checked by the loader */
struct bpf_func_info_min {
	__u32   insn_off;
	__u32   type_id;
};

/* The minimum bpf_line_info checked by the loader */
struct bpf_line_info_min {
	__u32	insn_off;
	__u32	file_name_off;
	__u32	line_off;
	__u32	line_col;
};


typedef int (*type_id_visit_fn)(__u32 *type_id, void *ctx);
typedef int (*str_off_visit_fn)(__u32 *str_off, void *ctx);
int btf_type_visit_type_ids(struct btf_type *t, type_id_visit_fn visit, void *ctx);
int btf_type_visit_str_offs(struct btf_type *t, str_off_visit_fn visit, void *ctx);
int btf_ext_visit_type_ids(struct btf_ext *btf_ext, type_id_visit_fn visit, void *ctx);
int btf_ext_visit_str_offs(struct btf_ext *btf_ext, str_off_visit_fn visit, void *ctx);
__s32 btf__find_by_name_kind_own(const struct btf *btf, const char *type_name,
				 __u32 kind);

typedef int (*kallsyms_cb_t)(unsigned long long sym_addr, char sym_type,
			     const char *sym_name, void *ctx);

int libbpf_kallsyms_parse(kallsyms_cb_t cb, void *arg);

/* handle direct returned errors */
static inline int libbpf_err(int ret)
{
	if (ret < 0)
		errno = -ret;
	return ret;
}

/* handle errno-based (e.g., syscall or libc) errors according to libbpf's
 * strict mode settings
 */
static inline int libbpf_err_errno(int ret)
{
	/* errno is already assumed to be set on error */
	return ret < 0 ? -errno : ret;
}

/* handle error for pointer-returning APIs, err is assumed to be < 0 always */
static inline void *libbpf_err_ptr(int err)
{
	/* set errno on error, this doesn't break anything */
	errno = -err;
	return NULL;
}

/* handle pointer-returning APIs' error handling */
static inline void *libbpf_ptr(void *ret)
{
	/* set errno on error, this doesn't break anything */
	if (IS_ERR(ret))
		errno = -PTR_ERR(ret);

	return IS_ERR(ret) ? NULL : ret;
}

static inline bool str_is_empty(const char *s)
{
	return !s || !s[0];
}

static inline bool is_ldimm64_insn(struct bpf_insn *insn)
{
	return insn->code == (BPF_LD | BPF_IMM | BPF_DW);
}

/* if fd is stdin, stdout, or stderr, dup to a fd greater than 2
 * Takes ownership of the fd passed in, and closes it if calling
 * fcntl(fd, F_DUPFD_CLOEXEC, 3).
 */
static inline int ensure_good_fd(int fd)
{
	int old_fd = fd, saved_errno;

	if (fd < 0)
		return fd;
	if (fd < 3) {
		fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
		saved_errno = errno;
		close(old_fd);
		errno = saved_errno;
		if (fd < 0) {
			pr_warn("failed to dup FD %d to FD > 2: %d\n", old_fd, -saved_errno);
			errno = saved_errno;
		}
	}
	return fd;
}

/* The following two functions are exposed to bpftool */
int bpf_core_add_cands(struct bpf_core_cand *local_cand,
		       size_t local_essent_len,
		       const struct btf *targ_btf,
		       const char *targ_btf_name,
		       int targ_start_id,
		       struct bpf_core_cand_list *cands);
void bpf_core_free_cands(struct bpf_core_cand_list *cands);

struct usdt_manager *usdt_manager_new(struct bpf_object *obj);
void usdt_manager_free(struct usdt_manager *man);
struct bpf_link * usdt_manager_attach_usdt(struct usdt_manager *man,
					   const struct bpf_program *prog,
					   pid_t pid, const char *path,
					   const char *usdt_provider, const char *usdt_name,
					   __u64 usdt_cookie);

static inline bool is_pow_of_2(size_t x)
{
	return x && (x & (x - 1)) == 0;
}

#define PROG_LOAD_ATTEMPTS 5
int sys_bpf_prog_load(union bpf_attr *attr, unsigned int size, int attempts);

#endif /* __LIBBPF_LIBBPF_INTERNAL_H */
