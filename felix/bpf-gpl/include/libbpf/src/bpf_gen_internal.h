/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Facebook */
#ifndef __BPF_GEN_INTERNAL_H
#define __BPF_GEN_INTERNAL_H

#include "bpf.h"

struct ksym_relo_desc {
	const char *name;
	int kind;
	int insn_idx;
	bool is_weak;
	bool is_typeless;
	bool is_ld64;
};

struct ksym_desc {
	const char *name;
	int ref;
	int kind;
	union {
		/* used for kfunc */
		int off;
		/* used for typeless ksym */
		bool typeless;
	};
	int insn;
	bool is_ld64;
};

struct bpf_gen {
	struct gen_loader_opts *opts;
	void *data_start;
	void *data_cur;
	void *insn_start;
	void *insn_cur;
	ssize_t cleanup_label;
	__u32 nr_progs;
	__u32 nr_maps;
	int log_level;
	int error;
	struct ksym_relo_desc *relos;
	int relo_cnt;
	struct bpf_core_relo *core_relos;
	int core_relo_cnt;
	char attach_target[128];
	int attach_kind;
	struct ksym_desc *ksyms;
	__u32 nr_ksyms;
	int fd_array;
	int nr_fd_array;
};

void bpf_gen__init(struct bpf_gen *gen, int log_level, int nr_progs, int nr_maps);
int bpf_gen__finish(struct bpf_gen *gen, int nr_progs, int nr_maps);
void bpf_gen__free(struct bpf_gen *gen);
void bpf_gen__load_btf(struct bpf_gen *gen, const void *raw_data, __u32 raw_size);
void bpf_gen__map_create(struct bpf_gen *gen,
			 enum bpf_map_type map_type, const char *map_name,
			 __u32 key_size, __u32 value_size, __u32 max_entries,
			 struct bpf_map_create_opts *map_attr, int map_idx);
void bpf_gen__prog_load(struct bpf_gen *gen,
			enum bpf_prog_type prog_type, const char *prog_name,
			const char *license, struct bpf_insn *insns, size_t insn_cnt,
			struct bpf_prog_load_opts *load_attr, int prog_idx);
void bpf_gen__map_update_elem(struct bpf_gen *gen, int map_idx, void *value, __u32 value_size);
void bpf_gen__map_freeze(struct bpf_gen *gen, int map_idx);
void bpf_gen__record_attach_target(struct bpf_gen *gen, const char *name, enum bpf_attach_type type);
void bpf_gen__record_extern(struct bpf_gen *gen, const char *name, bool is_weak,
			    bool is_typeless, bool is_ld64, int kind, int insn_idx);
void bpf_gen__record_relo_core(struct bpf_gen *gen, const struct bpf_core_relo *core_relo);
void bpf_gen__populate_outer_map(struct bpf_gen *gen, int outer_map_idx, int key, int inner_map_idx);

#endif
