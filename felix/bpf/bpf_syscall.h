// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <linux/bpf.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/syscall.h>

#include "bpf.h"
#include "libbpf.h"

union bpf_attr *bpf_attr_alloc() {
   union bpf_attr *attr = malloc(sizeof(union bpf_attr));
   memset(attr, 0, sizeof(union bpf_attr));
   return attr;
}
// bpf_attr_setup_obj_get sets up the bpf_attr union for use with BPF_OBJ_GET.
// A C function makes this easier because unions aren't easy to access from Go.
void bpf_attr_setup_obj_get(union bpf_attr *attr, char *path, __u32 flags) {
   attr->pathname = (__u64)(unsigned long)path;
   attr->bpf_fd = 0;
   attr->file_flags = flags;
}

// bpf_attr_setup_obj_get_id sets up the bpf_attr union for use with BPF_XXX_GET_FD_BY_ID.
// A C function makes this easier because unions aren't easy to access from Go.
void bpf_attr_setup_obj_get_id(union bpf_attr *attr, __u32 id, __u32 flags) {
   attr->map_id = id;
   attr->open_flags = flags;
}

// bpf_attr_setup_obj_pin sets up the bpf_attr union for use with BPF_OBJ_PIN.
// A C function makes this easier because unions aren't easy to access from Go.
void bpf_attr_setup_obj_pin(union bpf_attr *attr, char *path, __u32 fd, __u32 flags) {
   attr->pathname = (__u64)(unsigned long)path;
   attr->bpf_fd = fd;
   attr->file_flags = flags;
}

int bpf_load_prog(char *name, __u32 prog_type, __u32 attach_type,
		  void *insns, __u32 insn_count,
		  char *license, __u32 log_level,
		  __u32 log_size, void *log_buf)
{
	DECLARE_LIBBPF_OPTS(bpf_prog_load_opts, opts,
		.log_level = log_level,
		.log_size = log_size,
		.log_buf = log_buf,
		.kern_version = 0,
		.expected_attach_type = attach_type,
	);
	if (name) {
		for (int i = 0; i < BPF_OBJ_NAME_LEN; i++) {
			if (name[i] == '\0') {
				break;
			}
			if (isalnum(name[i]) || name[i] == '_' || name[i] == '.')
				continue;
			name[i] = '_';
		}
	}

	int fd = bpf_prog_load(prog_type, name, license, insns, insn_count, &opts);
	if (fd < 0)
		errno = -fd;
	return fd;
}

// bpf_attr_setup_prog_run sets up the bpf_attr union for use with BPF_PROG_TEST_RUN.
// A C function makes this easier because unions aren't easy to access from Go.
void bpf_attr_setup_prog_run(union bpf_attr *attr, __u32 prog_fd,
                             __u32 data_size_in, void *data_in,
                             __u32 data_size_out, void *data_out,
                             __u32 repeat) {
   attr->test.prog_fd = prog_fd;
   attr->test.data_size_in = data_size_in;
   attr->test.data_size_out = data_size_out;
   attr->test.data_in = (__u64)(unsigned long)data_in;
   attr->test.data_out = (__u64)(unsigned long)data_out;
   attr->test.repeat = repeat;
}

// bpf_attr_setup_get_info sets up the bpf_attr union for use with BPF_OBJ_GET_INFO_BY_FD.
// A C function makes this easier because unions aren't easy to access from Go.
void bpf_attr_setup_get_info(union bpf_attr *attr, __u32 map_fd,
                             __u32 info_size, void *info) {
   attr->info.bpf_fd = map_fd;
   attr->info.info_len = info_size;
   attr->info.info = (__u64)(unsigned long)info;
}

__u32 bpf_attr_prog_run_retval(union bpf_attr *attr) {
   return attr->test.retval;
}

__u32 bpf_attr_prog_run_data_out_size(union bpf_attr *attr) {
   return attr->test.data_size_out;
}

__u32 bpf_attr_prog_run_duration(union bpf_attr *attr) {
   return attr->test.duration;
}
