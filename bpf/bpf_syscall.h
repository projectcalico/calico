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
#include <sys/syscall.h>

union bpf_attr *bpf_attr_alloc();
void bpf_attr_setup_obj_get(union bpf_attr *attr, char *path, __u32 flags);
void bpf_attr_setup_obj_get_id(union bpf_attr *attr, __u32 id, __u32 flags);
void bpf_attr_setup_obj_pin(union bpf_attr *attr, char *path, __u32 fd,
								__u32 flags);
void bpf_attr_setup_map_elem(union bpf_attr *attr, __u32 map_fd, void *pointer_to_key, 
					void *pointer_to_value, __u64 flags);
void bpf_attr_setup_map_get_next_key(union bpf_attr *attr, __u32 map_fd, 
					void *key, void *next_key, __u64 flags);
void bpf_attr_setup_map_elem_for_delete(union bpf_attr *attr, __u32 map_fd, 
							void *pointer_to_key);
void bpf_attr_setup_load_prog(union bpf_attr *attr, __u32 prog_type, 
				__u32 insn_count, void *insns, char *license, 
				__u32 log_level, __u32 log_size, void *log_buf);
void bpf_attr_setup_prog_run(union bpf_attr *attr, __u32 prog_fd,
                             __u32 data_size_in, void *data_in,
                             __u32 data_size_out, void *data_out,
                             __u32 repeat);
void bpf_attr_setup_get_info(union bpf_attr *attr, __u32 map_fd,
                             __u32 info_size, void *info);
__u32 bpf_attr_prog_run_retval(union bpf_attr *attr);
__u32 bpf_attr_prog_run_data_out_size(union bpf_attr *attr);
__u32 bpf_attr_prog_run_duration(union bpf_attr *attr);
int bpf_map_call(int cmd, __u32 map_fd, void *pointer_to_key, void *pointer_to_value, __u64 flags);
int bpf_map_load_multi(__u32 map_fd,
                       void *current_key,
                       int max_num,
                       int key_stride,
                       void *keys_out,
                       int value_stride,
                       void *values_out);

