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

// bpf_attr_setup_map_elem sets up the bpf_attr union for use with BPF_MAP_GET|UPDATE
// A C function makes this easier because unions aren't easy to access from Go.
void bpf_attr_setup_map_elem(union bpf_attr *attr, __u32 map_fd, void *pointer_to_key, void *pointer_to_value, __u64 flags) {
   attr->map_fd = map_fd;
   attr->key = (__u64)(unsigned long)pointer_to_key;
   attr->value = (__u64)(unsigned long)pointer_to_value;
   attr->flags = flags;
}

// bpf_attr_setup_map_get_next_key sets up the bpf_attr union for use with BPF_MAP_GET_NEXT_KEY
// A C function makes this easier because unions aren't easy to access from Go.
void bpf_attr_setup_map_get_next_key(union bpf_attr *attr, __u32 map_fd, void *key, void *next_key, __u64 flags) {
   attr->map_fd = map_fd;
   attr->key = (__u64)(unsigned long)key;
   attr->next_key = (__u64)(unsigned long)next_key;
   attr->flags = flags;
}

// bpf_attr_setup_map_elem_for_delete sets up the bpf_attr union for use with BPF_MAP_DELETE_ELEM
// A C function makes this easier because unions aren't easy to access from Go.
void bpf_attr_setup_map_elem_for_delete(union bpf_attr *attr, __u32 map_fd, void *pointer_to_key) {
   attr->map_fd = map_fd;
   attr->key = (__u64)(unsigned long)pointer_to_key;
}

// bpf_attr_setup_load_prog sets up the bpf_attr union for use with BPF_PROG_LOAD.
// A C function makes this easier because unions aren't easy to access from Go.
void bpf_attr_setup_load_prog(union bpf_attr *attr, __u32 prog_type, __u32 insn_count, void *insns, char *license, __u32 log_level, __u32 log_size, void *log_buf) {
   attr->prog_type = prog_type;
   attr->insn_cnt = insn_count;
   attr->insns = (__u64)(unsigned long)insns;
   attr->license = (__u64)(unsigned long)license;
   attr->log_level = log_level;
   attr->log_size = log_size;
   attr->log_buf = (__u64)(unsigned long)log_buf;
   attr->kern_version = 0;
   if (log_size > 0) ((char *)log_buf)[0] = 0;
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

int bpf_map_call(int cmd, __u32 map_fd, void *pointer_to_key, void *pointer_to_value, __u64 flags) {
   union bpf_attr attr = {};

   attr.map_fd = map_fd;
   attr.key = (__u64)(unsigned long)pointer_to_key;
   attr.value = (__u64)(unsigned long)pointer_to_value;
   attr.flags = flags;

   return syscall(SYS_bpf, cmd, &attr, sizeof(attr)) == 0 ? 0 : errno;
}

int bpf_map_load_multi(__u32 map_fd,
                       void *current_key,
                       int max_num,
                       int key_stride,
                       void *keys_out,
                       int value_stride,
                       void *values_out) {
   int count = 0;
   union bpf_attr attr = {};
   __u64 last_good_key = (__u64)(unsigned long)current_key;
   attr.map_fd = map_fd;
   attr.key = last_good_key;
   for (int i = 0; i < max_num; i++) {
     // Load the next key from the map.
   get_next_key:
     attr.value = (__u64)(unsigned long)keys_out;
     int rc = syscall(SYS_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
     if (rc != 0) {
       if (errno == ENOENT) {
         return count; // Reached end of map.
       }
       return -errno;
     }
     // Load the corresponding value.
     attr.key = (__u64)(unsigned long)keys_out;
     attr.value = (__u64)(unsigned long)values_out;

     rc = syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
     if (rc != 0) {
       if (errno == ENOENT) {
         // Expected next entry has just been deleted.  We need
         // to BPF_MAP_GET_NEXT_KEY again from the previous key.
         attr.key = last_good_key;
         goto get_next_key;
       }
       return -errno;
     }
     last_good_key = attr.key;

     keys_out+=key_stride;
     values_out+=value_stride;
     count++;
   }
   return count;
}
