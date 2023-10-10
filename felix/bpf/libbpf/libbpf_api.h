// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
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

#include "libbpf.h"
#include <linux/limits.h>
#include <net/if.h>
#include <bpf.h>
#include <stdlib.h>
#include <errno.h>
#include "globals.h"
#include "ip_addr.h"

static void set_errno(int ret) {
	errno = ret >= 0 ? ret : -ret;
}

struct bpf_object* bpf_obj_open(char *filename) {
	struct bpf_object *obj;
	obj = bpf_object__open(filename);
	int err = libbpf_get_error(obj);
	if (err) {
		obj = NULL;
	}
	set_errno(err);
	return obj;
}

void bpf_obj_load(struct bpf_object *obj) {
	set_errno(bpf_object__load(obj));
}

int bpf_program_fd(struct bpf_object *obj, char *secname)
{
	int fd = bpf_program__fd(bpf_object__find_program_by_name(obj, secname));
	if (fd < 0) {
		errno = -fd;
	}

	return fd;
}

struct bpf_tc_opts bpf_tc_program_attach(struct bpf_object *obj, char *secName, int ifIndex, bool ingress)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			.attach_point = ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS,
			);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach);

	attach.prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, secName));
	if (attach.prog_fd < 0) {
		errno = -attach.prog_fd;
		return attach;
	}
	hook.ifindex = ifIndex;
	set_errno(bpf_tc_attach(&hook, &attach));
	return attach;
}

void bpf_tc_program_detach(int ifindex, int handle, int pref, bool ingress)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			.ifindex = ifindex,
			.attach_point = ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS,
			);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
			.handle = handle,
			.priority = pref,
			);

	set_errno(bpf_tc_detach(&hook, &opts));
}

struct bpf_tc_opts bpf_tc_program_query(int ifindex, int handle, int pref, bool ingress)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			.ifindex = ifindex,
			.attach_point = ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS,
			);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
			.handle = handle,
			.priority = pref,
			);

	set_errno(bpf_tc_query(&hook, &opts));

	return opts;
}

void bpf_tc_create_qdisc(int ifIndex)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS);
	hook.ifindex = ifIndex;
	set_errno(bpf_tc_hook_create(&hook));
}

void bpf_tc_remove_qdisc(int ifindex)
{
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			.attach_point = BPF_TC_EGRESS | BPF_TC_INGRESS,
			.ifindex = ifindex,
			);

        set_errno(bpf_tc_hook_destroy(&hook));
}

int bpf_update_jump_map(struct bpf_object *obj, char* mapName, char *progName, int progIndex) {
	struct bpf_program *prog_name = bpf_object__find_program_by_name(obj, progName);
	if (prog_name == NULL) {
		errno = ENOENT;
		return -1;
	}
	int prog_fd = bpf_program__fd(prog_name);
	if (prog_fd < 0) {
		errno = -prog_fd;
		return prog_fd;
	}
	int map_fd = bpf_object__find_map_fd_by_name(obj, mapName);
	if (map_fd < 0) {
		errno = -map_fd;
		return map_fd;
	}
	return bpf_map_update_elem(map_fd, &progIndex, &prog_fd, 0);
}

int bpf_link_destroy(struct bpf_link *link) {
	return bpf_link__destroy(link);
}

void bpf_tc_set_globals(struct bpf_map *map,
			char *iface_name,
			uint host_ip,
			uint intf_ip,
			uint ext_to_svc_mark,
			ushort tmtu,
			ushort vxlanPort,
			ushort psnat_start,
			ushort psnat_len,
			uint host_tunnel_ip,
			uint flags,
			ushort wg_port,
			uint natin,
			uint natout,
			uint log_filter_jmp,
			uint *jumps)
{
	struct cali_tc_globals data = {
		.host_ip = host_ip,
		.tunnel_mtu = tmtu,
		.vxlan_port = vxlanPort,
		.intf_ip = intf_ip,
		.ext_to_svc_mark = ext_to_svc_mark,
		.psnat_start = psnat_start,
		.psnat_len = psnat_len,
		.host_tunnel_ip = host_tunnel_ip,
		.flags = flags,
		.wg_port = wg_port,
		.natin_idx = natin,
		.natout_idx = natout,
		.log_filter_jmp = log_filter_jmp,
	};

	strncpy(data.iface_name, iface_name, sizeof(data.iface_name));
	data.iface_name[sizeof(data.iface_name)-1] = '\0';

	int i;

	for (i = 0; i < sizeof(data.jumps)/sizeof(uint); i++) {
		data.jumps[i] = jumps[i];
	}

	set_errno(bpf_map__set_initial_value(map, (void*)(&data), sizeof(data)));
}

void bpf_tc_set_globals_v6(struct bpf_map *map,
			   char *iface_name,
			   char* host_ip,
			   char* intf_ip,
			   uint ext_to_svc_mark,
			   ushort tmtu,
			   ushort vxlanPort,
			   ushort psnat_start,
			   ushort psnat_len,
			   char* host_tunnel_ip,
			   uint flags,
			   ushort wg_port,
			   uint natin,
			   uint natout,
			   uint log_filter_jmp,
			   uint *jumps)
{
	struct cali_tc_globals_v6 data = {
		.tunnel_mtu = tmtu,
		.vxlan_port = vxlanPort,
		.ext_to_svc_mark = ext_to_svc_mark,
		.psnat_start = psnat_start,
		.psnat_len = psnat_len,
		.flags = flags,
		.wg_port = wg_port,
		.natin_idx = natin,
		.natout_idx = natout,
		.log_filter_jmp = log_filter_jmp,
	};

	memcpy(&data.host_ip, host_ip, 16);
	memcpy(&data.intf_ip, intf_ip, 16);
	memcpy(&data.host_tunnel_ip, host_tunnel_ip, 16);

	strncpy(data.iface_name, iface_name, sizeof(data.iface_name));
	data.iface_name[sizeof(data.iface_name)-1] = '\0';

	int i;

	for (i = 0; i < sizeof(data.jumps)/sizeof(uint); i++) {
		data.jumps[i] = jumps[i];
	}

	set_errno(bpf_map__set_initial_value(map, (void*)(&data), sizeof(data)));
}

int bpf_xdp_program_id(int ifIndex) {
	__u32 prog_id = 0, flags = 0;
	int err;

	err = bpf_xdp_query_id(ifIndex, flags, &prog_id);
	set_errno(err);
	return prog_id;
}

int bpf_program_attach_xdp(struct bpf_object *obj, char *name, int ifIndex, int old_id, __u32 flags)
{
	int err = 0;
	struct bpf_link *link = NULL;
	struct bpf_program *prog, *first_prog = NULL;
	DECLARE_LIBBPF_OPTS(bpf_xdp_attach_opts, opts,
		.old_prog_fd = bpf_prog_get_fd_by_id(old_id));

	if (!(prog = bpf_object__find_program_by_name(obj, name))) {
		err = ENOENT;
		goto out;
	}

	int prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		errno = -prog_fd;
		return prog_fd;
	}

	err = bpf_xdp_attach(ifIndex, prog_fd, flags, &opts);
	set_errno(err);
	return err;

out:
	set_errno(err);
	return err;
}

struct bpf_link *bpf_program_attach_cgroup(struct bpf_object *obj, int cgroup_fd, char *name)
{
	int err = 0;
	struct bpf_link *link = NULL;
	struct bpf_program *prog;

	if (!(prog = bpf_object__find_program_by_name(obj, name))) {
		err = ENOENT;
		goto out;
	}

	link = bpf_program__attach_cgroup(prog, cgroup_fd);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		goto out;
	}

out:
	set_errno(err);
	return link;
}

int bpf_program_attach_cgroup_legacy(struct bpf_object *obj, int cgroup_fd, char *name)
{
	int err = 0, prog_fd;
	struct bpf_program *prog;
	enum bpf_attach_type attach_type;

	if (!(prog = bpf_object__find_program_by_name(obj, name))) {
		err = ENOENT;
		goto out;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		err = EINVAL;
		goto out;
	}

	attach_type = bpf_program__get_expected_attach_type(prog);
	err = bpf_prog_attach(prog_fd, cgroup_fd, attach_type, 0);

out:
	set_errno(err);
	return err;
}

void bpf_ctlb_set_globals(struct bpf_map *map, uint udp_not_seen_timeo, bool exclude_udp)
{
	struct cali_ctlb_globals data = {
		.udp_not_seen_timeo = udp_not_seen_timeo,
		.exclude_udp = exclude_udp,
	};

	set_errno(bpf_map__set_initial_value(map, (void*)(&data), sizeof(data)));
}

void bpf_xdp_set_globals(struct bpf_map *map, char *iface_name, uint *jumps)
{
	struct cali_xdp_globals data = {
	};

	strncpy(data.iface_name, iface_name, sizeof(data.iface_name));
	data.iface_name[sizeof(data.iface_name)-1] = '\0';
	
	int i;

	for (i = 0; i < sizeof(data.jumps)/sizeof(__u32); i++) {
		data.jumps[i] = jumps[i];
	}

	set_errno(bpf_map__set_initial_value(map, (void*)(&data), sizeof(data)));
}

void bpf_map_set_max_entries(struct bpf_map *map, uint max_entries) {
	set_errno(bpf_map__set_max_entries(map, max_entries));
}

int num_possible_cpu()
{
    return libbpf_num_possible_cpus();
}
