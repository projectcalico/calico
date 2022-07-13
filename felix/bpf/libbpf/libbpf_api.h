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

struct bpf_tc_opts bpf_tc_program_attach(struct bpf_object *obj, char *secName, int ifIndex, int isIngress) {

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach);

	if (isIngress) {
		hook.attach_point = BPF_TC_INGRESS;
	}

	attach.prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, secName));
	if (attach.prog_fd < 0) {
		errno = -attach.prog_fd;
		return attach;
	}
	hook.ifindex = ifIndex;
	set_errno(bpf_tc_attach(&hook, &attach));
	return attach;
}

int bpf_tc_query_iface (int ifIndex, struct bpf_tc_opts opts, int isIngress) {

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	if (isIngress) {
		hook.attach_point = BPF_TC_INGRESS;
	}
	hook.ifindex = ifIndex;
	opts.prog_fd = opts.prog_id = opts.flags = 0;
	set_errno(bpf_tc_query(&hook, &opts));
	return opts.prog_id;
}

void bpf_tc_create_qdisc (int ifIndex) {
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS);
	hook.ifindex = ifIndex;
	set_errno(bpf_tc_hook_create(&hook));
}

void bpf_tc_remove_qdisc (int ifIndex) {
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS | BPF_TC_INGRESS);
        hook.ifindex = ifIndex;
        set_errno(bpf_tc_hook_destroy(&hook));
        return;
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
			uint host_ip,
			uint intf_ip,
			uint ext_to_svc_mark,
			ushort tmtu,
			ushort vxlanPort,
			ushort psnat_start,
			ushort psnat_len,
			uint host_tunnel_ip,
			uint flags,
			ushort wg_port)
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
	};

	set_errno(bpf_map__set_initial_value(map, (void*)(&data), sizeof(data)));
}

int bpf_xdp_program_id(int ifIndex) {
	__u32 prog_id = 0, flags = 0;
	int err;

	err = bpf_get_link_xdp_id(ifIndex, &prog_id, flags);
	set_errno(err);
	return prog_id;
}

struct bpf_link *bpf_program_attach_xdp(struct bpf_object *obj, char *secName, int ifIndex)
{
	int err = 0;
	struct bpf_link *link = NULL;
	struct bpf_program *prog, *first_prog = NULL;

	if (!(prog = bpf_object__find_program_by_title(obj, secName))) {
		err = ENOENT;
		goto out;
	}

	link = bpf_program__attach_xdp(prog, ifIndex);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		goto out;
	}

out:
	set_errno(err);
	return link;
}

int bpf_program_update_xdp(int ifIndex, int new_fd, int old_fd, __u32 flags)
{
	struct bpf_xdp_set_link_opts opts = {
		.sz = sizeof(struct bpf_xdp_set_link_opts),
		.old_fd = old_fd,
	};

	return bpf_set_link_xdp_fd_opts(ifIndex, new_fd, flags, &opts);
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

void bpf_ctlb_set_globals(struct bpf_map *map, uint udp_not_seen_timeo)
{
	struct cali_ctlb_globals data = {
		.udp_not_seen_timeo = udp_not_seen_timeo,
	};

	set_errno(bpf_map__set_initial_value(map, (void*)(&data), sizeof(data)));
}

void bpf_map_set_max_entries(struct bpf_map *map, uint max_entries) {
	set_errno(bpf_map__resize(map, max_entries));
}

int num_possible_cpu()
{
    return libbpf_num_possible_cpus();
}
