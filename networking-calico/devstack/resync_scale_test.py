#!/usr/bin/env python3
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

"""Neutron->Calico resync scale benchmark.

Populates a real Neutron DB (via the REST API as admin) with N ports
spread across F fake hosts, then runs ``calico-resync`` against it and
times how long the resync takes.  Each scale produces one CSV-style
``RESYNC_SCALE_RESULT`` line so the numbers can be grepped out of the
Semaphore log.

Realism: nothing about Neutron, neutron-lib or SQLAlchemy is mocked.
Ports go through the real REST API and the real ML2 bind_port flow.
The one exception is the ``agents`` table: we INSERT fake "Calico
per-host agent (felix)" rows directly so the Calico mech driver
accepts ports bound to hosts other than this devstack node.

This is *not* a correctness test; it does not assert any resync output.
It measures only.

Run as the ``stack`` user with the admin openrc sourced, plus:

    ETCD_HOST=<ip>         (default localhost)
    ETCD_PORT=<port>       (default 2379)
    NEUTRON_CONF=<path>    (default /etc/neutron/neutron.conf)
    RESYNC_SCALES=100,1000 (default; comma-separated port counts)
    RESYNC_HOSTS_PER_SCALE=auto  (default: sqrt(ports), min 1)
    RESYNC_CALICO_RESYNC=calico-resync  (default; path to the CLI)
    RESYNC_CALICO_RESYNC_CONF=<path>  (default /tmp/calico-resync-scale.ini;
                                       extra config file layered on top of
                                       neutron.conf)
    RESYNC_CALICO_RESYNC_LOG=<path>   (default /tmp/calico-resync-scale.log;
                                       where calico-resync writes its logs)
"""

import argparse
import concurrent.futures
import configparser
import datetime
import json
import logging
import math
import os
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.parse import urlparse

import etcd3
import openstack
import pymysql


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger("resync-scale")

# Default scales to measure if RESYNC_SCALES is not set.  Stops at
# 3000 because larger scales take longer than Semaphore CI is willing
# to wait — 10000 ports took >12 minutes just to populate.  Override
# via the env var to push higher when running off-CI.
DEFAULT_SCALES = "100,1000,3000"

# Calico's mech driver looks for this exact agent_type in the agents
# table when binding a port to a host.  Must match AGENT_TYPE_FELIX
# in mech_calico.py.
AGENT_TYPE_FELIX = "Calico per-host agent (felix)"

# How many ports to ask the Neutron API to create in one HTTP request.
# Bulk create is supported by the v2 API and is much faster than
# one-at-a-time.
PORT_BULK_BATCH = 50

# How many concurrent worker threads to use when populating resources.
# Modest concurrency keeps the single neutron-server fork from
# self-bottlenecking.
POPULATE_WORKERS = 8

# Default tag we attach to every resource we create, so the cleanup
# pass can find them even if a previous run crashed mid-flight.
TEST_TAG = "calico-resync-scale-test"


def env_int(name, default):
    val = os.environ.get(name)
    return int(val) if val else default


def parse_scales():
    raw = os.environ.get("RESYNC_SCALES", DEFAULT_SCALES)
    return [int(s) for s in raw.split(",") if s.strip()]


def hosts_for_scale(num_ports):
    """How many fake hosts to spread `num_ports` across.

    Override with RESYNC_HOSTS_PER_SCALE=<n>.  Default is sqrt(N),
    which keeps the agents table bounded as we scale up the port
    count.
    """
    override = os.environ.get("RESYNC_HOSTS_PER_SCALE", "auto")
    if override != "auto":
        return max(1, int(override))
    return max(1, int(math.sqrt(num_ports)))


# ---------------------------------------------------------------------------
# MySQL helpers (for agent-row insertion).
# ---------------------------------------------------------------------------


def parse_db_connection(neutron_conf_path):
    """Read [database] connection from neutron.conf and return a dict
    that pymysql.connect understands.

    Example value:
      mysql+pymysql://neutron:secret@127.0.0.1/neutron?charset=utf8
    """
    parser = configparser.ConfigParser()
    parser.read(neutron_conf_path)
    conn_str = parser.get("database", "connection")
    parsed = urlparse(conn_str)
    if not parsed.username or not parsed.password:
        raise RuntimeError(
            "Could not parse user/password from neutron.conf [database] connection=%s"
            % conn_str
        )
    return {
        "host": parsed.hostname or "127.0.0.1",
        "port": parsed.port or 3306,
        "user": parsed.username,
        "password": parsed.password,
        "database": (parsed.path or "/neutron").lstrip("/") or "neutron",
        "charset": "utf8",
    }


def insert_fake_agents(db_args, hosts):
    """INSERT one Calico-felix agent row per host into the Neutron DB.

    Idempotent: existing rows for (agent_type, host) are left alone.

    heartbeat_timestamp is set to one day in the future, so Neutron's
    aliveness check (`now - heartbeat <= agent_down_time`) reads them
    as alive throughout the test without needing a refresh thread.
    Real felix processes would heartbeat naturally; for a benchmark
    that's just churning bind_port we don't care.
    """
    conn = pymysql.connect(**db_args)
    try:
        with conn.cursor() as cur:
            for host in hosts:
                cur.execute(
                    "SELECT id FROM agents WHERE agent_type=%s AND host=%s",
                    (AGENT_TYPE_FELIX, host),
                )
                if cur.fetchone():
                    continue
                # `binary` and `load` are MySQL reserved words and must
                # be quoted.  Backtick the rest for consistency.
                cur.execute(
                    """
                    INSERT INTO agents (
                        `id`, `agent_type`, `binary`, `topic`, `host`,
                        `admin_state_up`, `created_at`, `started_at`,
                        `heartbeat_timestamp`, `configurations`, `load`
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        1, UTC_TIMESTAMP(), UTC_TIMESTAMP(),
                        DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 DAY),
                        '{}', 0
                    )
                    """,
                    (
                        str(uuid.uuid4()),
                        AGENT_TYPE_FELIX,
                        "calico-felix",
                        "calico-felix",
                        host,
                    ),
                )
        conn.commit()
    finally:
        conn.close()


def delete_fake_agents(db_args):
    """Drop every Calico-felix agent row.  Used by cleanup."""
    conn = pymysql.connect(**db_args)
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM agents WHERE agent_type=%s", (AGENT_TYPE_FELIX,))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Neutron resource creation (via openstacksdk as admin).
# ---------------------------------------------------------------------------


def connect_openstack():
    return openstack.connection.Connection(
        auth_url=os.environ.get("OS_AUTH_URL", "http://localhost/identity"),
        project_name=os.environ.get("OS_PROJECT_NAME", "admin"),
        username=os.environ.get("OS_USERNAME", "admin"),
        password=os.environ["OS_PASSWORD"],
        region_name=os.environ.get("OS_REGION_NAME", "RegionOne"),
        project_domain_id=os.environ.get("OS_PROJECT_DOMAIN_ID", "default"),
        user_domain_id=os.environ.get("OS_USER_DOMAIN_ID", "default"),
        identity_api_version=3,
    )


def bump_quotas(conn):
    """Set the current project's Neutron quotas to unlimited (-1).

    Defaults are 10 networks / 50 ports / 10 SGs / 100 SG rules, way
    below what the 10000-port scale needs.  -1 means unlimited.
    """
    project = conn.identity.find_project(os.environ.get("OS_PROJECT_NAME", "admin"))
    LOG.info(
        "Bumping Neutron quotas for project %s (%s) to unlimited",
        project.name,
        project.id,
    )
    conn.network.update_quota(
        project.id,
        networks=-1,
        subnets=-1,
        ports=-1,
        security_groups=-1,
        security_group_rules=-1,
    )


def create_networks_and_subnets(conn, num_networks):
    """Create N flat networks, each with a /24 subnet.

    Uses provider:network_type=local so check_segment_for_agent
    accepts the network for the Calico agent (which only supports
    local/flat).
    """
    nets = []
    subs = []
    for i in range(num_networks):
        net = conn.network.create_network(
            name=f"{TEST_TAG}-net-{i:05d}",
            provider_network_type="local",
            shared=True,
        )
        nets.append(net)
        cidr = f"10.{(i // 256) & 0xff}.{i & 0xff}.0/24"
        sub = conn.network.create_subnet(
            name=f"{TEST_TAG}-sub-{i:05d}",
            network_id=net.id,
            ip_version=4,
            cidr=cidr,
            gateway_ip=f"10.{(i // 256) & 0xff}.{i & 0xff}.1",
            enable_dhcp=True,
        )
        subs.append(sub)
    return nets, subs


def create_security_groups(conn, num_sgs):
    """Create N security groups (each gets the default 4 rules).

    Then add 4 extra custom rules per SG (tcp/22, tcp/80, tcp/443,
    udp/53) so the resync has non-trivial NetworkPolicy content to
    compare.
    """
    sgs = []
    for i in range(num_sgs):
        sg = conn.network.create_security_group(
            name=f"{TEST_TAG}-sg-{i:05d}",
            description="resync scale test",
        )
        sgs.append(sg)
    # Add rules in parallel: ~4N rule creates.
    rule_args = []
    for sg in sgs:
        for proto, port in [("tcp", 22), ("tcp", 80), ("tcp", 443), ("udp", 53)]:
            rule_args.append(
                {
                    "security_group_id": sg.id,
                    "direction": "ingress",
                    "ether_type": "IPv4",
                    "protocol": proto,
                    "port_range_min": port,
                    "port_range_max": port,
                    "remote_ip_prefix": "0.0.0.0/0",
                }
            )

    def _add_rule(args):
        try:
            conn.network.create_security_group_rule(**args)
        except Exception as exc:
            # Duplicate rules from earlier runs / races are non-fatal.
            LOG.debug("create_security_group_rule failed: %s", exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=POPULATE_WORKERS) as ex:
        list(ex.map(_add_rule, rule_args))

    return sgs


def create_ports(conn, num_ports, networks, subnets, sgs, hosts):
    """Create N ports spread across networks, subnets, SGs and hosts.

    Uses single-port REST calls in a thread pool.  Ports go in with
    binding:host_id set so the Calico ML2 bind_port flow runs and the
    port reaches ACTIVE.
    """
    LOG.info(
        "Populating %d ports across %d networks, %d sgs, %d hosts...",
        num_ports,
        len(networks),
        len(sgs),
        len(hosts),
    )

    def _build_port_spec(i):
        net = networks[i % len(networks)]
        sub = subnets[i % len(subnets)]
        sg = sgs[i % len(sgs)]
        host = hosts[i % len(hosts)]
        return {
            "name": f"{TEST_TAG}-port-{i:08d}",
            "network_id": net.id,
            "fixed_ips": [{"subnet_id": sub.id}],
            "security_groups": [sg.id],
            "device_id": f"{TEST_TAG}-inst-{i:08d}",
            "device_owner": "compute:fake",
            "binding_host_id": host,
        }

    def _create_one(spec):
        try:
            return conn.network.create_port(**spec)
        except Exception as exc:
            LOG.error("create_port failed for %s: %s", spec["name"], exc)
            return None

    created = []
    for batch_start in range(0, num_ports, PORT_BULK_BATCH):
        batch = [
            _build_port_spec(i)
            for i in range(batch_start, min(batch_start + PORT_BULK_BATCH, num_ports))
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=POPULATE_WORKERS) as ex:
            results = list(ex.map(_create_one, batch))
        created.extend(p for p in results if p is not None)
        if (batch_start // PORT_BULK_BATCH) % 10 == 0:
            LOG.info("  ...created %d/%d ports", len(created), num_ports)
    LOG.info("Port creation done: %d ports", len(created))
    return created


# ---------------------------------------------------------------------------
# Cleanup (best-effort).
# ---------------------------------------------------------------------------


def cleanup_neutron(conn):
    """Best-effort cleanup of every resource tagged with TEST_TAG.

    Order matters: ports first, then subnets+SGs+networks.
    """
    LOG.info("Cleaning up %s ports...", TEST_TAG)
    deleted = 0
    for port in conn.network.ports():
        if port.name and port.name.startswith(TEST_TAG):
            try:
                conn.network.delete_port(port.id)
                deleted += 1
            except Exception as exc:
                LOG.warning("delete_port %s: %s", port.id, exc)
    LOG.info("  deleted %d ports", deleted)

    for sg in conn.network.security_groups():
        if sg.name and sg.name.startswith(TEST_TAG):
            try:
                conn.network.delete_security_group(sg.id)
            except Exception as exc:
                LOG.warning("delete_security_group %s: %s", sg.id, exc)

    for net in conn.network.networks():
        if net.name and net.name.startswith(TEST_TAG):
            try:
                conn.network.delete_network(net.id)
            except Exception as exc:
                LOG.warning("delete_network %s: %s", net.id, exc)


def cleanup_etcd(etcd_client):
    """Wipe everything under /calico so the next resync starts cold."""
    LOG.info("Wiping /calico from etcd...")
    etcd_client.delete_prefix("/calico")


# ---------------------------------------------------------------------------
# calico-resync invocation.
# ---------------------------------------------------------------------------


def run_calico_resync(neutron_conf_path, extra_conf_path):
    """Run calico-resync once.  Return (elapsed_seconds, result_dict).

    Layers a benchmark-specific config file on top of neutron.conf so
    calico-resync's logs land in a file rather than competing with the
    JSON result on stdout (oslo.log's neutron-server defaults can put
    log lines on stdout in this environment).  Uses --output to direct
    the JSON to a dedicated file for the same reason.

    elapsed_seconds is the wall-clock time of the subprocess, which is
    a slight overestimate of result_dict['total_ms']/1000 because it
    includes Python startup.  Both are reported.
    """
    with tempfile.NamedTemporaryFile(
        mode="w+", suffix=".json", prefix="calico-resync-"
    ) as out_file:
        cmd = [
            os.environ.get("RESYNC_CALICO_RESYNC", "calico-resync"),
            "--config-file",
            neutron_conf_path,
            "--config-file",
            extra_conf_path,
            "--output",
            out_file.name,
        ]
        LOG.info("Running %s", " ".join(cmd))
        t0 = time.monotonic()
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        elapsed = time.monotonic() - t0
        if proc.returncode != 0:
            LOG.error(
                "calico-resync exited %d.  stderr:\n%s",
                proc.returncode,
                proc.stderr,
            )
        out_file.seek(0)
        raw = out_file.read()
        try:
            result = json.loads(raw)
        except json.JSONDecodeError:
            LOG.error(
                "calico-resync did not produce valid JSON in --output.  "
                "Contents:\n%s\nstderr:\n%s",
                raw,
                proc.stderr,
            )
            result = {"ok": False, "error": "non-json output", "phases": {}}
    if not result.get("ok"):
        LOG.warning("calico-resync result ok=False: %s", result.get("error"))
    return elapsed, result


# ---------------------------------------------------------------------------
# Summary line.
# ---------------------------------------------------------------------------


def phase_ms(result, phase):
    """Get total_ms for a named phase from a ResyncResult dict.

    Returns 0 if the phase wasn't run (e.g. felix_config on a narrow
    scope, or endpoints when the run errored out before reaching it)
    or the result is malformed.
    """
    phases = result.get("phases", {}) or {}
    phase_dict = phases.get(phase) or {}
    return int(phase_dict.get("total_ms", 0))


def summarise(scale, num_networks, num_sgs, num_hosts, cold, steady_runs):
    """Print one RESYNC_SCALE_RESULT line for grep, then a JSON dump.

    cold is one (elapsed, result) tuple from the cold-etcd run.
    steady_runs is a list of such tuples from the steady-state runs.
    """
    steady_totals = [int(r["total_ms"]) for _, r in steady_runs if r.get("ok")]
    cold_elapsed, cold_result = cold
    cold_total = int(cold_result.get("total_ms", cold_elapsed * 1000))

    def stat(values, fn):
        return int(fn(values)) if values else -1

    line_fields = [
        f"scale={scale}",
        f"ports={scale}",
        f"networks={num_networks}",
        f"sgs={num_sgs}",
        f"hosts={num_hosts}",
        f"cold_ms={cold_total}",
        f"steady_min_ms={stat(steady_totals, min)}",
        f"steady_med_ms={stat(steady_totals, statistics.median)}",
        f"steady_max_ms={stat(steady_totals, max)}",
        f"cold_subnets_ms={phase_ms(cold_result, 'subnets')}",
        f"cold_policy_ms={phase_ms(cold_result, 'policy')}",
        f"cold_endpoints_ms={phase_ms(cold_result, 'endpoints')}",
        f"cold_felix_config_ms={phase_ms(cold_result, 'felix_config')}",
    ]
    if steady_runs:
        # Pick the median run for the per-phase breakdown.
        steady_sorted = sorted(steady_runs, key=lambda t: t[1].get("total_ms", 0))
        median_result = steady_sorted[len(steady_sorted) // 2][1]
        line_fields.extend(
            [
                f"steady_med_subnets_ms={phase_ms(median_result, 'subnets')}",
                f"steady_med_policy_ms={phase_ms(median_result, 'policy')}",
                f"steady_med_endpoints_ms={phase_ms(median_result, 'endpoints')}",
                f"steady_med_felix_config_ms={phase_ms(median_result, 'felix_config')}",
            ]
        )
    print("RESYNC_SCALE_RESULT " + " ".join(line_fields))
    sys.stdout.flush()

    # Also dump the raw JSON for each run for ad-hoc analysis.
    dump = {
        "scale": scale,
        "networks": num_networks,
        "sgs": num_sgs,
        "hosts": num_hosts,
        "cold": cold_result,
        "steady": [r for _, r in steady_runs],
    }
    print("RESYNC_SCALE_JSON " + json.dumps(dump))
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# One scale iteration.
# ---------------------------------------------------------------------------


def run_one_scale(scale, conn, etcd_client, db_args, neutron_conf, extra_conf):
    """Populate, measure, clean up.  Returns True on success."""
    LOG.info("=" * 60)
    LOG.info("Scale = %d ports", scale)
    LOG.info("=" * 60)

    num_hosts = hosts_for_scale(scale)
    num_networks = max(1, scale // 100)
    num_sgs = max(1, num_networks * 2)
    hosts = [f"resync-fake-{i:05d}" for i in range(num_hosts)]

    try:
        # Provision fake agent rows first.  The mech driver checks
        # agent presence and aliveness during bind_port; both queries
        # hit MySQL directly.
        LOG.info("Inserting %d fake agent rows...", num_hosts)
        insert_fake_agents(db_args, hosts)

        nets, subs = create_networks_and_subnets(conn, num_networks)
        sgs = create_security_groups(conn, num_sgs)
        create_ports(conn, scale, nets, subs, sgs, hosts)

        # Steady-state: etcd is whatever the postcommit hooks left,
        # which should be the full set of WEPs/Subnets/Policies for
        # everything we just created.  3 runs to get min/median/max.
        steady_runs = []
        for run_i in range(3):
            LOG.info("Steady-state run %d/3", run_i + 1)
            steady_runs.append(run_calico_resync(neutron_conf, extra_conf))

        # Cold: wipe etcd, then resync.  This forces every WEP /
        # NetworkPolicy / Subnet to be re-created.
        cleanup_etcd(etcd_client)
        LOG.info("Cold-etcd run")
        cold = run_calico_resync(neutron_conf, extra_conf)

        summarise(scale, num_networks, num_sgs, num_hosts, cold, steady_runs)
        return True
    finally:
        cleanup_neutron(conn)
        delete_fake_agents(db_args)


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--neutron-conf",
        default=os.environ.get("NEUTRON_CONF", "/etc/neutron/neutron.conf"),
        help="Path to neutron.conf (default %(default)s).",
    )
    args = parser.parse_args()

    LOG.info(
        "Resync scale benchmark started at %s", datetime.datetime.utcnow().isoformat()
    )
    LOG.info("Reading DB config from %s", args.neutron_conf)
    db_args = parse_db_connection(args.neutron_conf)
    LOG.info("DB host=%s database=%s", db_args["host"], db_args["database"])

    conn = connect_openstack()
    etcd_host = os.environ.get("ETCD_HOST", "localhost")
    etcd_port = env_int("ETCD_PORT", 2379)
    etcd_client = etcd3.client(host=etcd_host, port=etcd_port)
    LOG.info("etcd %s:%d", etcd_host, etcd_port)

    bump_quotas(conn)

    # Write a small INI that calico-resync will read on top of
    # neutron.conf, the same way neutron-dhcp-agent layers neutron.conf
    # + dhcp_agent.ini.  This sends calico-resync logs to a file so
    # they don't compete with the JSON result on stdout.
    extra_conf = os.environ.get(
        "RESYNC_CALICO_RESYNC_CONF", "/tmp/calico-resync-scale.ini"
    )
    log_file = os.environ.get(
        "RESYNC_CALICO_RESYNC_LOG", "/tmp/calico-resync-scale.log"
    )
    with open(extra_conf, "w") as f:
        f.write("[DEFAULT]\n")
        f.write("log_file = %s\n" % log_file)
        f.write("use_stderr = False\n")
    LOG.info("calico-resync extra config: %s (logs -> %s)", extra_conf, log_file)

    scales = parse_scales()
    LOG.info("Scales: %s", scales)

    failed = False
    for scale in scales:
        try:
            run_one_scale(
                scale,
                conn,
                etcd_client,
                db_args,
                args.neutron_conf,
                extra_conf,
            )
        except Exception:
            LOG.exception("Scale %d failed", scale)
            failed = True

    LOG.info(
        "Resync scale benchmark finished at %s", datetime.datetime.utcnow().isoformat()
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
