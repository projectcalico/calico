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

"""Resync concurrency test: does a long-running resync block dynamic port creation?

Resync runs in its own OS process - equally whether it is the
``CalicoStartupResyncWorker`` for start-of-day resync within the Neutron server, or a
``calico-resync`` invocation for on-demand - separate from the API workers.  So in
principle a long resync should not block dynamic operations: the only ways it could
would be through shared external resources -- Neutron DB lock contention, etcd's
serialised transaction queue, or, on a single-host test box, CPU contention.

This test demonstrates that, in practice, dynamic port creation latency does not regress
meaningfully while a long resync is alive.  Two scenarios:

* **on_demand**: run ``calico-resync`` with the ``--inject-per-item-delay-ms``
  hidden flag so it stretches the endpoints phase to a known duration; create
  test ports during that window; compare median latency to a baseline with no
  concurrent resync.

* **startup**: set ``[calico] startup_resync_inject_per_item_delay_ms`` in
  ``neutron.conf``, restart neutron-server, and create test ports during the
  ``CalicoStartupResyncWorker``'s stretched endpoints phase.

Both scenarios assert that the in-resync median latency is at most ``2x`` the baseline
median; both emit a timing summary that puts each port-create timestamp alongside the
resync's own ``started_at`` / ``finished_at``, so a reviewer can see the overlap
directly.

Run as the ``stack`` user with the admin openrc sourced.  Environment vars:

    ETCD_HOST=<ip>         (default localhost)
    ETCD_PORT=<port>       (default 2379)
    NEUTRON_CONF=<path>    (default /etc/neutron/neutron.conf)
    RESYNC_CONCURRENCY_POPULATE_SCALE=<n>     (default 1000)
    RESYNC_CONCURRENCY_TEST_PORTS=<n>         (default 5)
    RESYNC_CONCURRENCY_PER_ITEM_DELAY_MS=<n>  (default 50)
    RESYNC_CONCURRENCY_RATIO_LIMIT=<f>        (default 2.0)
    RESYNC_CALICO_RESYNC=calico-resync        (path to the CLI)
    RESYNC_CONCURRENCY_SCENARIOS=on_demand,startup  (which to run)

The scenarios share their populate / cleanup with ``resync_scale_test.py`` -- the same
fake-agent rows, networks, SGs and ports.
"""

import argparse
import datetime
import json
import logging
import os
import statistics
import subprocess
import sys
import tempfile
import time
import uuid

# Reuse all populate / cleanup machinery from the scale test.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import resync_scale_test as scale


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger("resync-concurrency")


# ---------------------------------------------------------------------------
# Measurement.
# ---------------------------------------------------------------------------


def time_port_create(conn, network, subnet, sg, host, label):
    """Create one port via the Neutron REST API.

    Returns (port_id, elapsed_secs, started_at_iso).  ``label`` ends up in the port
    name so the per-iteration log lines and the Neutron DB rows can be correlated.
    """
    # Prefix the port name with scale.TEST_TAG so scale.cleanup_neutron()
    # picks it up at the end of the run (it deletes only ports whose name
    # starts with TEST_TAG).  Without this, our test ports outlive cleanup
    # and block the subsequent network-delete pass.
    spec = {
        "name": "%s-concurrency-%s-%s" % (scale.TEST_TAG, label, uuid.uuid4().hex[:8]),
        "network_id": network.id,
        "fixed_ips": [{"subnet_id": subnet.id}],
        "security_groups": [sg.id],
        "device_id": "concurrency-inst-%s" % uuid.uuid4().hex[:8],
        "device_owner": "compute:fake",
        "binding_host_id": host,
    }
    started_at = datetime.datetime.utcnow().isoformat() + "Z"
    t0 = time.monotonic()
    port = conn.network.create_port(**spec)
    elapsed = time.monotonic() - t0
    return port.id, elapsed, started_at


def measure_port_create_burst(conn, network, subnet, sg, host, count, label):
    """Create ``count`` ports back-to-back, return list of measurement dicts."""
    out = []
    for i in range(count):
        port_id, elapsed_secs, started_at = time_port_create(
            conn, network, subnet, sg, host, label
        )
        LOG.info(
            "  %s port %d/%d: id=%s elapsed=%.3fs",
            label,
            i + 1,
            count,
            port_id,
            elapsed_secs,
        )
        out.append(
            {
                "label": label,
                "iter": i,
                "port_id": port_id,
                "elapsed_secs": elapsed_secs,
                "started_at": started_at,
            }
        )
    return out


def median(measurements):
    if not measurements:
        return -1
    return statistics.median(m["elapsed_secs"] for m in measurements)


def _take_warmup_then_measure(conn, network, subnet, sg, host, count, label):
    """Create one warm-up port (discarded from the median) then ``count``
    measured ports under ``label``.  Returns ``(warmup_list, measured_list)``.

    Warm-up discard matters most in the startup scenario, where the API
    workers have just come back up after a neutron-server restart and the
    first port-create pays for cold DB-connection pools and plugin caches.
    Applied symmetrically to both baseline and in-resync bursts so the two
    medians come from comparably-trimmed samples -- trimming only one side
    would bias the ``in_resync / baseline`` ratio (typically toward making
    the test more lenient, since the first sample is usually the slowest).
    The warm-up sample is still included in the timing summary so a
    reviewer can see what it cost.
    """
    warmup_label = "%s_warmup" % label
    warmup = measure_port_create_burst(conn, network, subnet, sg, host, 1, warmup_label)
    LOG.info(
        "%s warm-up port (discarded from median): %.3fs",
        label,
        warmup[0]["elapsed_secs"],
    )
    measured = measure_port_create_burst(conn, network, subnet, sg, host, count, label)
    return warmup, measured


# ---------------------------------------------------------------------------
# Scenario A: on-demand calico-resync.
# ---------------------------------------------------------------------------


# Marker logged by ResourceSyncer at the top of the WorkloadEndpoint resync's
# compare loop -- i.e. AFTER the etcd read and the CONTEXT_WRITER-held neutron
# read, immediately before the per-item delay loop begins.  The test waits for
# this line so the in-resync burst lands inside the stretched delay window,
# not during the (held writer) neutron read that precedes it.  Pinning the
# marker to the compare-loop start is what lets the in-resync median actually
# reflect the stretched phase the test is trying to measure.
_ENDPOINTS_PHASE_MARKER = "Resync for WorkloadEndpoint: starting compare loop"


def wait_for_endpoints_phase(log_path, deadline_secs):
    """Tail ``log_path`` until the endpoints-phase start marker appears."""
    t_end = time.monotonic() + deadline_secs
    while time.monotonic() < t_end:
        try:
            with open(log_path) as f:
                if _ENDPOINTS_PHASE_MARKER in f.read():
                    return True
        except FileNotFoundError:
            pass
        time.sleep(0.5)
    return False


def scenario_on_demand(
    conn,
    network,
    subnet,
    sg,
    host,
    neutron_conf,
    extra_conf,
    log_file,
    test_ports,
    per_item_delay_ms,
):
    """Scenario A: on-demand calico-resync."""
    LOG.info("=" * 60)
    LOG.info("Scenario: on_demand calico-resync")
    LOG.info("=" * 60)

    # Truncate the log file so the marker poll starts from a known state.
    open(log_file, "w").close()

    # Baseline: measure without a concurrent resync.  Take a warm-up port
    # first and discard it from the median, so the baseline is trimmed the
    # same way the in-resync burst is (see _take_warmup_then_measure).
    LOG.info("Baseline: creating %d ports, no concurrent resync", test_ports)
    baseline_warmup, baseline_main = _take_warmup_then_measure(
        conn, network, subnet, sg, host, test_ports, "baseline"
    )
    baseline = baseline_warmup + baseline_main
    baseline_median = median(baseline_main)
    LOG.info("Baseline median: %.3fs", baseline_median)

    # Run calico-resync with the per-item delay.  Capture its JSON output for
    # the timing summary.
    output_file = tempfile.NamedTemporaryFile(
        mode="r", suffix=".json", prefix="calico-resync-conc-", delete=False
    )
    output_file.close()
    cmd = [
        os.environ.get("RESYNC_CALICO_RESYNC", "calico-resync"),
        "--config-file",
        neutron_conf,
        "--config-file",
        extra_conf,
        "--output",
        output_file.name,
        "--inject-per-item-delay-ms",
        str(per_item_delay_ms),
    ]
    LOG.info("Starting calico-resync (per-item delay=%dms)", per_item_delay_ms)
    LOG.info("  %s", " ".join(cmd))
    # Discard stdout/stderr rather than piping them: with PIPE and no reader,
    # a Python warning or stray traceback could fill the ~64KB OS pipe buffer
    # and deadlock proc.wait().  All oslo logging is routed to log_file via
    # extra_conf, and the JSON ResyncResult is written to --output, so nothing
    # we care about is being thrown away.
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        if not wait_for_endpoints_phase(log_file, deadline_secs=60):
            proc.kill()
            proc.wait()
            raise RuntimeError(
                "calico-resync did not reach the endpoints phase within 60s"
            )
        LOG.info("Resync confirmed in endpoints phase -- starting in-resync burst")

        # In-resync: measure while the resync is in the stretched endpoints
        # phase.  We always discard the first sample as a warm-up (see
        # _take_warmup_then_measure for rationale).
        warmup, in_resync_main = _take_warmup_then_measure(
            conn, network, subnet, sg, host, test_ports, "in_resync"
        )
        in_resync = warmup + in_resync_main
        in_resync_median = median(in_resync_main)
        LOG.info("In-resync median: %.3fs", in_resync_median)

        # Wait for resync to actually complete so the timing summary can pair
        # each test port's timestamp with the resync's own started_at /
        # finished_at.
        LOG.info("Waiting for resync to complete...")
        rc = proc.wait()
        with open(output_file.name) as f:
            result = json.load(f)
        LOG.info(
            "Resync finished rc=%d, started_at=%s, finished_at=%s, total_ms=%d",
            rc,
            result["started_at"],
            result["finished_at"],
            result["total_ms"],
        )
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        try:
            os.unlink(output_file.name)
        except OSError:
            pass

    return {
        "scenario": "on_demand",
        "baseline": baseline,
        "baseline_median_secs": baseline_median,
        "in_resync": in_resync,
        "in_resync_median_secs": in_resync_median,
        "ratio": (in_resync_median / baseline_median if baseline_median > 0 else -1),
        "resync_started_at": result["started_at"],
        "resync_finished_at": result["finished_at"],
        "resync_total_ms": result["total_ms"],
    }


# ---------------------------------------------------------------------------
# Scenario B: start-of-day resync via neutron-server restart.
# ---------------------------------------------------------------------------


def neutron_conf_set(path, section, key, value):
    """``crudini``-style edit: set [section] key=value in a config file."""
    subprocess.check_call(["sudo", "crudini", "--set", path, section, key, str(value)])


def neutron_conf_unset(path, section, key):
    subprocess.run(["sudo", "crudini", "--del", path, section, key], check=False)


def neutron_server_restart_and_wait(conn, deadline_secs=60):
    """Restart neutron-server and poll until its API is responsive."""
    LOG.info("Restarting neutron-server (systemctl restart devstack@q-svc)")
    subprocess.check_call(["sudo", "systemctl", "restart", "devstack@q-svc"])
    t_end = time.monotonic() + deadline_secs
    while time.monotonic() < t_end:
        try:
            list(conn.network.networks(limit=1))
            LOG.info("Neutron API responsive again")
            return
        except Exception as exc:
            LOG.debug("Neutron API not yet ready: %s", exc)
            time.sleep(1)
    raise RuntimeError(
        "neutron-server did not become API-responsive within %ds" % deadline_secs
    )


def wait_for_log_text_in_journal(text, since_dt, deadline_secs):
    """Poll ``journalctl -u devstack@q-svc`` until ``text`` appears.

    ``since_dt`` is a naive ``datetime.datetime`` in UTC; we format it as
    ``YYYY-MM-DD HH:MM:SS`` for ``journalctl --since``, which doesn't
    accept ISO 8601's ``T``/``Z`` punctuation.  ``--utc`` tells journalctl
    to interpret ``--since`` (and display its output) in UTC, so the test
    runs identically on UTC and non-UTC hosts -- without ``--utc`` the
    bare timestamp is interpreted as local time, which off a non-UTC box
    would either match nothing (timestamp in the future) or a prior run's
    marker (timestamp too far back).
    """
    since_journal = since_dt.strftime("%Y-%m-%d %H:%M:%S")
    t_end = time.monotonic() + deadline_secs
    while time.monotonic() < t_end:
        tail = subprocess.run(
            [
                "sudo",
                "journalctl",
                "-u",
                "devstack@q-svc",
                "--utc",
                "--since",
                since_journal,
                "-q",
            ],
            capture_output=True,
            text=True,
        )
        if text in tail.stdout:
            return True
        time.sleep(2)
    return False


def scenario_startup(
    conn,
    network,
    subnet,
    sg,
    host,
    neutron_conf,
    test_ports,
    per_item_delay_ms,
    populate_scale,
):
    """Scenario B: start-of-day resync."""
    LOG.info("=" * 60)
    LOG.info("Scenario: startup resync")
    LOG.info("=" * 60)

    # Set the per-item-delay knob on [calico] and restart neutron-server.
    # After the restart, CalicoStartupResyncWorker handles the resync in its
    # own process while the API workers stay alive and handle requests.
    neutron_conf_set(
        neutron_conf,
        "calico",
        "startup_resync_inject_per_item_delay_ms",
        per_item_delay_ms,
    )
    try:
        t_restart_dt = datetime.datetime.utcnow()
        t_restart_iso = t_restart_dt.isoformat() + "Z"
        neutron_server_restart_and_wait(conn)

        # Wait for the endpoints phase to begin in the resync worker's log.
        # Once it starts, we have populate_scale * per_item_delay_ms of
        # window to fire the in-resync burst.
        LOG.info("Waiting for start-of-day endpoints phase to begin...")
        if not wait_for_log_text_in_journal(
            _ENDPOINTS_PHASE_MARKER, t_restart_dt, deadline_secs=60
        ):
            raise RuntimeError(
                "Start-of-day resync did not reach the endpoints phase "
                "within 60s of restart"
            )
        LOG.info("Resync confirmed in endpoints phase -- starting in-resync burst")

        # In-resync: measure while the resync worker is in the stretched
        # endpoints phase.  We always discard the first sample as a warm-up
        # (see _take_warmup_then_measure for rationale).
        warmup, in_resync_main = _take_warmup_then_measure(
            conn, network, subnet, sg, host, test_ports, "in_resync"
        )
        in_resync = warmup + in_resync_main
        in_resync_median = median(in_resync_main)
        LOG.info("In-resync median: %.3fs", in_resync_median)

        # Wait for the resync to actually complete.  Total time is bounded
        # by populate_scale * per_item_delay_ms plus etcd-read /
        # neutron-read overhead.
        expected_endpoints_secs = (populate_scale * per_item_delay_ms) / 1000.0
        budget_secs = int(expected_endpoints_secs * 2) + 120
        LOG.info(
            "Waiting up to %ds for start-of-day resync to complete...",
            budget_secs,
        )
        if not wait_for_log_text_in_journal(
            "One-shot resync done", t_restart_dt, deadline_secs=budget_secs
        ):
            raise RuntimeError("Start-of-day resync did not complete within the window")
        t_resync_done_iso = datetime.datetime.utcnow().isoformat() + "Z"
        LOG.info("Resync completed")
    finally:
        # Restore neutron.conf so future test runs aren't perturbed.
        neutron_conf_unset(
            neutron_conf,
            "calico",
            "startup_resync_inject_per_item_delay_ms",
        )

    # Baseline AFTER the resync has finished -- the cleanest "no concurrent
    # resync" state we can get without another restart.  Symmetric warm-up
    # with the in-resync burst (see _take_warmup_then_measure).
    LOG.info("Baseline: creating %d ports, no concurrent resync", test_ports)
    baseline_warmup, baseline_main = _take_warmup_then_measure(
        conn, network, subnet, sg, host, test_ports, "baseline"
    )
    baseline = baseline_warmup + baseline_main
    baseline_median = median(baseline_main)
    LOG.info("Baseline median: %.3fs", baseline_median)

    return {
        "scenario": "startup",
        "baseline": baseline,
        "baseline_median_secs": baseline_median,
        "in_resync": in_resync,
        "in_resync_median_secs": in_resync_median,
        "ratio": (in_resync_median / baseline_median if baseline_median > 0 else -1),
        # No JSON-level resync timestamps for the start-of-day case, so we
        # use the closest observable proxies.
        "resync_started_at": t_restart_iso,
        "resync_finished_at": t_resync_done_iso,
    }


# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------


def print_summary(result, ratio_limit):
    """Print a reviewer-friendly summary showing the overlap between the
    resync's lifetime and each test port's API call."""
    LOG.info("")
    LOG.info("===== Concurrency summary: scenario=%s =====", result["scenario"])
    LOG.info("Resync started:  %s", result.get("resync_started_at", "?"))
    for m in result["in_resync"]:
        # Match the 1-based numbering and label used by the burst log
        # ("in_resync port 3/5") so the per-port lines printed live and the
        # summary at the end refer to the same ports the same way.  The
        # warmup is logged as ``in_resync_warmup port 1`` and the measured
        # ports as ``in_resync port 1`` ... ``port N``.
        LOG.info(
            "  %s port %d at %s, API took %.3fs",
            m["label"],
            m["iter"] + 1,
            m["started_at"],
            m["elapsed_secs"],
        )
    LOG.info("Resync finished: %s", result.get("resync_finished_at", "?"))
    LOG.info("")
    LOG.info("Baseline median: %.3fs", result["baseline_median_secs"])
    LOG.info("In-resync median: %.3fs", result["in_resync_median_secs"])
    LOG.info("Ratio: %.2fx (limit: %.2fx)", result["ratio"], ratio_limit)

    passed = result["ratio"] <= ratio_limit and result["ratio"] > 0
    LOG.info(
        "RESYNC_CONCURRENCY_RESULT scenario=%s ratio=%.3f passed=%s",
        result["scenario"],
        result["ratio"],
        passed,
    )
    sys.stdout.flush()
    return passed


# ---------------------------------------------------------------------------
# Setup helpers (thin wrappers around scale-test code).
# ---------------------------------------------------------------------------


def populate(conn, db_args, populate_scale):
    """Provision fake agents + networks + SGs + populate-scale base ports.

    Returns (network, subnet, sg, host) for the test to use when creating
    additional ports.
    """
    num_hosts = scale.hosts_for_scale(populate_scale)
    num_networks = max(1, populate_scale // 100)
    num_sgs = max(1, num_networks * 2)
    hosts = ["concurrency-fake-%05d" % i for i in range(num_hosts)]

    LOG.info(
        "Populating %d ports across %d networks / %d SGs / %d hosts...",
        populate_scale,
        num_networks,
        num_sgs,
        num_hosts,
    )
    scale.insert_fake_agents(db_args, hosts)
    nets, subs = scale.create_networks_and_subnets(conn, num_networks)
    sgs = scale.create_security_groups(conn, num_sgs)
    scale.create_ports(conn, populate_scale, nets, subs, sgs, hosts)

    # Test ports go on the first network/subnet/SG, with the first fake
    # host.  Each test port is one more port on top of the populate-scale
    # baseline.
    return nets[0], subs[0], sgs[0], hosts[0]


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--neutron-conf",
        default=os.environ.get("NEUTRON_CONF", "/etc/neutron/neutron.conf"),
        help=(
            "Path to neutron.conf to read [database] from and to mutate for "
            "the startup scenario."
        ),
    )
    args = parser.parse_args()

    populate_scale = scale.env_int("RESYNC_CONCURRENCY_POPULATE_SCALE", 1000)
    test_ports = scale.env_int("RESYNC_CONCURRENCY_TEST_PORTS", 5)
    per_item_delay_ms = scale.env_int("RESYNC_CONCURRENCY_PER_ITEM_DELAY_MS", 50)
    ratio_limit = float(os.environ.get("RESYNC_CONCURRENCY_RATIO_LIMIT", "2.0"))
    scenarios = os.environ.get(
        "RESYNC_CONCURRENCY_SCENARIOS", "on_demand,startup"
    ).split(",")
    scenarios = [s.strip() for s in scenarios if s.strip()]

    db_args = scale.parse_db_connection(args.neutron_conf)
    LOG.info(
        "DB: %s@%s:%d/%s",
        db_args["user"],
        db_args["host"],
        db_args["port"],
        db_args["database"],
    )

    etcd_host = os.environ.get("ETCD_HOST", "localhost")
    etcd_port = int(os.environ.get("ETCD_PORT", "2379"))
    etcd_client = scale.etcd3.client(host=etcd_host, port=etcd_port)
    LOG.info("etcd %s:%d", etcd_host, etcd_port)

    conn = scale.connect_openstack()
    scale.bump_quotas(conn)

    # Layered calico-resync config: route logs to a file we can tail for
    # the endpoints-phase marker, and bump the DB connection pool so the
    # large populated baseline doesn't exhaust the default.
    extra_conf = os.environ.get(
        "RESYNC_CALICO_RESYNC_CONF", "/tmp/calico-resync-conc.ini"
    )
    log_file = os.environ.get("RESYNC_CALICO_RESYNC_LOG", "/tmp/calico-resync-conc.log")
    with open(extra_conf, "w") as f:
        f.write("[DEFAULT]\n")
        f.write("log_file = %s\n" % log_file)
        f.write("use_stderr = False\n")
        f.write("[database]\n")
        f.write("max_pool_size = 50\n")
        f.write("max_overflow = 200\n")

    failed = False
    network = subnet = sg = host = None
    try:
        network, subnet, sg, host = populate(conn, db_args, populate_scale)
        for scen in scenarios:
            try:
                if scen == "on_demand":
                    result = scenario_on_demand(
                        conn,
                        network,
                        subnet,
                        sg,
                        host,
                        args.neutron_conf,
                        extra_conf,
                        log_file,
                        test_ports,
                        per_item_delay_ms,
                    )
                elif scen == "startup":
                    result = scenario_startup(
                        conn,
                        network,
                        subnet,
                        sg,
                        host,
                        args.neutron_conf,
                        test_ports,
                        per_item_delay_ms,
                        populate_scale,
                    )
                else:
                    LOG.warning("Unknown scenario %r, skipping", scen)
                    continue
                passed = print_summary(result, ratio_limit)
                if not passed:
                    failed = True
            except Exception:
                LOG.exception("Scenario %s failed with exception", scen)
                failed = True
    finally:
        scale.cleanup_neutron(conn)
        scale.delete_fake_agents(db_args)
        scale.cleanup_etcd(etcd_client)

    LOG.info(
        "Resync concurrency test finished at %s",
        datetime.datetime.utcnow().isoformat(),
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
