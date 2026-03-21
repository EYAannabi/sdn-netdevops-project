import os
import sys
import time
import subprocess
from functools import partial
import socket
import requests

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from topology.datacenter_topo import DatacenterTopo

# Controller settings
CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6633
REST_URL = "http://127.0.0.1:8080"
POLICY_DEPLOY_SCRIPT = os.path.join(PROJECT_ROOT, "scripts", "deploy_policies.py")

ALLOW_TESTS = [
    ("h1", "10.0.0.2", "h2"),
]

DENY_TESTS = [
    ("h1", "10.0.0.4", "h4"),
]

QOS_TESTS = [
    ("h1", "h2", 15.0),
]


def run_command(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, text=True, capture_output=True)


def wait_for_controller(max_retries: int = 20, delay: int = 2) -> bool:
    """Wait until both OpenFlow and REST endpoints are reachable."""
    info("*** ⏳ Waiting for SDN controller (REST + OpenFlow)...\n")

    for i in range(max_retries):
        of_ok = False
        rest_ok = False

        # OpenFlow port check
        try:
            with socket.create_connection((CONTROLLER_IP, CONTROLLER_PORT), timeout=2):
                of_ok = True
        except Exception:
            pass

        # REST server check: only verify server answers
        try:
            r = requests.get(REST_URL, timeout=2)
            if r.status_code in (200, 404):
                rest_ok = True
        except Exception:
            pass

        if of_ok and rest_ok:
            info("*** ✅ Controller is ready.\n")
            return True

        info(f"   attempt {i + 1}/{max_retries}...\n")
        time.sleep(delay)

    return False


def deploy_policies() -> bool:
    info("*** 🚀 Deploying network policies...\n")
    result = run_command(f"python3 {POLICY_DEPLOY_SCRIPT}")

    if result.returncode != 0:
        info("❌ Policy deployment failed.\n")
        if result.stdout:
            info(result.stdout + "\n")
        if result.stderr:
            info(result.stderr + "\n")
        return False

    info("✅ Policies deployed successfully.\n")
    return True


def test_ping_allowed(net: Mininet, src_name: str, dst_ip: str, dst_name: str) -> bool:
    info(f"*** 🟢 ALLOW TEST: {src_name} -> {dst_name}\n")
    result = net.get(src_name).cmd(f"ping -c 2 {dst_ip}")

    if "0% packet loss" in result:
        info(f"   ✅ OK: {src_name} can reach {dst_name}\n")
        return True

    info(f"   ❌ FAIL: {src_name} cannot reach {dst_name}\n")
    info(result + "\n")
    return False


def test_ping_denied(net: Mininet, src_name: str, dst_ip: str, dst_name: str) -> bool:
    info(f"*** 🔴 DENY TEST: {src_name} -> {dst_name}\n")
    result = net.get(src_name).cmd(f"ping -c 2 {dst_ip}")

    if "100% packet loss" in result or "Destination Host Unreachable" in result:
        info(f"   ✅ OK: traffic {src_name} -> {dst_name} is blocked\n")
        return True

    info(f"   ❌ FAIL: traffic {src_name} -> {dst_name} is not blocked\n")
    info(result + "\n")
    return False


def parse_iperf_mbps(bw_str: str):
    try:
        value, unit = bw_str.strip().split()[:2]
        value = float(value)

        if "Kbit" in unit:
            return value / 1000.0
        if "Mbit" in unit:
            return value
        if "Gbit" in unit:
            return value * 1000.0
    except Exception:
        return None

    return None


def test_qos(net: Mininet, src_name: str, dst_name: str, max_mbps: float) -> bool:
    info(f"*** 📊 QoS TEST: {src_name} -> {dst_name}, expected <= {max_mbps} Mbps\n")

    try:
        bw = net.iperf((net.get(src_name), net.get(dst_name)))[0]
        info(f"   measured throughput: {bw}\n")

        mbps = parse_iperf_mbps(bw)
        if mbps is None:
            info("   ❌ FAIL: unrecognized iperf output format\n")
            return False

        if mbps <= max_mbps:
            info(f"   ✅ QoS OK: {mbps:.2f} Mbps <= {max_mbps} Mbps\n")
            return True

        info(f"   ❌ QoS FAIL: {mbps:.2f} Mbps > {max_mbps} Mbps\n")
        return False

    except Exception as e:
        info(f"   ❌ QoS exception: {e}\n")
        return False


def build_network() -> Mininet:
    info("*** 🏗️ Creating ephemeral CI network...\n")

    topo = DatacenterTopo()
    switch = partial(OVSKernelSwitch, protocols="OpenFlow13")

    net = Mininet(
        topo=topo,
        switch=switch,
        link=TCLink,
        controller=None,
        autoSetMacs=True,
    )

    net.addController(
        "c0",
        controller=RemoteController,
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT,
    )

    net.start()
    return net


def run_automated_tests() -> int:
    setLogLevel("info")
    net = None

    try:
        if not wait_for_controller():
            info("❌ Controller is not available.\n")
            return 1

        net = build_network()

        info("*** ⏳ Waiting for network learning...\n")
        time.sleep(10)

        if not deploy_policies():
            return 1

        info("*** ⏳ Waiting for policies to be applied...\n")
        time.sleep(5)

        all_ok = True

        for test in ALLOW_TESTS:
            all_ok = test_ping_allowed(net, *test) and all_ok

        for test in DENY_TESTS:
            all_ok = test_ping_denied(net, *test) and all_ok

        for test in QOS_TESTS:
            all_ok = test_qos(net, *test) and all_ok

        if all_ok:
            info("\n🏆 CI SUCCESS: all tests passed.\n")
            return 0

        info("\n💥 CI FAILED: one or more tests failed.\n")
        return 1

    except Exception as e:
        info(f"\n💥 Exception during CI tests: {e}\n")
        return 1

    finally:
        if net is not None:
            info("*** 🛑 Stopping ephemeral CI network...\n")
            net.stop()


if __name__ == "__main__":
    sys.exit(run_automated_tests())