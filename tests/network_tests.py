import os
import sys
import time
import subprocess
import re
from functools import partial

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from topology.datacenter_topo import DatacenterTopo

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653
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
    return subprocess.run(cmd, shell=True)


def deploy_policies() -> bool:
    info("*** 🚀 Deploying network policies...\n")
    result = run_command(f"python3 {POLICY_DEPLOY_SCRIPT}")

    if result.returncode != 0:
        info("❌ Policy deployment failed.\n")
        return False

    info("✅ Policies deployed successfully.\n")
    return True


def test_ping_allowed(net: Mininet, src_name: str, dst_ip: str, dst_name: str) -> bool:
    info(f"*** 🟢 ALLOW TEST: {src_name} -> {dst_name}\n")
    result = net.get(src_name).cmd(f"ping -c 2 -W 1 {dst_ip}")

    if "0% packet loss" in result:
        info(f"   ✅ OK: {src_name} can reach {dst_name}\n")
        return True

    info(f"   ❌ FAIL: {src_name} cannot reach {dst_name}\n")
    return False


def test_ping_denied(net: Mininet, src_name: str, dst_ip: str, dst_name: str) -> bool:
    info(f"*** 🔴 DENY TEST: {src_name} -> {dst_name}\n")
    result = net.get(src_name).cmd(f"ping -c 2 -W 1 {dst_ip}")

    if "100% packet loss" in result or "Destination Host Unreachable" in result:
        info(f"   ✅ OK: traffic {src_name} -> {dst_name} is blocked\n")
        return True

    info(f"   ❌ FAIL: traffic {src_name} -> {dst_name} is not blocked\n")
    return False


def parse_iperf_mbps(iperf_output: str):
    # Cherche la bande passante avec Regex dans la sortie brute Linux
    matches = re.findall(r'(\d+(?:\.\d+)?)\s+([KkMmGg]bits?/sec)', iperf_output)
    if not matches:
        return None
    
    # Prendre la dernière occurrence (généralement la moyenne)
    value_str, unit = matches[-1]
    value = float(value_str)

    if 'K' in unit.upper(): return value / 1000.0
    if 'M' in unit.upper(): return value
    if 'G' in unit.upper(): return value * 1000.0

    return None


def test_qos(net: Mininet, src_name: str, dst_name: str, max_mbps: float) -> bool:
    info(f"*** 📊 QoS TEST: {src_name} -> {dst_name}, expected <= {max_mbps} Mbps\n")

    try:
        srv = net.get(dst_name)
        cli = net.get(src_name)

        # Lancer iperf serveur
        srv.cmd("iperf -s &")
        time.sleep(1)

        # Lancer iperf client (2 secondes de test)
        bw_output = cli.cmd(f"timeout 5 iperf -c {srv.IP()} -t 2")

        # Couper le serveur proprement
        srv.cmd("killall -9 iperf")

        if not bw_output.strip() or "Connection timed out" in bw_output:
            info("   ❌ FAIL: Le test a figé (trafic probablement bloqué par le Firewall)\n")
            return False

        mbps = parse_iperf_mbps(bw_output)
        if mbps is None:
            info("   ❌ FAIL: unrecognized iperf output format\n")
            info(f"Sortie brute: {bw_output}\n")
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
        info("*** ⏳ Controller was already validated by Ansible. Starting CI network...\n")
        net = build_network()

        info("*** ⏳ Waiting for switches to connect and network to learn...\n")
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