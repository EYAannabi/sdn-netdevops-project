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

# ✅ CORRECTION : bon port OpenFlow
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


# =========================
# ✅ ATTENTE CONTROLLER
# =========================
def wait_for_controller(max_retries=15, delay=2):
    info("*** ⏳ Attente du contrôleur (REST + OpenFlow)...\n")

    for i in range(max_retries):
        of_ok = False
        rest_ok = False

        # OpenFlow check
        try:
            with socket.create_connection((CONTROLLER_IP, CONTROLLER_PORT), timeout=2):
                of_ok = True
        except:
            pass

        # REST check
        try:
            r = requests.get("http://127.0.0.1:8080/stats/switches", timeout=2)
            if r.status_code == 200:
                rest_ok = True
        except:
            pass

        if of_ok and rest_ok:
            info("*** ✅ Contrôleur prêt.\n")
            return True

        info(f"   tentative {i+1}/{max_retries}...\n")
        time.sleep(delay)

    return False


def run_command(cmd):
    return subprocess.run(cmd, shell=True, text=True, capture_output=True)


def deploy_policies():
    info("*** 🚀 Déploiement des politiques réseau...\n")
    result = run_command(f"python3 {POLICY_DEPLOY_SCRIPT}")

    if result.returncode != 0:
        info("❌ Échec du déploiement des policies.\n")
        info(result.stdout + "\n")
        info(result.stderr + "\n")
        return False

    info("✅ Policies déployées avec succès.\n")
    return True


# =========================
# TESTS
# =========================
def test_ping_allowed(net, src_name, dst_ip, dst_name):
    info(f"*** 🟢 TEST ALLOW: {src_name} -> {dst_name}\n")
    result = net.get(src_name).cmd(f"ping -c 2 {dst_ip}")

    if "0% packet loss" in result:
        info("   ✅ OK\n")
        return True

    info("   ❌ FAIL\n" + result)
    return False


def test_ping_denied(net, src_name, dst_ip, dst_name):
    info(f"*** 🔴 TEST DENY: {src_name} -> {dst_name}\n")
    result = net.get(src_name).cmd(f"ping -c 2 {dst_ip}")

    if "100% packet loss" in result or "Destination Host Unreachable" in result:
        info("   ✅ OK\n")
        return True

    info("   ❌ FAIL\n" + result)
    return False


def parse_iperf_mbps(bw_str):
    try:
        value, unit = bw_str.strip().split()[:2]
        value = float(value)

        if "Kbit" in unit:
            return value / 1000
        if "Mbit" in unit:
            return value
        if "Gbit" in unit:
            return value * 1000
    except:
        return None


def test_qos(net, src_name, dst_name, max_mbps):
    info(f"*** 📊 TEST QoS: {src_name} -> {dst_name}\n")

    try:
        bw = net.iperf((net.get(src_name), net.get(dst_name)))[0]
        info(f"   débit: {bw}\n")

        mbps = parse_iperf_mbps(bw)
        if mbps is None:
            return False

        if mbps <= max_mbps:
            info("   ✅ QoS OK\n")
            return True

        info("   ❌ QoS FAIL\n")
        return False

    except Exception as e:
        info(f"   ❌ Exception QoS: {e}\n")
        return False


# =========================
# BUILD NETWORK
# =========================
def build_network():
    info("*** 🏗️ Création réseau CI...\n")

    topo = DatacenterTopo()
    switch = partial(OVSKernelSwitch, protocols="OpenFlow13")

    net = Mininet(
        topo=topo,
        switch=switch,
        link=TCLink,
        controller=None,
        autoSetMacs=True,
    )

    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT,
    )

    net.start()
    return net


# =========================
# MAIN TEST
# =========================
def run_automated_tests():
    setLogLevel("info")
    net = None

    try:
        # ✅ ATTENTE CONTROLLER AVANT MININET
        if not wait_for_controller():
            info("❌ Controller non disponible\n")
            return 1

        net = build_network()

        info("*** ⏳ apprentissage réseau...\n")
        time.sleep(8)

        if not deploy_policies():
            return 1

        time.sleep(3)

        all_ok = True

        for t in ALLOW_TESTS:
            all_ok &= test_ping_allowed(net, *t)

        for t in DENY_TESTS:
            all_ok &= test_ping_denied(net, *t)

        for t in QOS_TESTS:
            all_ok &= test_qos(net, *t)

        if all_ok:
            info("\n🏆 CI SUCCESS\n")
            return 0

        info("\n💥 CI FAILED\n")
        return 1

    except Exception as e:
        info(f"\n💥 Exception: {e}\n")
        return 1

    finally:
        if net:
            net.stop()


if __name__ == "__main__":
    sys.exit(run_automated_tests())