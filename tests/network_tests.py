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

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6635
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


def run_command(cmd):
    return subprocess.run(cmd, shell=True, text=True, capture_output=True)


def deploy_policies():
    info("*** 🚀 Déploiement des politiques réseau...\n")
    result = run_command(f"python3 {POLICY_DEPLOY_SCRIPT}")

    if result.returncode != 0:
        info("❌ Échec du déploiement des policies.\n")
        info(result.stderr + "\n")
        return False

    info("✅ Policies déployées avec succès.\n")
    return True


def test_ping_allowed(net, src_name, dst_ip, dst_name):
    info(f"*** 🟢 TEST ALLOW: {src_name} -> {dst_name}\n")
    src = net.get(src_name)
    result = src.cmd(f"ping -c 2 {dst_ip}")

    if "0% packet loss" in result:
        info(f"   ✅ SUCCÈS : {src_name} communique avec {dst_name}.\n")
        return True

    info(f"   ❌ ÉCHEC : {src_name} ne communique pas avec {dst_name}.\n")
    info(result + "\n")
    return False


def test_ping_denied(net, src_name, dst_ip, dst_name):
    info(f"*** 🔴 TEST DENY: {src_name} -> {dst_name}\n")
    src = net.get(src_name)
    result = src.cmd(f"ping -c 2 {dst_ip}")

    if "100% packet loss" in result or "Destination Host Unreachable" in result:
        info(f"   ✅ SUCCÈS : le trafic {src_name} -> {dst_name} est bien bloqué.\n")
        return True

    info(f"   ❌ ÉCHEC : le trafic {src_name} -> {dst_name} n'est pas bloqué.\n")
    info(result + "\n")
    return False


def parse_iperf_mbps(bw_str):
    try:
        parts = bw_str.strip().split()
        value = float(parts[0])
        unit = parts[1]

        if unit.startswith("Kbit"):
            return value / 1000.0
        if unit.startswith("Mbit"):
            return value
        if unit.startswith("Gbit"):
            return value * 1000.0
    except Exception:
        return None

    return None


def test_qos(net, src_name, dst_name, max_mbps):
    info(f"*** 📊 TEST QoS: {src_name} -> {dst_name}, max attendu ~ {max_mbps} Mbps\n")
    src = net.get(src_name)
    dst = net.get(dst_name)

    try:
        bw_result = net.iperf((src, dst))
        measured_bw_str = bw_result[0]
        info(f"   Vitesse mesurée : {measured_bw_str}\n")

        measured_mbps = parse_iperf_mbps(measured_bw_str)
        if measured_mbps is None:
            info("   ❌ ÉCHEC : format iperf non reconnu.\n")
            return False

        if measured_mbps <= max_mbps:
            info(f"   ✅ SUCCÈS : QoS respectée ({measured_mbps:.2f} Mbps <= {max_mbps} Mbps).\n")
            return True

        info(f"   ❌ ÉCHEC : QoS non respectée ({measured_mbps:.2f} Mbps > {max_mbps} Mbps).\n")
        return False

    except Exception as e:
        info(f"   ❌ ÉCHEC QoS : {e}\n")
        return False


def build_network():
    info("*** 🏗️ Création du réseau CI éphémère...\n")
    topo = DatacenterTopo()
    switch_of13 = partial(OVSKernelSwitch, protocols="OpenFlow13")

    net = Mininet(
        topo=topo,
        switch=switch_of13,
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

    c0.start()
    time.sleep(2)
    net.start()
    return net


def run_automated_tests():
    setLogLevel("info")
    net = None

    try:
        net = build_network()

        info("*** ⏳ Attente de 10 secondes pour l'apprentissage réseau...\n")
        time.sleep(10)

        if not deploy_policies():
            return 1

        info("*** ⏳ Attente de 5 secondes pour application des policies...\n")
        time.sleep(5)

        all_ok = True

        for src_name, dst_ip, dst_name in ALLOW_TESTS:
            all_ok = test_ping_allowed(net, src_name, dst_ip, dst_name) and all_ok

        for src_name, dst_ip, dst_name in DENY_TESTS:
            all_ok = test_ping_denied(net, src_name, dst_ip, dst_name) and all_ok

        for src_name, dst_name, max_mbps in QOS_TESTS:
            all_ok = test_qos(net, src_name, dst_name, max_mbps) and all_ok

        if all_ok:
            info("\n🏆 RÉSULTAT FINAL : Tous les tests CI ont réussi.\n")
            return 0

        info("\n💥 RÉSULTAT FINAL : Un ou plusieurs tests CI ont échoué.\n")
        return 1

    except Exception as e:
        info(f"\n💥 Exception pendant les tests CI : {e}\n")
        return 1

    finally:
        if net is not None:
            info("*** 🛑 Arrêt du réseau CI éphémère...\n")
            net.stop()


if __name__ == "__main__":
    sys.exit(run_automated_tests())