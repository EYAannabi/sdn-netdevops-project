import os
import sys
import time
import subprocess
import re
import json
import itertools
from functools import partial
from typing import Dict, Any, List, Tuple, Optional, Set

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

HOST_IP_MAP = {
    "h1": "10.0.0.1",
    "h2": "10.0.0.2",
    "h3": "10.0.0.3",
    "h4": "10.0.0.4",
}

IP_HOST_MAP = {v: k for k, v in HOST_IP_MAP.items()}


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


def normalize_ip(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return None
    return ip.split("/")[0].strip()


def ip_to_host(ip: Optional[str]) -> Optional[str]:
    ip = normalize_ip(ip)
    return IP_HOST_MAP.get(ip)


def get_all_host_pairs() -> List[Tuple[str, str]]:
    hosts = list(HOST_IP_MAP.keys())
    return list(itertools.permutations(hosts, 2))


def load_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def is_ipv4_rule(rule: Dict[str, Any]) -> bool:
    dl_type = rule.get("dl_type")
    eth_type = rule.get("eth_type")
    return dl_type == "IPv4" or eth_type == 2048 or (dl_type is None and eth_type is None)


def is_arp_rule(rule: Dict[str, Any]) -> bool:
    dl_type = rule.get("dl_type")
    eth_type = rule.get("eth_type")
    return dl_type == "ARP" or eth_type == 2054


def extract_firewall_rules(fw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    rules = []

    for rule in fw_data.get("specific_rules", []):
        rules.append(rule)

    for rule in fw_data.get("rules", []):
        rules.append(rule)

    return rules


def extract_match_from_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    return rule.get("match", rule)


def extract_action(rule: Dict[str, Any]) -> Optional[str]:
    action = rule.get("actions", rule.get("action"))
    return action.upper() if isinstance(action, str) else action


def extract_firewall_test_plan() -> Dict[str, List[Tuple[str, str]]]:
    fw_path = os.path.join(PROJECT_ROOT, "controller", "policies", "firewall.json")
    fw_data = load_json(fw_path)

    all_pairs = set(get_all_host_pairs())
    deny_pairs: Set[Tuple[str, str]] = set()

    rules = extract_firewall_rules(fw_data)

    for rule in rules:
        action = extract_action(rule)
        if action != "DENY":
            continue

        match = extract_match_from_rule(rule)

        if not is_ipv4_rule(match):
            continue

        src_host = ip_to_host(match.get("ipv4_src") or match.get("nw_src"))
        dst_host = ip_to_host(match.get("ipv4_dst") or match.get("nw_dst"))

        if src_host and dst_host:
            deny_pairs.add((src_host, dst_host))

    allow_pairs = sorted(list(all_pairs - deny_pairs))
    deny_pairs = sorted(list(deny_pairs))

    return {
        "allow": allow_pairs,
        "deny": deny_pairs,
    }


def extract_qos_test_plan() -> List[Tuple[str, str, float]]:
    qos_path = os.path.join(PROJECT_ROOT, "controller", "policies", "qos.json")
    qos_data = load_json(qos_path)

    meters = {}
    for meter in qos_data.get("meters", []):
        meter_id = meter.get("meter_id")
        bands = meter.get("bands", [])
        if meter_id is None or not bands:
            continue

        first_band = bands[0]
        rate = first_band.get("rate")
        flags = str(meter.get("flags", "")).upper()

        if rate is None:
            continue

        if flags == "KBPS":
            rate_mbps = float(rate) / 1000.0
        elif flags == "MBPS":
            rate_mbps = float(rate)
        else:
            # fallback le plus raisonnable pour ton cas
            rate_mbps = float(rate) / 1000.0

        meters[meter_id] = rate_mbps

    qos_tests = []

    for rule in qos_data.get("qos_rules", []):
        match = rule.get("match", {})
        instructions = rule.get("instructions", [])

        src_host = ip_to_host(match.get("ipv4_src") or match.get("nw_src"))
        dst_host = ip_to_host(match.get("ipv4_dst") or match.get("nw_dst"))

        meter_id = None
        for inst in instructions:
            if inst.get("type") == "METER":
                meter_id = inst.get("meter_id")
                break

        if meter_id is None or meter_id not in meters:
            continue

        if not src_host:
            continue

        if not dst_host:
            # choisir une destination automatiquement différente de la source
            candidates = [h for h in HOST_IP_MAP.keys() if h != src_host]
            if not candidates:
                continue
            dst_host = candidates[0]

        qos_tests.append((src_host, dst_host, meters[meter_id]))

    return qos_tests


def test_ping_allowed(net: Mininet, src_name: str, dst_name: str) -> bool:
    info(f"*** 🟢 ALLOW TEST: {src_name} -> {dst_name}\n")
    dst_ip = net.get(dst_name).IP()
    result = net.get(src_name).cmd(f"ping -c 2 -W 1 {dst_ip}")

    if "0% packet loss" in result or " 0% packet loss" in result:
        info(f"   ✅ OK: {src_name} can reach {dst_name}\n")
        return True

    info(f"   ❌ FAIL: {src_name} cannot reach {dst_name}\n")
    return False


def test_ping_denied(net: Mininet, src_name: str, dst_name: str) -> bool:
    info(f"*** 🔴 DENY TEST: {src_name} -> {dst_name} (Policy as Code)\n")
    dst_ip = net.get(dst_name).IP()
    result = net.get(src_name).cmd(f"ping -c 2 -W 1 {dst_ip}")

    if "100% packet loss" in result or "Destination Host Unreachable" in result:
        info(f"   ✅ OK: traffic {src_name} -> {dst_name} is blocked\n")
        return True

    info(f"   ❌ FAIL: traffic {src_name} -> {dst_name} is NOT blocked\n")
    return False


def test_qos(net: Mininet, src_name: str, dst_name: str, max_mbps: float) -> bool:
    info(f"*** 📊 QoS TEST: {src_name} -> {dst_name}, expected bandwidth <= {max_mbps} Mbps\n")

    try:
        cli = net.get(src_name)
        srv = net.get(dst_name)
        dst_ip = srv.IP()

        srv.cmd("killall -9 iperf || true")
        srv.cmd("iperf -s -p 5001 > /tmp/iperf_server.log 2>&1 &")
        time.sleep(1)

        info(f"   ⏳ Running iperf from {src_name} to {dst_name} for 4 seconds...\n")
        result = cli.cmd(f"timeout 8 iperf -c {dst_ip} -p 5001 -t 4")
        srv.cmd("killall -9 iperf || true")

        matches = re.findall(r"([\d\.]+)\s*Mbits/sec", result)
        if not matches:
            info("   ❌ FAIL: could not parse iperf throughput.\n")
            return False

        measured_mbps = float(matches[-1])

        # tolérance de 15%
        if measured_mbps <= (max_mbps * 1.15):
            info(f"   ✅ OK: QoS respected ({measured_mbps} Mbps <= {max_mbps} Mbps)\n")
            return True

        info(f"   ❌ FAIL: QoS exceeded ({measured_mbps} Mbps > {max_mbps} Mbps)\n")
        return False

    except Exception as e:
        info(f"   ❌ Exception in QoS test: {e}\n")
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
        autoSetMacs=True
    )
    net.addController("c0", controller=RemoteController, ip=CONTROLLER_IP, port=CONTROLLER_PORT)
    net.start()
    return net


def run_automated_tests() -> int:
    setLogLevel("info")
    net = None

    try:
        net = build_network()
        info("*** ⏳ Waiting for switches to connect...\n")
        time.sleep(10)

        if not deploy_policies():
            return 1

        info("*** ⏳ Waiting for policies to be applied...\n")
        time.sleep(5)

        info("*** 🧠 Building dynamic test plan from JSON policies...\n")
        firewall_plan = extract_firewall_test_plan()
        qos_plan = extract_qos_test_plan()

        all_ok = True

        for src, dst in firewall_plan["allow"]:
            all_ok = test_ping_allowed(net, src, dst) and all_ok

        if not firewall_plan["deny"]:
            info("*** ⚠️ No DENY firewall rules found.\n")
        for src, dst in firewall_plan["deny"]:
            all_ok = test_ping_denied(net, src, dst) and all_ok

        if not qos_plan:
            info("*** ⚠️ No QoS rules found.\n")
        for src, dst, max_mbps in qos_plan:
            all_ok = test_qos(net, src, dst, max_mbps) and all_ok

        if all_ok:
            info("\n🏆 CI SUCCESS: all policy-driven tests passed.\n")
            return 0

        info("\n💥 CI FAILED: one or more policy-driven tests failed.\n")
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