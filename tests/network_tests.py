import os
import sys
import time
import subprocess
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
    info("*** Deploying network policies...\n")
    result = run_command(f"python3 {POLICY_DEPLOY_SCRIPT}")
    if result.returncode != 0:
        info("Policy deployment failed.\n")
        return False
    info("Policies deployed successfully.\n")
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


def extract_match_from_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    return rule.get("match", rule)


def extract_action(rule: Dict[str, Any]) -> Optional[str]:
    action = rule.get("actions", rule.get("action"))
    return action.upper() if isinstance(action, str) else action


def is_ipv4_rule(rule: Dict[str, Any]) -> bool:
    dl_type = rule.get("dl_type")
    eth_type = rule.get("eth_type")
    return dl_type == "IPv4" or eth_type == 2048 or (dl_type is None and eth_type is None)


def extract_firewall_test_plan() -> Dict[str, List[Tuple[str, str]]]:
    fw_path = os.path.join(PROJECT_ROOT, "controller", "policies", "firewall.json")
    fw_data = load_json(fw_path)

    all_pairs = set(get_all_host_pairs())
    deny_pairs: Set[Tuple[str, str]] = set()

    rules = []
    rules.extend(fw_data.get("specific_rules", []))
    rules.extend(fw_data.get("rules", []))

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


def test_ping_allowed(net: Mininet, src_name: str, dst_name: str) -> bool:
    info(f"*** ALLOW TEST: {src_name} -> {dst_name}\n")
    dst_ip = net.get(dst_name).IP()
    result = net.get(src_name).cmd(f"ping -c 2 -W 2 {dst_ip}")

    if "0% packet loss" in result or " 0% packet loss" in result:
        info(f"   OK: {src_name} can reach {dst_name}\n")
        return True

    info(f"   FAIL: {src_name} cannot reach {dst_name}\n")
    info(f"   Output: {result}\n")
    return False


def test_ping_denied(net: Mininet, src_name: str, dst_name: str) -> bool:
    info(f"*** DENY TEST: {src_name} -> {dst_name}\n")
    dst_ip = net.get(dst_name).IP()
    result = net.get(src_name).cmd(f"ping -c 2 -W 2 {dst_ip}")

    if "100% packet loss" in result or "Destination Host Unreachable" in result:
        info(f"   OK: traffic {src_name} -> {dst_name} is blocked\n")
        return True

    info(f"   FAIL: traffic {src_name} -> {dst_name} is NOT blocked\n")
    info(f"   Output: {result}\n")
    return False


def warmup_network(net: Mininet) -> None:
    info("*** Warming up ARP/MAC learning after STP convergence...\n")
    pairs = [("h1", "h2"), ("h1", "h3"), ("h1", "h4"), ("h3", "h4")]
    for src_name, dst_name in pairs:
        dst_ip = net.get(dst_name).IP()
        net.get(src_name).cmd(f"ping -c 1 -W 1 {dst_ip} >/dev/null 2>&1")


def build_network() -> Mininet:
    info("*** Creating ephemeral CI network...\n")
    topo = DatacenterTopo()

    # IMPORTANT: no stp=True here, because STP is already handled by Ryu simple_switch_stp_13
    switch = partial(OVSKernelSwitch, protocols="OpenFlow13")

    net = Mininet(
        topo=topo,
        switch=switch,
        link=TCLink,
        controller=None,
        autoSetMacs=True
    )

    net.addController(
        "c0",
        controller=RemoteController,
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT
    )

    net.start()
    return net


def run_automated_tests() -> int:
    setLogLevel("info")
    net = None

    try:
        net = build_network()

        info("*** Waiting for switches to connect...\n")
        time.sleep(10)

        # Wait STP convergence first
        info("*** Waiting 50 seconds for STP convergence...\n")
        time.sleep(50)

        # Warm-up traffic before firewall tests
        warmup_network(net)

        # Now deploy firewall/QoS policies
        if not deploy_policies():
            return 1

        info("*** Waiting 10 seconds for policies to be applied...\n")
        time.sleep(10)

        info("*** Building dynamic test plan from JSON policies...\n")
        firewall_plan = extract_firewall_test_plan()

        required_ok = True

        info("\n*** PHASE 1: Firewall and connectivity tests\n")

        for src, dst in firewall_plan["allow"]:
            required_ok = test_ping_allowed(net, src, dst) and required_ok

        if not firewall_plan["deny"]:
            info("*** No DENY firewall rules found.\n")

        for src, dst in firewall_plan["deny"]:
            required_ok = test_ping_denied(net, src, dst) and required_ok

        if required_ok:
            info("\nCI SUCCESS: STP converged and firewall/connectivity tests passed.\n")
            return 0

        info("\nCI FAILED: firewall/connectivity tests failed.\n")
        return 1

    except Exception as e:
        info(f"\nException during CI tests: {e}\n")
        return 1

    finally:
        if net is not None:
            info("*** Stopping ephemeral CI network...\n")
            net.stop()


if __name__ == "__main__":
    sys.exit(run_automated_tests())