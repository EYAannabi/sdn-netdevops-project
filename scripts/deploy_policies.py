import json
import os
import sys
import time
import subprocess
from typing import Any, Dict, List

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FIREWALL_POLICY_PATH = os.path.join(BASE_DIR, "../controller/policies/firewall.json")
QOS_POLICY_PATH = os.path.join(BASE_DIR, "../controller/policies/qos.json")

RYU_BASE_URL = os.getenv("RYU_BASE_URL", "http://127.0.0.1:8080")
REQUEST_TIMEOUT = 10

# Les listes de DPIDs ne sont plus strictement nécessaires pour le pare-feu
# puisqu'on va utiliser "all", mais on les garde pour les règles spécifiques OpenFlow
FIREWALL_DPIDS = [
    "0000000000000001",
    "0000000000000002",
    "0000000000000003",
    "0000000000000004",
]
OVSDB_PORT = 6632
HOST_EDGE_SWITCH = {
    "10.0.0.1": 3,  # h1 on s3
    "10.0.0.2": 3,  # h2 on s3
    "10.0.0.3": 4,  # h3 on s4
    "10.0.0.4": 4,  # h4 on s4
}

# For the OpenFlow /stats/* APIs
OF_DPIDS = [1, 2, 3, 4]


def apply_ovs_ingress_policing(interface: str, rate_kbps: int, burst_kb: int) -> None:
    cmd_rate = [
        "sudo", "ovs-vsctl", "set", "interface", interface,
        f"ingress_policing_rate={rate_kbps}"
    ]
    cmd_burst = [
        "sudo", "ovs-vsctl", "set", "interface", interface,
        f"ingress_policing_burst={burst_kb}"
    ]

    subprocess.run(cmd_rate, check=True)
    subprocess.run(cmd_burst, check=True)

    print(f"    QOS policing applied on {interface}: rate={rate_kbps} kbps, burst={burst_kb} kb")


def get_qos_dpids_for_rule(rule: Dict[str, Any]) -> List[int]:
    match = rule.get("match", {})
    src_ip = match.get("ipv4_src") or match.get("nw_src")
    if not src_ip:
        return []
    src_ip = src_ip.split("/")[0]
    dpid = HOST_EDGE_SWITCH.get(src_ip)
    return [dpid] if dpid is not None else []


def configure_ovsdb_for_switch(dpid: int) -> None:
    url = f"{RYU_BASE_URL}/v1.0/conf/switches/{dpid:016x}/ovsdb_addr"
    payload = f"tcp:127.0.0.1:{OVSDB_PORT}"
    response = requests.put(url, json=payload, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    print(f"    OVSDB configured for switch {dpid}")


def build_queue_payload_from_meter(meter: Dict[str, Any], port_name: str) -> Dict[str, Any]:
    bands = meter.get("bands", [])
    if not bands:
        raise ValueError(f"Meter without bands: {meter}")

    rate_kbps = bands[0]["rate"]
    max_rate_bps = str(int(rate_kbps) * 1000)

    return {
        "port_name": port_name,
        "type": "linux-htb",
        "max_rate": max_rate_bps,
        "queues": [
            {
                "max_rate": max_rate_bps
            }
        ]
    }


def build_qos_rule_payload(rule: Dict[str, Any]) -> Dict[str, Any]:
    match = rule.get("match", {})
    src_ip = match.get("ipv4_src") or match.get("nw_src")

    return {
        "match": {
            "nw_src": src_ip,
            "dl_type": "IPv4"
        },
        "actions": {
            "queue": "0"
        }
    }


def get_port_name_for_qos_source(src_ip: str) -> str:
    src_ip = src_ip.split("/")[0]
    if src_ip == "10.0.0.3":
        return "s4-eth1"
    if src_ip == "10.0.0.4":
        return "s4-eth2"
    if src_ip == "10.0.0.1":
        return "s3-eth1"
    if src_ip == "10.0.0.2":
        return "s3-eth2"
    raise ValueError(f"Unknown QoS source IP: {src_ip}")


def load_json_file(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def http_get(url: str) -> requests.Response:
    response = requests.get(url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response


def http_put(url: str) -> requests.Response:
    response = requests.put(url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response


def http_post(url: str, payload: Dict[str, Any]) -> requests.Response:
    response = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response


def wait_for_ryu_and_switches(max_retries: int = 15, delay: int = 3) -> None:
    print("*** Checking that the Ryu API is available and switches are connected...")
    switches_url = f"{RYU_BASE_URL}/stats/switches"

    for attempt in range(1, max_retries + 1):
        try:
            response = http_get(switches_url)
            switches = response.json()

            if isinstance(switches, list) and len(switches) > 0:
                print(f"*** Ryu API is available, connected switches: {switches}")
                return

            print(f"    Attempt {attempt}/{max_retries}... no switch connected yet.")
        except requests.RequestException as e:
            print(f"    Attempt {attempt}/{max_retries}... error: {e}")

        time.sleep(delay)

    raise RuntimeError("Ryu API unavailable, or available with no connected switches.")


# --- NOUVELLE FONCTION GLOBALE POUR LE PARE-FEU ---
def enable_firewall_all() -> None:
    url = f"{RYU_BASE_URL}/firewall/module/enable/all"
    http_put(url)
    print("    Firewall ENABLED globally on ALL switches.")


def normalize_firewall_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(rule)

    if "action" in normalized and "actions" not in normalized:
        normalized["actions"] = normalized.pop("action")

    has_ip_match = any(key in normalized for key in ["nw_src", "nw_dst", "ipv4_src", "ipv4_dst"])
    if has_ip_match and "dl_type" not in normalized and "eth_type" not in normalized:
        normalized["dl_type"] = "IPv4"

    return normalized


def validate_firewall_rule(rule: Dict[str, Any]) -> None:
    if "actions" not in rule:
        raise ValueError(f"Invalid firewall rule: missing 'actions' field -> {rule}")

    if rule["actions"] not in ["ALLOW", "DENY"]:
        raise ValueError(f"Invalid firewall rule: actions must be ALLOW or DENY -> {rule}")


def build_drop_flow_from_firewall_rule(dpid: int, rule: Dict[str, Any]) -> Dict[str, Any]:
    match = {}

    dl_type = rule.get("dl_type")
    eth_type = rule.get("eth_type")

    if dl_type == "IPv4":
        match["eth_type"] = 2048
    elif dl_type == "ARP":
        match["eth_type"] = 2054
    elif eth_type is not None:
        match["eth_type"] = eth_type

    if "nw_src" in rule:
        match["ipv4_src"] = rule["nw_src"]
    if "nw_dst" in rule:
        match["ipv4_dst"] = rule["nw_dst"]
    if "ipv4_src" in rule:
        match["ipv4_src"] = rule["ipv4_src"]
    if "ipv4_dst" in rule:
        match["ipv4_dst"] = rule["ipv4_dst"]

    payload = {
        "dpid": dpid,
        "priority": int(rule.get("priority", 65000)),
        "match": match,
        "actions": []
    }
    return payload


def extract_firewall_rules(policies: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    global_rules = policies.get("global_rules", [])
    specific_rules = policies.get("specific_rules", [])

    if not global_rules and not specific_rules and "rules" in policies:
        for rule in policies.get("rules", []):
            action = str(rule.get("actions", rule.get("action", ""))).upper()
            if action == "DENY":
                specific_rules.append(rule)
            else:
                global_rules.append(rule)

    return {
        "global_rules": global_rules,
        "specific_rules": specific_rules,
    }


def deploy_firewall() -> None:
    print("*** Reading and applying firewall policies (Policy as Code)...")
    policies = load_json_file(FIREWALL_POLICY_PATH)
    extracted = extract_firewall_rules(policies)

    global_rules = [normalize_firewall_rule(r) for r in extracted["global_rules"]]
    specific_rules = [normalize_firewall_rule(r) for r in extracted["specific_rules"]]

    for rule in global_rules + specific_rules:
        validate_firewall_rule(rule)

    # 1) Enable the firewall module sur TOUS les switchs en une seule requête
    enable_firewall_all()

    # 2) Injecter les règles globales sur TOUS les switchs en utilisant "all"
    for rule in global_rules:
        url = f"{RYU_BASE_URL}/firewall/rules/all"
        http_post(url, rule)
        print(f"    Global firewall rule applied on ALL switches: {rule.get('description', rule)}")

    # 3) Inject DENY rules as actual OpenFlow DROP flows (cela reste via OF_DPIDS car c'est direct flowentry)
    for rule in specific_rules:
        action = str(rule.get("actions", "")).upper()

        if action == "DENY":
            for dpid in OF_DPIDS:
                payload = build_drop_flow_from_firewall_rule(dpid, rule)
                url = f"{RYU_BASE_URL}/stats/flowentry/add"
                http_post(url, payload)
                print(f"    OpenFlow DENY rule applied on switch {dpid}: {rule.get('description', rule)}")
        else:
            # Handle future specific ALLOW rules si elles sont ajoutées plus tard
            url = f"{RYU_BASE_URL}/firewall/rules/all"
            http_post(url, rule)
            print(f"    Specific firewall rule applied globally: {rule.get('description', rule)}")


def deploy_qos() -> None:
    print("*** Reading and applying QoS policies (Policy as Code)...")

    if not os.path.exists(QOS_POLICY_PATH):
        print("    qos.json not found, skipping QoS.")
        return

    qos_data = load_json_file(QOS_POLICY_PATH)
    policing_rules = qos_data.get("policing_rules", [])

    if not policing_rules:
        print("    No QoS policy defined.")
        return

    for rule in policing_rules:
        interface = rule.get("interface")
        rate_kbps = rule.get("rate_kbps")
        burst_kb = rule.get("burst_kb", 1000)

        if not interface or rate_kbps is None:
            raise ValueError(f"Invalid QoS rule: {rule}")

        apply_ovs_ingress_policing(interface, int(rate_kbps), int(burst_kb))
        print(f"    QoS rule applied: {rule.get('description', rule)}")


def main() -> int:
    try:
        wait_for_ryu_and_switches()
        deploy_firewall()
        deploy_qos()
        print("*** All policies (Firewall + QoS) were applied successfully!")
        return 0

    except Exception as e:
        print(f"*** Error while deploying policies: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())