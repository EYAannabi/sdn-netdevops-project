import json
import os
import sys
import time
from typing import Any, Dict, List
import subprocess
import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FIREWALL_POLICY_PATH = os.path.join(BASE_DIR, "../controller/policies/firewall.json")
QOS_POLICY_PATH = os.path.join(BASE_DIR, "../controller/policies/qos.json")

RYU_BASE_URL = os.getenv("RYU_BASE_URL", "http://127.0.0.1:8080")
REQUEST_TIMEOUT = 10

# Pour le module firewall REST
FIREWALL_DPIDS = [
    "0000000000000001",
    "0000000000000002",
    "0000000000000003",
    "0000000000000004",
]
OVSDB_PORT = 6632
HOST_EDGE_SWITCH = {
    "10.0.0.1": 3,  # h1 sur s3
    "10.0.0.2": 3,  # h2 sur s3
    "10.0.0.3": 4,  # h3 sur s4
    "10.0.0.4": 4   # h4 sur s4
}
# Pour les APIs OpenFlow /stats/*
OF_DPIDS = [1, 2, 3, 4]
#QOS_DPIDS = [4]
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

    print(f"    ✅ QoS policing appliqué sur {interface}: rate={rate_kbps} kbps, burst={burst_kb} kb")
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
    print(f"    ✅ OVSDB configuré pour le switch {dpid}")


def build_queue_payload_from_meter(meter: Dict[str, Any], port_name: str) -> Dict[str, Any]:
    bands = meter.get("bands", [])
    if not bands:
        raise ValueError(f"Meter sans bande: {meter}")

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
    raise ValueError(f"IP source QoS inconnue: {src_ip}")

def load_json_file(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Fichier introuvable : {path}")

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
    print("*** ⏳ Vérification que l'API Ryu est disponible et que les switches sont connectés...")
    switches_url = f"{RYU_BASE_URL}/stats/switches"

    for attempt in range(1, max_retries + 1):
        try:
            response = http_get(switches_url)
            switches = response.json()

            if isinstance(switches, list) and len(switches) > 0:
                print(f"*** ✅ API Ryu disponible, switches connectés : {switches}")
                return

            print(f"    Tentative {attempt}/{max_retries}... aucun switch connecté pour l'instant.")
        except requests.RequestException as e:
            print(f"    Tentative {attempt}/{max_retries}... erreur: {e}")

        time.sleep(delay)

    raise RuntimeError("API Ryu disponible mais aucun switch connecté, ou API indisponible.")


def enable_firewall_on_switch(dpid: str) -> None:
    url = f"{RYU_BASE_URL}/firewall/module/enable/{dpid}"
    http_put(url)
    print(f"    ✅ Firewall activé sur switch {dpid}")


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
        raise ValueError(f"Règle firewall invalide: champ 'actions' manquant -> {rule}")

    if rule["actions"] not in ["ALLOW", "DENY"]:
        raise ValueError(f"Règle firewall invalide: actions doit être ALLOW ou DENY -> {rule}")


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
    print("*** 🛡️ Lecture et injection des politiques Firewall (Policy as Code)...")
    policies = load_json_file(FIREWALL_POLICY_PATH)
    extracted = extract_firewall_rules(policies)

    global_rules = [normalize_firewall_rule(r) for r in extracted["global_rules"]]
    specific_rules = [normalize_firewall_rule(r) for r in extracted["specific_rules"]]

    for rule in global_rules + specific_rules:
        validate_firewall_rule(rule)

    # 1) Activer le module firewall et injecter seulement les règles globales ALLOW
    for dpid in FIREWALL_DPIDS:
        enable_firewall_on_switch(dpid)

        for rule in global_rules:
            url = f"{RYU_BASE_URL}/firewall/rules/{dpid}"
            http_post(url, rule)
            print(f"    ✅ Règle firewall globale appliquée sur {dpid}: {rule.get('description', rule)}")

    # 2) Injecter les DENY comme vrais flows OpenFlow DROP
    for rule in specific_rules:
        action = str(rule.get("actions", "")).upper()

        if action == "DENY":
            for dpid in OF_DPIDS:
                payload = build_drop_flow_from_firewall_rule(dpid, rule)
                url = f"{RYU_BASE_URL}/stats/flowentry/add"
                http_post(url, payload)
                print(f"    ✅ Règle DENY OpenFlow appliquée sur switch {dpid}: {rule.get('description', rule)}")
        else:
            # Si jamais tu ajoutes des règles spécifiques ALLOW plus tard
            for dpid in FIREWALL_DPIDS:
                url = f"{RYU_BASE_URL}/firewall/rules/{dpid}"
                http_post(url, rule)
                print(f"    ✅ Règle firewall spécifique appliquée sur {dpid}: {rule.get('description', rule)}")


def validate_meter(meter: Dict[str, Any]) -> None:
    if "meter_id" not in meter:
        raise ValueError(f"Meter invalide: meter_id manquant -> {meter}")
    if "bands" not in meter or not meter["bands"]:
        raise ValueError(f"Meter invalide: bands manquant/vide -> {meter}")


def validate_qos_rule(rule: Dict[str, Any]) -> None:
    if "match" not in rule:
        raise ValueError(f"Règle QoS invalide: match manquant -> {rule}")
    if "instructions" not in rule or not rule["instructions"]:
        raise ValueError(f"Règle QoS invalide: instructions manquantes -> {rule}")

def deploy_qos() -> None:
    print("*** 📊 Lecture et injection des politiques QoS (Policy as Code)...")

    if not os.path.exists(QOS_POLICY_PATH):
        print("    ⚠️ Fichier qos.json introuvable, QoS ignorée.")
        return

    qos_data = load_json_file(QOS_POLICY_PATH)
    policing_rules = qos_data.get("policing_rules", [])

    if not policing_rules:
        print("    ⚠️ Aucune politique QoS définie.")
        return

    for rule in policing_rules:
        interface = rule.get("interface")
        rate_kbps = rule.get("rate_kbps")
        burst_kb = rule.get("burst_kb", 1000)

        if not interface or rate_kbps is None:
            raise ValueError(f"Règle QoS invalide: {rule}")

        apply_ovs_ingress_policing(interface, int(rate_kbps), int(burst_kb))
        print(f"    ✅ Règle QoS appliquée: {rule.get('description', rule)}")
        
def main() -> int:
    try:
        wait_for_ryu_and_switches()
        deploy_firewall()
        deploy_qos()
        print("*** ✅ Toutes les politiques (Firewall + QoS) ont été appliquées avec succès !")
        return 0

    except Exception as e:
        print(f"*** ❌ Erreur lors du déploiement des politiques : {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())