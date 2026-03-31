import json
import os
import sys
import time
from typing import Any, Dict, List

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

# Pour les APIs OpenFlow /stats/*
OF_DPIDS = [1, 2, 3, 4]
QOS_DPIDS = [4]

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
    meters = qos_data.get("meters", [])
    qos_rules = qos_data.get("qos_rules", [])

    if not meters and not qos_rules:
        print("    ⚠️ Aucune politique QoS définie.")
        return

    for meter in meters:
        validate_meter(meter)

    for rule in qos_rules:
        validate_qos_rule(rule)

    for dpid in QOS_DPIDS:
    for meter in meters:
        meter_payload = {"dpid": dpid}
        meter_payload.update(meter)
        url = f"{RYU_BASE_URL}/stats/meterentry/add"
        http_post(url, meter_payload)
        print(f"    ✅ Meter appliqué sur switch {dpid}: {meter.get('description', meter)}")

    for rule in qos_rules:
        rule_payload = {"dpid": dpid}
        rule_payload.update(rule)
        url = f"{RYU_BASE_URL}/stats/flowentry/add"
        http_post(url, rule_payload)
        print(f"    ✅ Règle QoS appliquée sur switch {dpid}: {rule.get('description', rule)}")

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