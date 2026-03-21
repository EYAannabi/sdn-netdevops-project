# scripts/deploy_policies.py
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

FIREWALL_DPIDS = [
    "0000000000000001",
    "0000000000000002",
    "0000000000000003",
    "0000000000000004",
]

QOS_DPIDS = [1, 2, 3, 4]


def load_json_file(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Fichier introuvable : {path}")

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


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
            response = requests.get(switches_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                switches = response.json()
                if isinstance(switches, list) and len(switches) > 0:
                    print(f"*** ✅ API Ryu disponible, switches connectés : {switches}")
                    return
                print(f"    Tentative {attempt}/{max_retries}... aucun switch connecté pour l'instant.")
            else:
                print(f"    Tentative {attempt}/{max_retries}... HTTP {response.status_code}")
        except requests.RequestException as e:
            print(f"    Tentative {attempt}/{max_retries}... erreur: {e}")

        time.sleep(delay)

    raise RuntimeError("API Ryu disponible mais aucun switch connecté, ou API indisponible.")


def enable_firewall_on_switch(dpid: str) -> None:
    url = f"{RYU_BASE_URL}/firewall/module/enable/{dpid}"
    http_put(url)
    print(f"    ✅ Firewall activé sur switch {dpid}")


def deploy_firewall(dpids: List[str]) -> None:
    print("*** 🛡️ Lecture et injection des politiques Firewall (Policy as Code)...")
    policies = load_json_file(FIREWALL_POLICY_PATH)

    global_rules = policies.get("global_rules", [])
    specific_rules = policies.get("specific_rules", [])

    for dpid in dpids:
        enable_firewall_on_switch(dpid)

        for rule in global_rules:
            url = f"{RYU_BASE_URL}/firewall/rules/{dpid}"
            http_post(url, rule)
            print(f"    ✅ Règle globale appliquée sur {dpid}: {rule}")

        for rule in specific_rules:
            url = f"{RYU_BASE_URL}/firewall/rules/{dpid}"
            http_post(url, rule)
            print(f"    ✅ Règle spécifique appliquée sur {dpid}: {rule.get('description', rule)}")


def deploy_qos(dpids: List[int]) -> None:
    print("*** 📊 Lecture et injection des politiques QoS (Policy as Code)...")

    if not os.path.exists(QOS_POLICY_PATH):
        print("    ⚠️ Fichier qos.json introuvable, QoS ignorée.")
        return

    qos_data = load_json_file(QOS_POLICY_PATH)

    meters = qos_data.get("meters", [])
    qos_rules = qos_data.get("qos_rules", [])

    for dpid in dpids:
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
        deploy_firewall(FIREWALL_DPIDS)
        deploy_qos(QOS_DPIDS)
        print("*** ✅ Toutes les politiques (Firewall + QoS) ont été appliquées avec succès !")
        return 0

    except Exception as e:
        print(f"*** ❌ Erreur lors du déploiement des politiques : {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())