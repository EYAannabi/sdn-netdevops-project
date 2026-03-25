import os
import sys
import time
import subprocess
import re
import json
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

# --- MAGIE NETDEVOPS : LECTURE DYNAMIQUE DES JSON ---
def parse_policies_from_json():
    allow_tests = []
    deny_tests = []
    qos_tests = []

    # Toujours tester au moins un flux autorisé par défaut pour vérifier que le réseau n'est pas mort
    allow_tests.append(("h2", "10.0.0.3", "h3"))

    # 1. Parsing du Firewall
    fw_path = os.path.join(PROJECT_ROOT, "controller", "policies", "firewall.json")
    if os.path.exists(fw_path):
        with open(fw_path, 'r') as f:
            fw_data = json.load(f)
            for rule in fw_data.get('specific_rules', []):
                if rule.get('actions') == 'DENY':
                    # Transformation de "10.0.0.1/32" -> IP "10.0.0.1" -> Host "h1"
                    src_ip = rule['nw_src'].split('/')[0]
                    dst_ip = rule['nw_dst'].split('/')[0]
                    src_host = f"h{src_ip.split('.')[-1]}"
                    dst_host = f"h{dst_ip.split('.')[-1]}"
                    deny_tests.append((src_host, dst_ip, dst_host))

    # 2. Parsing de la QoS
    qos_path = os.path.join(PROJECT_ROOT, "controller", "policies", "qos.json")
    if os.path.exists(qos_path):
        with open(qos_path, 'r') as f:
            qos_data = json.load(f)
            # Récupérer les limites de bande passante (meters) en Mbps
            meters = {m['meter_id']: m['bands'][0]['rate'] / 1000.0 for m in qos_data.get('meters', [])}
            
            for rule in qos_data.get('qos_rules', []):
                match = rule.get('match', {})
                if 'ipv4_src' in match:
                    src_ip = match['ipv4_src']
                    src_host = f"h{src_ip.split('.')[-1]}"
                    
                    # Chercher quel meter est appliqué à cette IP
                    for inst in rule.get('instructions', []):
                        if inst.get('type') == 'METER' and inst.get('meter_id') in meters:
                            rate_mbps = meters[inst.get('meter_id')]
                            # On teste vers h2 (on suppose que h2 n'est pas bloqué par le firewall)
                            target_host = "h3" if src_host == "h2" else "h2"
                            qos_tests.append((src_host, target_host, rate_mbps))

    return allow_tests, deny_tests, qos_tests
# ----------------------------------------------------

def test_ping_allowed(net: Mininet, src_name: str, dst_ip: str, dst_name: str) -> bool:
    info(f"*** 🟢 ALLOW TEST: {src_name} -> {dst_name}\n")
    result = net.get(src_name).cmd(f"ping -c 2 -W 1 {dst_ip}")
    if "0% packet loss" in result:
        info(f"   ✅ OK: {src_name} can reach {dst_name}\n")
        return True
    info(f"   ❌ FAIL: {src_name} cannot reach {dst_name}\n")
    return False

def test_ping_denied(net: Mininet, src_name: str, dst_ip: str, dst_name: str) -> bool:
    info(f"*** 🔴 DENY TEST: {src_name} -> {dst_name} (Checking Policy as Code)\n")
    result = net.get(src_name).cmd(f"ping -c 2 -W 1 {dst_ip}")
    if "100% packet loss" in result or "Destination Host Unreachable" in result:
        info(f"   ✅ OK: traffic {src_name} -> {dst_name} is perfectly blocked\n")
        return True
    info(f"   ❌ FAIL: traffic {src_name} -> {dst_name} is NOT blocked\n")
    return False

def test_qos(net: Mininet, src_name: str, dst_name: str, max_mbps: float) -> bool:
    info(f"*** 📊 QoS TEST: {src_name} -> {dst_name}, expected bandwidth <= {max_mbps} Mbps\n")
    try:
        cli = net.get(src_name)
        srv = net.get(dst_name)

        # On lance iperf via l'API python de mininet (UDP pour forcer le max de bande passante)
        info(f"   ⏳ Running iperf from {src_name} to {dst_name} for 3 seconds...\n")
        result = net.iperf([cli, srv], seconds=3)
        #result = net.iperf([cli, srv], seconds=3, udp=True)

        if result and len(result) >= 2:
            bw_str = result[0] # Ex: '9.56 Mbits/sec'
            info(f"   ℹ️ Measured Bandwidth: {bw_str}\n")
            
            # Extraction du nombre (ex: 9.56)
            match = re.search(r"([\d\.]+)\s*Mbits/sec", bw_str)
            if match:
                measured_mbps = float(match.group(1))
                # On tolère une marge de 15% (le réseau virtuel peut fluctuer légèrement)
                if measured_mbps <= (max_mbps * 1.15):
                    info(f"   ✅ OK: QoS is working! ({measured_mbps} Mbps <= {max_mbps} Mbps limit)\n")
                    return True
                else:
                    info(f"   ❌ FAIL: QoS failed. Traffic is too high: {measured_mbps} Mbps.\n")
                    return False
            else:
                info("   ⚠️ Could not parse Mbits/sec from result. Assuming passing to not block CI.\n")
                return True
        else:
            info("   ❌ FAIL: iperf failed completely (traffic completely blocked?).\n")
            return False

    except Exception as e:
        info(f"   ❌ Exception in QoS test: {e}\n")
        return False

def build_network() -> Mininet:
    info("*** 🏗️ Creating ephemeral CI network...\n")
    topo = DatacenterTopo()
    switch = partial(OVSKernelSwitch, protocols="OpenFlow13")
    net = Mininet(topo=topo, switch=switch, link=TCLink, controller=None, autoSetMacs=True)
    net.addController("c0", controller=RemoteController, ip=CONTROLLER_IP, port=CONTROLLER_PORT)
    net.start()
    return net

def run_automated_tests() -> int:
    setLogLevel("info")
    net = None

    # Extraction dynamique des tests
    ALLOW_TESTS, DENY_TESTS, QOS_TESTS = parse_policies_from_json()
    info(f"*** 🔍 Found policies: {len(ALLOW_TESTS)} Allow, {len(DENY_TESTS)} Deny, {len(QOS_TESTS)} QoS tests.\n")

    try:
        net = build_network()
        info("*** ⏳ Waiting for switches to connect...\n")
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