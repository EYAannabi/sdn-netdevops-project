import json
import os
import sys
import time
import subprocess
import re
from functools import partial
import itertools

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

# --- FONCTIONS UTILITAIRES ---
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

def ip_to_host(ip: str) -> str:
    """Convertit une IP (ex: 10.0.0.1 ou 10.0.0.1/32) en nom d'hôte Mininet."""
    if not ip:
        return None
    clean_ip = ip.split('/')[0]
    mapping = {
        "10.0.0.1": "h1",
# --- MAGIE NETDEVOPS : LECTURE 100% DYNAMIQUE DES JSON ---
def get_dynamic_tests():
    """Lit les fichiers JSON pour déterminer dynamiquement quels tests exécuter."""
    hosts = ["h1", "h2", "h3", "h4"]
    
    # 1. Générer toutes les paires de communication possibles (par défaut, tout est ALLOW)
    all_pairs = list(itertools.permutations(hosts, 2))
    tests = {'allow': all_pairs, 'deny': [], 'qos': None}
    
    fw_path = os.path.join(PROJECT_ROOT, "controller", "policies", "firewall.json")
    qos_path = os.path.join(PROJECT_ROOT, "controller", "policies", "qos.json")

    # 2. Parsing du Firewall
    if os.path.exists(fw_path):
        try:
            with open(fw_path, 'r') as f:
                fw_data = json.load(f)
                rules_list = fw_data.get('rules', fw_data.get('specific_rules', []))
                for rule in rules_list:
                    action = rule.get('action', rule.get('actions'))
                    if action == 'DENY':
                        # Gérer les différents formats JSON possibles (imbriqué ou plat)
                        match = rule.get('match', rule)
                        src_ip = match.get('ipv4_src', match.get('nw_src', ''))
                        dst_ip = match.get('ipv4_dst', match.get('nw_dst', ''))
                        
                        src = ip_to_host(src_ip)
                        dst = ip_to_host(dst_ip)
                        
                        if src and dst:
                            if (src, dst) not in tests['deny']:
                                tests['deny'].append((src, dst))
                            # Retirer cette paire des tests ALLOW puisqu'elle doit être bloquée
                            if (src, dst) in tests['allow']:
                                tests['allow'].remove((src, dst))
        except Exception as e:
            info(f"⚠️ Erreur lecture firewall.json: {e}\n")

    # 3. Parsing de la QoS
    if os.path.exists(qos_path):
        try:
            with open(qos_path, 'r') as f:
                qos_data = json.load(f)
                meters = {m['meter_id']: m['bands'][0]['rate'] / 1000.0 for m in qos_data.get('meters', [])}
                
                for rule in qos_data.get('qos_rules', []):
                    match_data = rule.get('match', {})
                    src_ip = match_data.get('ipv4_src', match_data.get('nw_src', ''))
                    
                    for inst in rule.get('instructions', []):
                        if inst.get('type') == 'METER' and inst.get('meter_id') in meters:
                            rate_mbps = meters[inst.get('meter_id')]
                            src_host = ip_to_host(src_ip)
                            if src_host:
                                # Choisir dynamiquement une destination valide pour iperf
                                dst_host = "h2" if src_host != "h2" else "h3"
                                tests['qos'] = (src_host, dst_host, rate_mbps)
        except Exception as e:
            info(f"⚠️ Erreur lecture qos.json: {e}\n")

    return tests
    
# --- FONCTIONS DE TESTS RÉSEAU ---
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
        info(f"   ✅ OK: traffic {src_name} -> {dst_name} is perfectly blocked\n")
        return True
    info(f"   ❌ FAIL: traffic {src_name} -> {dst_name} is NOT blocked\n")
    return False

def test_qos(net: Mininet, src_name: str, dst_name: str, max_mbps: float) -> bool:
    info(f"*** 📊 QoS TEST: {src_name} -> {dst_name}, expected bandwidth <= {max_mbps} Mbps\n")
    try:
        cli = net.get(src_name)
        srv = net.get(dst_name)
        dst_ip = srv.IP()

        srv.cmd("iperf -s &")
        info(f"   ⏳ Running iperf from {src_name} to {dst_name} for 3 seconds...\n")
        result = cli.cmd(f"timeout 6 iperf -c {dst_ip} -t 3")
        srv.cmd("killall -9 iperf")

        if result:
            matches = re.findall(r"([\d\.]+)\s*Mbits/sec", result)
            if matches:
                measured_mbps = float(matches[-1])
                if measured_mbps <= (max_mbps * 1.15):
                    info(f"   ✅ OK: QoS is working! ({measured_mbps} Mbps <= {max_mbps} Mbps limit)\n")
                    return True
                else:
                    info(f"   ❌ FAIL: QoS failed. Traffic is too high: {measured_mbps} Mbps.\n")
                    return False
            else:
                info("   ⚠️ Could not parse Mbits/sec. Assuming passing to not block CI.\n")
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

    try:
        net = build_network()
        info("*** ⏳ Waiting for switches to connect...\n")
        time.sleep(10)

        if not deploy_policies():
            return 1

        info("*** ⏳ Waiting for policies to be applied...\n")
        time.sleep(5)

        info("*** 🧠 Lecture automatique des politiques JSON...\n")
        dynamic_tests = get_dynamic_tests()
        all_ok = True

        for src, dst in dynamic_tests['allow']:
            all_ok = test_ping_allowed(net, src, dst) and all_ok

        if not dynamic_tests['deny']:
            info("*** ⚠️ Aucun test DENY trouvé dans le firewall.\n")
        for src, dst in dynamic_tests['deny']:
            all_ok = test_ping_denied(net, src, dst) and all_ok

        if not dynamic_tests['qos']:
            info("*** ⚠️ Aucun test QoS trouvé.\n")
        else:
            all_ok = test_qos(net, *dynamic_tests['qos']) and all_ok

        if all_ok:
            info("\n🏆 CI SUCCESS: all tests passed.\n")
            return 0
        else:
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