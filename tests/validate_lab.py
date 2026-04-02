# tests/validate_lab.py
import subprocess
import sys
import time

import requests

RYU_HEALTH_URL = "http://127.0.0.1:8080/firewall/module/status"
TOPOLOGY_PROCESS_NAME = "start_lab_topology.py"


def run(cmd):
    return subprocess.run(cmd, shell=True, text=True, capture_output=True)


def main():
    print("=== Persistent lab validation ===")
    time.sleep(5)

    # 1. Check the Ryu REST API
    try:
        response = requests.get(RYU_HEALTH_URL, timeout=5)
        if response.status_code != 200:
            print(f"Ryu API unhealthy: HTTP {response.status_code}")
            sys.exit(1)
        print("Ryu REST API is operational")
    except Exception as e:
        print(f"Ryu API error: {e}")
        sys.exit(1)

    # 2. Check that the persistent topology is running
    topo_check = run(f"pgrep -f {TOPOLOGY_PROCESS_NAME}")
    if topo_check.returncode != 0:
        print("The persistent topology is not running")
        sys.exit(1)
    print("Persistent topology process detected")

    # 3. Check that OVS has bridges
    ovs_check = run("sudo ovs-vsctl list-br")
    if ovs_check.returncode != 0:
        print("Unable to read OVS bridges")
        print(ovs_check.stderr)
        sys.exit(1)

    bridges = [line.strip() for line in ovs_check.stdout.splitlines() if line.strip()]
    if not bridges:
        print("No OVS bridge detected")
        sys.exit(1)

    print(f"Detected OVS bridges: {', '.join(bridges)}")
    print("Persistent lab validation succeeded")
    sys.exit(0)


if __name__ == "__main__":
    main()
