import os
import time
import requests
from prometheus_client import start_http_server, Gauge

RYU_BASE_URL = os.getenv("RYU_BASE_URL", "http://sdn-controller:8080")

TX_BYTES = Gauge("ryu_port_tx_bytes", "Bytes transmis par le port", ["dpid", "port_no"])
RX_BYTES = Gauge("ryu_port_rx_bytes", "Bytes recus par le port", ["dpid", "port_no"])
RYU_CONTROLLER_UP = Gauge("ryu_controller_up", "Etat de connexion du contrôleur Ryu (1=up, 0=down)")
RYU_CONNECTED_SWITCHES = Gauge("ryu_connected_switches", "Nombre de switches connectés au contrôleur Ryu")

def fetch_metrics():
    try:
        switches_resp = requests.get(f"{RYU_BASE_URL}/stats/switches", timeout=5)
        if switches_resp.status_code != 200:
            print(f"Erreur HTTP switches: {switches_resp.status_code}")
            RYU_CONTROLLER_UP.set(0)
            RYU_CONNECTED_SWITCHES.set(0)
            return

        dpids = switches_resp.json()
        RYU_CONTROLLER_UP.set(1)
        RYU_CONNECTED_SWITCHES.set(len(dpids))

        for dpid in dpids:
            port_resp = requests.get(f"{RYU_BASE_URL}/stats/port/{dpid}", timeout=5)
            if port_resp.status_code != 200:
                print(f"Erreur HTTP port stats pour dpid {dpid}: {port_resp.status_code}")
                continue

            data = port_resp.json()
            ports = data.get(str(dpid), [])

            for port in ports:
                port_no = str(port.get("port_no"))
                if port_no != "LOCAL":
                    TX_BYTES.labels(dpid=str(dpid), port_no=port_no).set(port.get("tx_bytes", 0))
                    RX_BYTES.labels(dpid=str(dpid), port_no=port_no).set(port.get("rx_bytes", 0))

    except Exception as e:
        print(f"Erreur de connexion à Ryu: {e}")
        RYU_CONTROLLER_UP.set(0)
        RYU_CONNECTED_SWITCHES.set(0)

if __name__ == "__main__":
    start_http_server(8000)
    print("🚀 SDN Exporter démarré sur le port 8000...")
    while True:
        fetch_metrics()
        time.sleep(5)