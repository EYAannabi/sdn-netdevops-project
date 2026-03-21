import os
import time
import requests
from prometheus_client import start_http_server, Gauge

RYU_BASE_URL = os.getenv("RYU_BASE_URL", "http://sdn-controller:8080")

TX_BYTES = Gauge("ryu_port_tx_bytes", "Bytes transmis par le port", ["dpid", "port_no"])
RX_BYTES = Gauge("ryu_port_rx_bytes", "Bytes recus par le port", ["dpid", "port_no"])

def fetch_metrics():
    try:
        switches_resp = requests.get(f"{RYU_BASE_URL}/stats/switches", timeout=5)
        if switches_resp.status_code != 200:
            print(f"Erreur HTTP switches: {switches_resp.status_code}")
            return

        dpids = switches_resp.json()

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

if __name__ == "__main__":
    start_http_server(8000)
    print("🚀 SDN Exporter démarré sur le port 8000...")
    while True:
        fetch_metrics()
        time.sleep(5)