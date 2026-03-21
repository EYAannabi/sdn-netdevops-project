import yaml
import subprocess
import sys

CONFIG_PATH = "/app/iac/controller_config.yml"

try:
    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)

    apps = config["controller"]["apps"]

    print(f"🚀 Lancement du contrôleur Ryu avec : {apps}")

    subprocess.run(["ryu-manager", "--verbose"] + apps)

except Exception as e:
    print(f"❌ Erreur : {e}")
    sys.exit(1)