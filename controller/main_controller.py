import yaml
import os
import sys

CONFIG_PATH = "/app/iac/controller_config.yml"

try:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    apps = config["controller"]["apps"]

    print(f"Launching Ryu controller with: {apps}", flush=True)

    os.execvp("ryu-manager", ["ryu-manager", "--verbose"] + apps)

except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)