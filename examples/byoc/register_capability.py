"""Register the BYOC capability with the orchestrator. See doc/byoc.md for usage."""
import os
import urllib3
import requests
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# price_per_unit must be > 0: the gateway's resolvePriceInfo rejects BYOC
# capability entries with a zero price and refuses to generate payments.
# ORCHESTRATOR_HOST: host IP for orchestrator (default 127.0.0.1)
# ORCHESTRATOR_PORT: orchestrator port (default 8935)
# WORKER_URL: URL orch uses to reach worker (default http://${ORCHESTRATOR_HOST}:5000)
host = os.environ.get("ORCHESTRATOR_HOST", "127.0.0.1")
port = os.environ.get("ORCHESTRATOR_PORT", "8935")
orch_url = os.environ.get("ORCHESTRATOR_URL") or f"https://{host}:{port}"
worker_url = os.environ.get("WORKER_URL") or f"http://{host}:5000"

data = {
    "name": "text-reversal",
    "url": worker_url,
    "capacity": 1,
    "price_per_unit": 1,
    "price_scaling": 1,
    "currency": "wei",
}

headers = {"Authorization": "orch-secret"}

for i in range(10):
    time.sleep(1)
    try:
        r = requests.post(
            f"{orch_url.rstrip('/')}/capability/register",
            json=data,
            headers=headers,
            verify=False,  # ignore invalid/self-signed SSL certs
        )
        if r.status_code == 200:
            print("Registered capability: text-reversal")
            break
        print(f"Registration failed ({r.status_code}): {r.text}")
    except Exception as e:
        print(f"Attempt {i + 1}/10: {e}")
