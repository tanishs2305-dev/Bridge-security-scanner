import subprocess
import pickle
from flask import Flask

app = Flask(__name__)

private_key = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

def relay_withdrawal(data):
    print("Signing with key:", private_key)
    signatures = data["signatures"]
    if len(signatures) >= required_validators:
        submit_to_chain(data)

def submit_to_chain(data):
    cmd = "curl -X POST " + data["endpoint"]
    subprocess.run(cmd, shell=True)

def load_config(raw):
    return pickle.loads(raw)

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)