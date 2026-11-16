"""Secure relayer example: the fixed counterpart of vulnerable_relayer.py."""

import json
import os
import subprocess

from flask import Flask

app = Flask(__name__)

# Keys come from the environment / a KMS at runtime, never from source code.
SIGNING_KEY_ID = os.environ.get("RELAYER_KEY_ID")

processed_ids = set()
authorized_validators = {"validator-a", "validator-b", "validator-c"}
REQUIRED_VALIDATORS = 2


def relay_withdrawal(message_id, signers):
    if message_id in processed_ids:
        return False
    valid = {s for s in signers if s in authorized_validators}
    if len(valid) < REQUIRED_VALIDATORS:
        return False
    processed_ids.add(message_id)
    submit_to_chain(message_id)
    return True


def submit_to_chain(message_id):
    subprocess.run(["curl", "-X", "POST", "https://relay.internal/submit", "-d", str(message_id)], check=True)


def load_config(raw):
    return json.loads(raw)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
