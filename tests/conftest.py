# ruff: noqa: E402,F403
import os
import json
from pathlib import Path


def pytest_configure(config):
    """Set up environment variables before any modules are imported."""
    os.environ["MINER_OWNER_SS58"] = "5E6xfU3oNU7y1a7pQwoc31fmUjwBZ2gKcNCw8EXsdtCQieUQ"
    session_file = Path("/tmp/chutes-miner-pytest-session.env")
    session_file.write_text("CHUTES_ATTESTED_SESSION=test-attested-session\n")
    os.environ["CHUTES_ATTESTED_SESSION_FILE"] = str(session_file)

    validators_json = {
        "supported": [
            {
                "hotkey": "test_validator",
                "registry": "test-registry",
                "api": "http://test-api",
                "socket": "ws://test-socket",
            }
        ]
    }
    os.environ["VALIDATORS"] = json.dumps(validators_json)

    # Print confirmation for debugging
    print("Environment variables set up for testing!")


# pytest_configure(None)

from constants import *
