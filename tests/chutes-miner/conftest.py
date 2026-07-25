import os
import json
import runpy
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


pytest_configure(None)

# The repository also has tests/fixtures. When pytest collects the whole
# monorepo that package may already occupy ``sys.modules["fixtures"]``, so an
# absolute wildcard import silently loads the wrong fixture set. Load this
# suite's files by exact path and publish their pytest-decorated callables.
_FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"
for _fixture_name in (
    "db_fixtures.py",
    "k8s_fixtures.py",
    "redis_fixutres.py",
    "aiohttp_fixtures.py",
):
    globals().update(
        {
            name: value
            for name, value in runpy.run_path(
                str(_FIXTURE_ROOT / _fixture_name),
            ).items()
            if not name.startswith("__")
        }
    )
