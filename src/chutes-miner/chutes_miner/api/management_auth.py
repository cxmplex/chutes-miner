"""Authentication policy for destructive miner-management requests."""

from chutes_common.auth import authorize
from chutes_miner.api.config import settings


destructive_management_authorization = authorize(
    allow_miner=True,
    allow_validator=False,
    purpose="management",
    require_v2=lambda: settings.require_v2_management_signatures,
    allow_attested_session=False,
    observe_v1=True,
)
