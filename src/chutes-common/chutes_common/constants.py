VALIDATOR_HEADER = "X-Chutes-Validator"
HOTKEY_HEADER = "X-Chutes-Hotkey"
MINER_HEADER = "X-Chutes-Miner"
NONCE_HEADER = "X-Chutes-Nonce"
SIGNATURE_HEADER = "X-Chutes-Signature"
# Request-signature format version. "2" binds HTTP method + path into the signed message so a
# captured read signature cannot be replayed to a same-purpose destructive endpoint; absent/"1" = v1.
SIG_VERSION_HEADER = "X-Chutes-Sig-Version"
SIG_VERSION_V2 = "2"

# Monitoring
API_PREFIX = "/api/v1"
CLUSTER_ENDPOINT = f"{API_PREFIX}/clusters"
MONITORING_ENDPOINT = f"{API_PREFIX}/monitoring"
MONITORING_PURPOSE = "monitoring"
HEALTH_PURPOSE = "health"
