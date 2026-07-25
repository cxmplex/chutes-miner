import json
import math
import os
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

GPU_MINER_RUNTIME_PURPOSES = [
    "cache",
    "gpu-infra",
    "instances",
    "launch",
    "miner",
    "nodes",
    "registry",
    "sockets",
]


class Validator(BaseModel):
    hotkey: str
    registry: str
    api: str
    socket: str


class MinerSettings(BaseSettings):
    _validators: List[Validator] = []

    miner_ss58: str = os.environ["MINER_OWNER_SS58"]
    attested_session_file: str = os.getenv(
        "CHUTES_ATTESTED_SESSION_FILE",
        "/run/chutes-gpu/miner-session.env",
    )
    validators_file: str = os.getenv(
        "CHUTES_VALIDATORS_FILE",
        "/run/chutes-gpu/miner-session.json",
    )
    gpu_registration_file: str = os.getenv(
        "CHUTES_GPU_REGISTRATION_FILE",
        "/run/chutes-gpu/registration.json",
    )
    gpu_verified_env_file: str = os.getenv(
        "CHUTES_GPU_VERIFIED_ENV_FILE",
        "/run/chutes-gpu/verified.env",
    )
    attested_cert_file: str = os.getenv(
        "CHUTES_ATTESTED_CERT_FILE",
        "/run/chutes-tls/server.crt",
    )
    attested_key_file: str = os.getenv(
        "CHUTES_ATTESTED_KEY_FILE",
        "/run/chutes-tls/server.key",
    )
    registry_scopes_file: str = os.getenv(
        "CHUTES_REGISTRY_SCOPES_FILE",
        "/var/lib/chutes-registry/scopes.json",
    )
    validators_json: Optional[str] = os.getenv("VALIDATORS")
    gpu_tee_only: bool = os.getenv("GPU_TEE_ONLY", "false").lower() == "true"

    def _runtime_document(self) -> dict:
        return self._canonical_document(Path(self.validators_file), "validator/session")

    @staticmethod
    def _canonical_document(path: Path, description: str) -> dict:
        payload = path.read_bytes()
        document = json.loads(payload.decode("ascii"))
        canonical = (
            json.dumps(
                document,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
        if payload != canonical or not isinstance(document, dict):
            raise ValueError(f"seedless GPU {description} document is invalid")
        return document

    def _validated_runtime_document(self) -> dict:
        document = self._runtime_document()
        if (
            set(document)
            != {
                "schema",
                "version",
                "server_id",
                "owner_hotkey",
                "gpu_uuids",
                "gpu_identifiers",
                "runtime_session",
                "runtime_session_expires_at",
                "allowed_purposes",
                "validator",
            }
            or document["schema"] != "chutes.gpu-miner-session"
            or document["version"] != 1
            or document["owner_hotkey"] != self.miner_ss58
            or not isinstance(document["runtime_session"], str)
            or not document["runtime_session"]
            or document["allowed_purposes"] != GPU_MINER_RUNTIME_PURPOSES
            or not isinstance(document["gpu_uuids"], list)
            or not isinstance(document["gpu_identifiers"], list)
            or not document["gpu_uuids"]
            or len(document["gpu_uuids"]) != len(document["gpu_identifiers"])
            or not isinstance(document["validator"], dict)
            or set(document["validator"]) != {"hotkey", "registry", "api", "socket"}
        ):
            raise ValueError("seedless GPU validator/session document is invalid")
        return document

    @property
    def validators(self) -> List[Validator]:
        if self.gpu_tee_only:
            return [Validator(**self._validated_runtime_document()["validator"])]
        if self._validators:
            return self._validators
        if self.validators_json is None:
            raise ValueError("VALIDATORS must be configured")
        data = json.loads(self.validators_json)
        self._validators = [Validator(**item) for item in data["supported"]]
        return self._validators

    @property
    def attested_session(self) -> str:
        if self.gpu_tee_only:
            return str(self._validated_runtime_document()["runtime_session"])
        values = {}
        for line in Path(self.attested_session_file).read_text(encoding="ascii").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value
        token = values.get("CHUTES_ATTESTED_SESSION")
        if not token:
            raise ValueError("attested GPU runtime session file is invalid")
        return token

    @property
    def seedless_gpu_identity(self) -> dict:
        if not self.gpu_tee_only:
            raise ValueError("seedless GPU identity is unavailable outside GPU TEE mode")
        runtime = self._validated_runtime_document()
        registration = self._canonical_document(
            Path(self.gpu_registration_file),
            "registration",
        )
        required = {
            "server_id",
            "owner_hotkey",
            "reservation_id",
            "claims_sha256",
            "allocation_group_id",
            "allocation_group_generation",
            "process_incarnation",
            "gpu_uuids",
            "gpu_identifiers",
            "management_mode",
            "measurement_version",
            "measurement_name",
            "measurement_config_fingerprint",
            "trust_set_fingerprint",
            "attestation_id",
            "verified_at",
            "runtime_session",
            "runtime_session_expires_at",
            "status",
        }
        if (
            set(registration) != required
            or registration.get("management_mode") != "miner"
            or registration.get("status") != "registered"
            or registration.get("server_id") != runtime["server_id"]
            or registration.get("owner_hotkey") != runtime["owner_hotkey"]
            or registration.get("gpu_uuids") != runtime["gpu_uuids"]
            or registration.get("gpu_identifiers") != runtime["gpu_identifiers"]
            or registration.get("runtime_session") != runtime["runtime_session"]
            or registration.get("runtime_session_expires_at")
            != runtime["runtime_session_expires_at"]
            or not isinstance(registration.get("attestation_id"), str)
            or not registration["attestation_id"]
            or not isinstance(registration.get("allocation_group_id"), str)
            or not registration["allocation_group_id"]
            or not isinstance(registration.get("allocation_group_generation"), int)
            or registration["allocation_group_generation"] < 1
        ):
            raise ValueError("seedless GPU registration and runtime identities do not match")
        return {
            **registration,
            "validator": runtime["validator"],
        }

    @property
    def miner_hourly_cost(self) -> float:
        if not self.gpu_tee_only:
            raise ValueError("signed miner hourly cost is available only in GPU TEE mode")
        values: dict[str, str] = {}
        for line in Path(self.gpu_verified_env_file).read_text(encoding="ascii").splitlines():
            key, separator, value = line.partition("=")
            if not separator or not key or key in values:
                raise ValueError("verified GPU environment file is invalid")
            values[key] = value
        try:
            cost = float(values["CHUTES_MINER_HOURLY_COST"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("signed miner hourly cost is missing or invalid") from exc
        if not math.isfinite(cost) or cost <= 0:
            raise ValueError("signed miner hourly cost must be positive and finite")
        return cost


miner_settings = MinerSettings()


class RedisSettings(BaseSettings):
    redis_url: str = Field(default="redis://redis:6379", description="Redis URL")


# redis_settings = RedisSettings()
