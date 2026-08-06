import json
import math
import os
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

GPU_MINER_RUNTIME_PURPOSES = [
    "cache",
    "gpu-decommission",
    "gpu-infra",
    "instances",
    "launch",
    "miner",
    "nodes",
    "registry",
    "sockets",
]

GPU_REGISTRATION_V2_SCHEMA = "chutes.gpu-registration-response.v2"
GPU_REGISTRATION_PUBLIC_IDENTITY_FIELDS = (
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
    "status",
)
GPU_RUNTIME_SESSION_IDENTITY_FIELDS = (
    "runtime_session",
    "runtime_session_expires_at",
)
GPU_REGISTRATION_IDENTITY_FIELDS = (
    *GPU_REGISTRATION_PUBLIC_IDENTITY_FIELDS,
    *GPU_RUNTIME_SESSION_IDENTITY_FIELDS,
)
_GPU_REGISTRATION_STRING_FIELDS = frozenset(GPU_REGISTRATION_PUBLIC_IDENTITY_FIELDS) - {
    "allocation_group_generation",
    "gpu_uuids",
    "gpu_identifiers",
}


class SeedlessGPUConfigurationError(ValueError):
    """The measured seedless GPU runtime files cannot be consumed safely."""


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
        "/run/chutes-gpu/credentials/runtime-session.env",
    )
    validators_file: str = os.getenv(
        "CHUTES_VALIDATORS_FILE",
        "/run/chutes-gpu/credentials/runtime-session.json",
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
    registry_workload_token_file: str = os.getenv(
        "CHUTES_REGISTRY_WORKLOAD_TOKEN_FILE",
        "/var/run/secrets/chutes-registry-workload/token",
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
            or not isinstance(document["runtime_session_expires_at"], str)
            or not document["runtime_session_expires_at"]
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
        for line in (
            Path(self.attested_session_file).read_text(encoding="ascii").splitlines()
        ):
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value
        token = values.get("CHUTES_ATTESTED_SESSION")
        if not token:
            raise ValueError("attested GPU runtime session file is invalid")
        return token

    @property
    def registry_workload_token(self) -> str:
        """Read the pod-scoped broker mutation credential from its exact mount."""

        path = Path(self.registry_workload_token_file)
        try:
            token = path.read_text(encoding="ascii").strip()
        except (FileNotFoundError, PermissionError, UnicodeError) as exc:
            raise SeedlessGPUConfigurationError(
                "registry workload authentication token is unavailable"
            ) from exc
        if len(token) != 64 or not token.isalnum():
            raise SeedlessGPUConfigurationError(
                "registry workload authentication token is invalid"
            )
        return token

    @property
    def seedless_gpu_identity(self) -> dict:
        if not self.gpu_tee_only:
            raise ValueError(
                "seedless GPU identity is unavailable outside GPU TEE mode"
            )
        runtime = self._validated_runtime_document()
        registration = self._canonical_document(
            Path(self.gpu_registration_file),
            "registration",
        )
        if (
            registration.get("schema") != GPU_REGISTRATION_V2_SCHEMA
            or type(registration.get("version")) is not int
            or registration["version"] != 2
            or registration.get("state") != "completed"
            or registration.get("management_mode") != "miner"
            or registration.get("status") != "registered"
            or any(
                field in registration for field in GPU_RUNTIME_SESSION_IDENTITY_FIELDS
            )
            or any(
                not isinstance(registration.get(field), str) or not registration[field]
                for field in _GPU_REGISTRATION_STRING_FIELDS
            )
            or type(registration.get("allocation_group_generation")) is not int
            or registration["allocation_group_generation"] < 1
            or not isinstance(registration.get("gpu_uuids"), list)
            or not registration["gpu_uuids"]
            or any(
                not isinstance(value, str) or not value
                for value in registration["gpu_uuids"]
            )
            or not isinstance(registration.get("gpu_identifiers"), list)
            or not registration["gpu_identifiers"]
            or any(
                not isinstance(value, str) or not value
                for value in registration["gpu_identifiers"]
            )
            or len(registration["gpu_uuids"]) != len(registration["gpu_identifiers"])
        ):
            raise ValueError("seedless GPU Registration V2 document is invalid")
        identity = {
            field: registration[field]
            for field in GPU_REGISTRATION_PUBLIC_IDENTITY_FIELDS
        }
        if (
            registration["server_id"] != runtime["server_id"]
            or registration["owner_hotkey"] != runtime["owner_hotkey"]
            or registration["gpu_uuids"] != runtime["gpu_uuids"]
            or registration["gpu_identifiers"] != runtime["gpu_identifiers"]
        ):
            raise ValueError(
                "seedless GPU registration and runtime identities do not match"
            )
        return {
            **identity,
            **{field: runtime[field] for field in GPU_RUNTIME_SESSION_IDENTITY_FIELDS},
            "validator": runtime["validator"],
        }

    @property
    def miner_hourly_cost(self) -> float:
        if not self.gpu_tee_only:
            raise ValueError(
                "signed miner hourly cost is available only in GPU TEE mode"
            )
        values: dict[str, str] = {}
        verified_env_path = Path(self.gpu_verified_env_file)
        try:
            lines = verified_env_path.read_text(encoding="ascii").splitlines()
        except PermissionError as exc:
            raise SeedlessGPUConfigurationError(
                "seedless GPU verified environment file is not readable at "
                f"{verified_env_path}: grant the miner process (UID 65532) directory "
                "traversal and file read permission"
            ) from exc
        for line in lines:
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
