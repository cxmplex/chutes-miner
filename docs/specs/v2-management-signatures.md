# V2 Miner Management Signatures

**Date**: 2026-07-30
**Status**: enforced on state-changing miner-management routes

## Scope

The following miner API routes share the staged V2 management policy and
require a canonical V2 signature after cutover:

- `POST /servers/`
- `DELETE /servers/{id_or_name}`
- `DELETE /servers/{id_or_name}/deployments`
- `DELETE /deployments/purge`
- `DELETE /deployments/{deployment_id}`
- `GET /servers/{id_or_name}/lock`
- `GET /servers/{id_or_name}/unlock`

The `add-node`, `delete-node`, `purge-server`, `purge-deployments`,
`purge-deployment`, `lock`, `unlock`, and maintenance-lock CLI producers sign
those exact targets with V2. Read-only inventory, delete preflight, and
kubeconfig routes remain V1-compatible during operator migration. Runtime
attested-session bearer authentication is not a substitute for V2 on
state-changing routes in either rollout phase.

The route audit covers every local management `POST`, `PUT`, `PATCH`, and
`DELETE` handler, plus state-changing `GET` handlers. All current state-changing
management handlers use this staged policy. Legacy `POST /servers/` remains
unavailable in seedless production, but its producer and authentication contract
are V2 so final V1 compatibility is read-only only. There are no local
management `PUT` or `PATCH` handlers.

## Wire Contract

A request signs the ASCII message:

```text
v2:{miner}:{validator}:{METHOD}:{path-and-query}:{nonce}:{body-sha256-or-empty}
```

For local miner management, `miner` and `validator` are both the owner's
SS58 address. The nonce is exactly
`{canonical-unix-seconds}.{16-lowercase-hex}`. Future timestamps and timestamps
at least 30 seconds old are rejected. After signature verification, Redis
consumes the signer/nonce pair for the full remaining acceptance interval.
Method, exact request target, request identity, and non-empty body bytes are
therefore not replayable or mutable. Nonce-cache failure rejects the request.

## Rollout

The production chart requires `minerApi.requireV2ManagementSignatures` to be
the string `"true"` or `"false"`; it exports
`CHUTES_REQUIRE_V2_MANAGEMENT_SIGNATURES`. That exact prefixed setting is the
field's sole environment alias; the implicit unprefixed Pydantic name cannot
override it. Invalid values fail chart render or application startup.

1. Deploy the new API with the setting `"false"`. Authenticated V1 state-changing
   requests remain accepted and emit the structured
   `legacy_v1_management_signature_accepted` warning.
2. Publish and deploy the V2-capable CLI.
3. Observe miner API logs until no V1 warning remains.
4. Set the production value to `"true"`; V1 state-changing requests then return
   HTTP 401.
5. Keep read-only management calls compatible and keep bearer-session access
   rejected throughout both phases.

The checked-in final value is `"true"`. Rollback to an older CLI after final
enforcement is unsupported for state-changing commands. There is no dedicated
signature-version metrics subsystem in the miner API, so the authenticated
warning plus existing request/access logging is the rollout signal.

## Release Gates

- Pre-cutover V1 server deletion succeeds once and emits the authenticated V1
  warning; bearer-session deletion still returns HTTP 401.
- Post-cutover V1 and attested-session server deletion return HTTP 401.
- Correct V2 requests are accepted once; exact replay returns HTTP 401.
- Method, path, body, or request-identity mutation returns HTTP 401 without
  consuming the valid nonce.
- Every state-changing management route class rejects V1.
- A static producer audit verifies no state-changing local CLI producer calls the
  legacy signer.
- A runtime `APIRoute` inventory of the assembled app verifies the complete
  state-changing route set resolves the shared authorization policy.
- Read-only management remains V1-compatible.
