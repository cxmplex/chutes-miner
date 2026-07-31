## Chutes Miner CLI

This CLI ships with helpers for managing kubeconfigs when operating miner clusters, plus streaming pre-activation chute logs via the validator API. This document is the single source of truth for those workflows—other READMEs simply link here to avoid drift.

### Quick reference


| Question                        | Answer                                                                                          |
| ------------------------------- | ----------------------------------------------------------------------------------------------- |
| Where do the commands run?      | On the machine where you execute `chutes-miner`. Nothing is copied anywhere else automatically. |
| Default output path             | `~/.kube/chutes.config` unless you pass `--path`.                                               |
| How do I point `kubectl` at it? | `export KUBECONFIG=~/.kube/chutes.config` or `kubectl --kubeconfig ~/.kube/chutes.config ...`.  |
| Can I push it to another host?  | Yes, but you must copy it yourself (example below).                                             |


---

## Seedless Model-B L0

The `l0` command group never accepts artifact hashes, provider credentials, or miner seed text.
It signs API requests with the local hotkey JSON without printing `secretSeed`, verifies the
publisher-signed bootstrap contract against the public key packaged with this CLI, rehashes every
remote L0 artifact, and writes provider-ready raw iPXE as mode 0600.

```bash
chutes-miner l0 prepare-boot \
  --host-id l0-example \
  --tee-type tdx \
  --compute-type cpu \
  --data-device /dev/nvme0n1 \
  --data-device-id nvme-EXACT_DEVICE_ID \
  --validator-ca-url https://objects.example/validator-ca.crt \
  --hotkey ~/.bittensor/wallets/<wallet>/hotkeys/<hotkey>.json \
  --output ./enroll.ipxe \
  --steady-output ./steady.ipxe

chutes-miner l0 enrollment-status --host-id l0-example --hotkey <hotkey.json>

chutes-miner l0 complete-enrollment \
  --host-id l0-example \
  --pcs-key-file /run/secrets/intel-pcs-key \
  --hotkey <hotkey.json>
```

GPU V2 adds the required public disk contract:
`--compute-type gpu --data-device-serial <serial> --gpu-l0-profile <profile>
--storage-data-size-gb <GiB> --gpu-infra-size-gb <GiB>`.

Once the GPU host and its ChuteFS sibling are ready, `chutes-miner l0
gpu-start` reserves and dispatches the miner-managed whole fabric. The
validator returns the stable logical server ID. `chutes-miner l0 gpu-stop
--server-id <id>` seals gpu-infra before the exact QEMU/device reset lifecycle
releases the fabric.

An installed legacy GPU guest can initiate its one-use cutover locally as root:

```bash
sudo chutes-miner l0 gpu-legacy-cutover \
  --host-id <target-l0-host-id> \
  --legacy-server-id <legacy-validator-server-id> \
  --hotkey <operator-hotkey-json>
```

The command starts the packaged cutover service. Use
`gpu-legacy-cutover-retry` if the transfer response is interrupted after the
mappings close. While K3s and both exact source volumes are still live, use
`gpu-legacy-cutover-abort` to durably cancel and clear the reboot fence; abort is
rejected once quiescence starts. Use `gpu-legacy-recover` to reboot through
unchanged legacy key release when custody was not transferred. A new initiation
after a completed abort requires one reboot of the live source so the measured
boot sequence can regenerate and validate its root-only runtime kubeconfig.

`prepare-boot` always writes both the one-use enrollment script and the voucher-free steady-state
script. Add `--wait` to poll readiness with a finite monotonic deadline; it does not delay either
output. A wiped CHUTES_DATA disk requires a new voucher.

### Latitude and OVH provider adapters

Both adapters accept only an already verified mode-`0600` iPXE file. They never accept a wallet
seed, PCS key, PCCS password, or provider credential as a command-line argument.

Latitude reinstall erases CHUTES_DATA and therefore uses the enrollment script:

```bash
export LATITUDESH_BEARER_FILE=/run/secrets/latitude-api-token
chutes-miner l0 latitude-reinstall \
  --server-id sv_EXAMPLE \
  --hostname l0-example \
  --ipxe-file ./enroll.ipxe \
  --wait
```

`LATITUDESH_BEARER` is also accepted from a protected process environment. The adapter submits the
documented JSON:API reinstall request with `operating_system=ipxe`, then reports only the provider
server status. `failed_deployment` fails immediately.

OVH retains CHUTES_DATA across the normal custom-boot flow, so use the enrollment script once and
the steady script on subsequent boots:

```bash
export OVH_BEARER_TOKEN_FILE=/run/secrets/ovh-access-token
chutes-miner l0 ovh-boot \
  --service-name nsXXXXXXX.ip-XXX-XXX-XXX.us \
  --ipxe-file ./enroll.ipxe \
  --reboot \
  --wait
```

`OVH_BEARER_TOKEN` is also accepted from a protected process environment. The adapter writes the
exact inline `bootScript`, reads it back byte-for-byte, then starts the documented hard-reboot task
and reports only its ID, function, and status. Obtain the bearer token from an OVHcloud US service
account with a policy limited to the target dedicated server. Generate a fresh enrollment script
after a disk wipe or credential rotation.

## `sync-kubeconfig`

Fetches the merged kubeconfig for **all** nodes that have already been registered with the miner API.

```bash
chutes-miner sync-kubeconfig \
	--hotkey ~/.bittensor/wallets/<wallet>/hotkeys/<hotkey>.json \
	--miner-api http://127.0.0.1:32000 \
	--path ~/.kube/chutes.config   # optional, defaults to this value
```

1. Signs the request with your miner hotkey.
2. Calls `GET /servers/kubeconfig` on the miner API.
3. Writes the returned kubeconfig to the local filesystem, creating parent directories as needed and overwriting the target file.

After syncing:

```bash
export KUBECONFIG=~/.kube/chutes.config
kubectl config get-contexts
kubectl --namespace chutes get pods
```

> **Important:** `KUBECONFIG` must include the path you wrote to, otherwise `kubectl` keeps using whatever file it was already pointed at.

## `sync-node-kubeconfig`

Fetches a **single** context directly from a node before it has been added to the miner database. The CLI talks to the agent on that node at `/config/kubeconfig`, extracts the requested context, and merges it into your local kubeconfig.

```bash
chutes-miner sync-node-kubeconfig \
	--agent-api https://10.0.0.5:8443 \
	--context-name chutes-miner-gpu-0 \   # Set this to the name of your node
	--hotkey ~/.bittensor/wallets/<wallet>/hotkeys/<hotkey>.json \
	--path ~/.kube/chutes.config \
	--overwrite               # optional, required if the context already exists
```

Behavior highlights:

- Requires the same signed request headers as the miner API (`purpose="registration"`, management mode).
- Parses the returned kubeconfig, finds the specified context, and copies only the context/cluster/user bundle.
- Refuses to replace existing entries unless `--overwrite` is provided, which helps prevent accidental credential swaps.

## Copying the kubeconfig elsewhere

Both commands only touch the local filesystem. To make the synced kubeconfig available on another host, copy it manually. Example helper function:

```bash
sync_control_kubeconfig() {
	local local_cfg=${1:-$HOME/.kube/chutes.config}
	local remote_user=${2:-ubuntu}
	local remote_host=${3:-chutes-miner-cpu-0}
	local remote_path=${4:-.kube/chutes.config}

	if [ ! -f "$local_cfg" ]; then
		echo "Local kubeconfig not found at $local_cfg" >&2
		return 1
	fi

	echo "Copying $local_cfg to $remote_user@$remote_host:$remote_path"
	scp "$local_cfg" "$remote_user@$remote_host:$remote_path"
	ssh "$remote_user@$remote_host" "chmod 600 $remote_path && export KUBECONFIG=$remote_path && kubectl config get-contexts"
}
```

Usage:

```bash
sync_control_kubeconfig                             # uses defaults above
sync_control_kubeconfig ~/.kube/chutes.config admin my-control-node ~/.kube/chutes.config
```

Feel free to swap `scp` for `rsync`, add SSH options, or integrate with your automation tooling.

## `instance-logs`

Streams startup logs for a **public** chute instance (via the validator `GET /miner/instance_logs` endpoint) using the launch JWT. Pass `--jwt` or set `CHUTES_LAUNCH_JWT`.

On a miner cluster, the chute pod’s `CHUTES_LAUNCH_JWT` env var holds that token. This helper takes the **pod name** as the first argument (namespace `chutes`):

```bash
get_chute_jwt() {
	kubectl get po "$1" -n chutes -o json \
		| jq -r '.spec.containers[0].env[] | select(.name == "CHUTES_LAUNCH_JWT") | .value'
}
```

Requires `kubectl` (with a context that can see the pod) and `[jq](https://jqlang.github.io/jq/)`.

Example:

```bash
export CHUTES_LAUNCH_JWT="$(get_chute_jwt chute-2234db67-b453-4198-8ece-74f1f8ea3d03-58pph)"
chutes-miner instance-logs
```

## TEE Maintenance & Upgrades

When a new TEE measurement version is released, miners must cycle their TEE servers through a coordinated maintenance flow. The validator controls upgrade windows and concurrency limits to ensure network availability is preserved during the rollout.

### How it works

- The validator opens an **upgrade window** with a target measurement version, a start/end time, and a per-miner concurrency limit (typically 1).
- Servers whose measurement version is behind the target appear as **pending** in the maintenance policy.
- A server can only enter maintenance if it passes a **preflight check**: the upgrade window is active, the miner hasn't exceeded the concurrency limit, and the server isn't the sole surviving instance for any chute.
- Once in maintenance the validator **purges all instances** on that server and blocks new ones from being scheduled to it.

### Workflow

#### 1. Check maintenance status

See whether an upgrade window is active and which of your servers are pending:

```bash
chutes-miner tee maintenance-status
```

This shows the upgrade window details (target version, start/end, max concurrent), how many of your maintenance slots are in use, and a table of servers that need upgrading.

#### 2. Start maintenance on a server

```bash
chutes-miner tee start-maintenance \
  --name tee-h200-0
```

This single command handles the full flow:

1. **Preflight check** -- calls the validator to verify the server is eligible. If not (wrong window, concurrency limit hit, sole-survivor blocking), it prints the reasons and exits.
2. **Confirmation prompt** -- displays a warning about what will happen and asks for `y/N` confirmation. Pass `--yes` to skip for automation.
3. **Lock the server** -- calls the miner API to lock the server so the local scheduler (gepetto) stops placing new workloads on its GPUs.
4. **Enter maintenance** -- calls the validator to purge running instances and mark the server for upgrade.

#### 3. Shut down and upgrade the server

Once all chutes have terminated in the cluster, gracefully shut down the server:

```bash
chutes-miner tee shutdown \
  --name tee-h200-0 \
  --confirm
```

Then follow the host-specific upgrade steps for the release (e.g. downloading the new VM image and rebooting).

#### 4. Unlock the server

After the server comes back up with the new measurement version:

```bash
chutes-miner unlock --name tee-h200-0
```

This allows gepetto to resume scheduling workloads. The validator will also resume scheduling instances once it sees the server is no longer in maintenance.

#### 5. Repeat for remaining servers

If you have multiple servers to upgrade, repeat steps 2-4 for each one, respecting the per-miner concurrency limit shown in the maintenance status.

### What can block maintenance


| Reason                    | Meaning                                                                                                                                        |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| No active upgrade window  | No upgrade has been announced yet, or the window has closed.                                                                                   |
| Concurrency limit reached | You already have the maximum number of servers in maintenance. Wait for one to finish.                                                         |
| Sole-survivor instance    | Your server hosts the only running instance of a chute. The validator won't allow it to go down until another instance is available elsewhere. |


When the preflight check fails, the CLI displays the specific denial reasons and any blocking chute/instance IDs so you can take action (e.g. wait for another miner to spin up an instance of the blocking chute).

### Checking server version & maintenance status

The `remote-inventory` command now shows **Version** and **Maintenance Pending** for TEE servers, so you can verify the current measurement version and see at a glance which servers still need upgrading:

```bash
chutes-miner remote-inventory
```

### CLI reference


| Command                                              | Description                                                 |
| ---------------------------------------------------- | ----------------------------------------------------------- |
| `chutes-miner tee maintenance-status`                | Show active upgrade window, slot usage, and pending servers |
| `chutes-miner tee start-maintenance --name <server>` | Preflight + lock + enter maintenance (interactive)          |
| `chutes-miner unlock --name <server>`                | Unlock the server after reboot                              |
| `chutes-miner remote-inventory`                      | View server versions and maintenance status                 |


All commands accept `--hotkey` (or `HOTKEY` env var). The `start-maintenance` command also accepts `--miner-api` (default `http://127.0.0.1:32000`) and `--validator-api` (default `https://api.chutes.ai`). Pass `--raw-json` to any command for machine-readable output.

## Verification checklist

- `chutes-miner sync-kubeconfig ...` or `sync-node-kubeconfig ...` exits successfully.
- `stat ~/.kube/chutes.config` shows a recent timestamp.
- `KUBECONFIG` (or `--kubeconfig`) points to the path you just wrote.
- `kubectl config get-contexts` lists the expected contexts (control plane + all tracked nodes, plus any manual additions).
- Optional: run `sync_control_kubeconfig` to push the file to servers that need it.
- Optional: `chutes-miner instance-logs` with a JWT from `get_chute_jwt` (see above) streams logs until the validator closes the stream or you interrupt; use the stderr resume hint and `--cursor` to continue after errors or Ctrl+C.

