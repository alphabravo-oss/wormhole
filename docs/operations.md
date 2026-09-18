# Operations

This guide covers building Wormhole, supplying repository credentials, running
the lifecycle, and integrating it with a VM manager. Read
[Compatibility and limitations](compatibility.md) before restoring important
state.

## Requirements

- A Linux source and target using systemd and the same cgroup generation.
- Root access. Wormhole inventories and changes system-wide state.
- Go 1.25.10 or newer to build the pinned Restic fork.
- A Restic-supported repository. The cloud suite uses S3-compatible object
  storage.
- A VM manager capable of fencing the source and provisioning a fresh,
  compatible target from the same base image.

The source and target must have the same OS release, architecture, base state,
Wormhole configuration, and exact running kernel release.

## Install

Install the x86_64 Linux alpha release and its pinned Restic engine:

```sh
curl -fsSL https://raw.githubusercontent.com/alphabravo-oss/wormhole/v0.1.0-alpha.1/scripts/get-wormhole | bash
wormhole version
```

The installer verifies the release checksum before installing either binary.
It uses `sudo` only for the final write to `/usr/local/bin` when needed.

## Build from source

Build the Wormhole binary and its pinned Restic engine together:

```sh
make build
sudo install -m 0755 bin/wormhole bin/restic /usr/local/bin/
wormhole version
```

Do not replace the bundled `restic` with a stock binary. Wormhole depends on a
small pinned fork for exact-path restore, portable metadata comparison, and its
workflow-wide repository lease.

Run the local checks before packaging a new build:

```sh
make test
```

An engine compatibility stamp is recorded in every baseline and manifest. An
updated Wormhole build can intentionally reject an older baseline when its
state or engine contract changed. Requalify upgrades and create a new baseline
when the stamp changes.

## Repository and credentials

Wormhole accepts Restic's normal environment variables. At minimum:

```sh
export WORMHOLE_ENVIRONMENT_ID=lab-123
export RESTIC_REPOSITORY=s3:https://s3.example.com/labs/lab-123
export RESTIC_PASSWORD_FILE=/run/secrets/restic-password
```

For S3-compatible storage, also provide the variables required by that backend:

```sh
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...       # if temporary credentials use a token
export AWS_DEFAULT_REGION=eu-central-1
```

`RESTIC_PASSWORD` and `RESTIC_PASSWORD_COMMAND` are also supported. Prefer a
root-only password file or command over a long-lived plaintext environment
value. Wormhole does not put repository credentials in its state, snapshots,
or manifests.

The first `baseline create` initializes a repository that does not yet exist.
Use one repository path per environment. A repository-wide exclusive lease
serializes every baseline, capture, and restore, so sharing one path across many
environments also shares one throughput bottleneck.

The repository and its externally managed password must outlive the source VM.
Losing either makes recovery impossible.

## Direct lifecycle

Run these commands as root with the same environment ID, repository, password,
and configuration on every VM.

On the clean source VM, after cloud initialization and base-image preparation:

```sh
wormhole inventory
wormhole baseline create
```

After the user changes the lab:

```sh
wormhole capture run --leave-stopped
```

`--leave-stopped` keeps quiesced workloads stopped so the manager can destroy
the VM without reopening the lab after its capture boundary. Do not destroy the
source unless the command reports `capture_committed`.

On a new VM provisioned from the same logical base:

```sh
wormhole inspect
wormhole restore apply --source-fenced
```

Pass `--source-fenced` only after the manager has made the source unable to
serve or mutate the lab. A successful restore reports `ready` after content,
metadata, packages, accounts, runtime state, workload intent, and target host
identity have been verified and flushed to disk.

After restore, the replacement can accept new work and run another capture.
Each capture remains directly restorable onto the original base; recovery does
not require replaying earlier captures.

Useful inspection commands:

```sh
wormhole inspect --manifest latest
wormhole status
wormhole status --job JOB_ID
```

Jobs and checkpoints live under `/var/lib/wormhole/jobs`. An interrupted restore
of the same capture resumes from its durable checkpoint. Retry with the same
inputs; do not manually mark an incomplete job successful.

## Systemd integration

Install the provided templates:

```sh
sudo install -m 0644 deploy/wormhole-*.service /etc/systemd/system/
sudo systemctl daemon-reload
```

For environment `lab-123`, the manager writes a root-only temporary file at
`/run/wormhole/lab-123.env`, then starts one of:

```sh
systemctl start wormhole-baseline@lab-123.service
systemctl start wormhole-capture@lab-123.service
systemctl start wormhole-restore@lab-123.service
```

The templates run in `system.slice`; this allows Wormhole to freeze
`user.slice` without freezing itself. The manager should wait for the unit,
read its JSON result from the journal, and delete the environment file after the
unit exits.

The restore template already includes the source-fenced assertion. Start it
only from a control path that has actually fenced or destroyed the source.

## Configuration

The defaults manage `/`, dynamically include persistent mounts, and exclude
kernel/runtime trees plus narrow provider-owned identity paths. Supply a JSON
file with `--config /etc/wormhole.json` or `WORMHOLE_CONFIG`:

```json
{
  "roots": ["/", "/srv/lab-volume"],
  "exclude": ["/srv/lab-volume/scratch/**"],
  "protected_services": ["our-vm-agent.service"],
  "quiesce_services": ["a-protected-service-owned-by-the-lab.service"],
  "reconcile_files": ["/etc/example-mixed-ownership.conf"],
  "one_file_system": false,
  "restore_verify": true,
  "require_source_fence": true
}
```

- `roots` replaces the default managed root when non-empty.
- `exclude` adds patterns to the built-in exclusions.
- `protected_services` adds host services Wormhole must not stop or replay.
- `quiesce_services` explicitly permits stopping a protected service owned by
  this lab.
- `reconcile_files` adds line-oriented files whose source changes must merge
  with target-owned content.
- `one_file_system` prevents a root from crossing filesystem boundaries.
- `restore_verify` keeps Restic's restored-content verification enabled.
- `require_source_fence` controls the manager assertion; disabling it weakens
  the split-brain safety boundary and is not recommended.

The configuration becomes part of the baseline policy hash. Use the same file
for capture and restore. Changing it requires a new baseline.

## Attached storage

Wormhole captures files on mounted persistent filesystems; it does not provision
their block devices. Before restore, the VM manager must recreate and mount the
storage at the captured path with compatible filesystem semantics and enough
bytes and inodes.

Wormhole rejects a missing mount, a filesystem-type mismatch, or insufficient
capacity before mutation. The Hetzner suite has exercised ext4 and XFS. Disk
partitioning, LVM, RAID, encryption mappings, and provider-volume attachment
remain manager responsibilities.

## Operational safety

- Keep the repository password outside the source VM and back it up separately.
- Fence access before capture and fence the source before restore.
- Treat a non-`ready` restore as incomplete. After mutation, Wormhole leaves
  workloads stopped so an idempotent retry is safer than serving partial state.
- Preserve the target console or provider rescue path during early adoption.
- Test the exact base image, kernel, storage topology, and workload mix before
  relying on recovery.
- Retain the original VM until a test restore succeeds when the workflow permits
  it; the destructive suite deletes the source only to prove the harder case.
