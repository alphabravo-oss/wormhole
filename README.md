# Wormhole

Wormhole moves the persistent state of a Linux lab from one disposable VM to a
fresh compatible VM. It preserves the replacement VM's network, SSH access, and
provider identity while restoring the packages, users, files, services, and
application data created in the lab.

> **Status:** development preview. The core lifecycle has passed destructive
> Hetzner tests, including source deletion, fresh-target restore, reboot,
> continued writes, recapture, and a second fresh restore. It is not yet
> qualified for production or cross-provider recovery.

## Why this exists

Disposable VMs are easy to replace; useful work inside them is not. Keeping the
whole boot disk also keeps stale host identity and provider configuration, while
application-specific backup scripts cannot preserve arbitrary Linux lab state.

Wormhole takes a middle path:

1. record a clean base VM once;
2. capture its complete persistent change layer into an encrypted Restic
   repository;
3. destroy or fence the old VM;
4. apply that change layer to a fresh VM from the same base image;
5. verify the restored lab before reporting it ready.

Captures are complete recovery points, not replay chains. Restic deduplicates
unchanged data, so later captures upload only new repository content.

## Capabilities

- Restores file additions, modifications, deletions, type changes, ownership,
  modes, ACLs, xattrs, capabilities, hard links, sparse files, and unusual names.
- Preserves package changes, users and groups, cron, SSH authorized keys,
  `/etc/hosts`, and other configured mixed-ownership files.
- Restores systemd service, socket, timer, path, mount, and automount intent,
  including enabled, disabled, masked, active, and inactive state.
- Captures ordinary database, language-runtime, web-server, and container state
  without workload-specific Wormhole code.
- Restores guest firewall rules, portable sysctls, source-added kernel modules,
  and SELinux Enforcing/Permissive changes.
- Includes mounted persistent filesystems when the VM manager recreates and
  mounts compatible storage at the same path before restore.
- Preserves the target hostname, machine ID, network configuration, routes, SSH
  host keys, cloud-init state, and provider access.
- Encrypts and deduplicates repository data with Restic, holds an exclusive
  workflow lease, verifies restored content, resumes interrupted restores, and
  fails closed on corruption or incompatible targets.
- Supports continued work after restore: capture the replacement again and
  restore that newer state directly onto another fresh VM.

The detailed state and transaction model is in [plan.md](plan.md).

## Quick install

Requirements: a systemd-based Linux VM, root access, Go 1.25.10 or newer for
the pinned Restic build, and an S3-compatible repository or another Restic
backend. Source and target must use the same OS release, architecture, base
state, and exact running kernel.

From a checkout:

```sh
make build
sudo install -m 0755 bin/wormhole bin/restic /usr/local/bin/
```

Set repository credentials in a root-only environment. Wormhole creates the
encrypted repository during the first baseline if it does not exist:

```sh
export WORMHOLE_ENVIRONMENT_ID=lab-123
export RESTIC_REPOSITORY=s3:https://s3.example.com/labs/lab-123
export RESTIC_PASSWORD_FILE=/run/secrets/restic-password
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=eu-central-1
```

Run the lifecycle as root:

```sh
# Once, on the clean source VM
wormhole baseline create

# After the user has changed the lab
wormhole capture run --leave-stopped

# On a fresh compatible VM, only after the source is fenced or destroyed
wormhole restore apply --source-fenced
```

`--source-fenced` is a safety assertion: never pass it while the old VM can
still serve or modify the same lab. For systemd deployment, temporary
credentials, configuration, storage preparation, and manager integration, see
[Operations](docs/operations.md).

## Tested systems

All completed cloud runs used Hetzner Cloud x86_64 VMs and S3-compatible object
storage. “Current build” means the present `wormhole.18` compatibility stamp.

| OS | Completed coverage |
| --- | --- |
| Ubuntu 24.04 LTS | Current build: nginx, Python venv/package, Node/npm, compiled Go, PostgreSQL with live writer, SQLite, Docker image/container/volume/writable layer, ext4 volume, reboot, continued writes, recapture, and second fresh restore |
| Fedora 44 | Current build: generic lifecycle plus SELinux Permissive→Enforcing, reboot, recapture, and second fresh restore |
| AlmaLinux 10 | Earlier development build: generic lifecycle and attached XFS volume |
| CentOS Stream 10 | Earlier development build: generic lifecycle |
| openSUSE 16 | Earlier development build: generic lifecycle |

The dpkg/APT, RPM/DNF, and RPM/Zypper paths are implemented, but that does not
make every release in those families qualified. Debian, Rocky, other Ubuntu,
Fedora, AlmaLinux, and CentOS versions still need a completed current-build
matrix. See [Validation and tested systems](docs/testing.md) for exact scenarios
and remaining coverage.

## Important boundaries

Wormhole is persistent-state recovery, not live migration. It does not preserve
RAM, processes, connections, PIDs, or unsaved buffers. It does not perform
cross-distribution, cross-architecture, or cross-kernel migration, and it does
not recreate disks, partitions, LVM, encryption mappings, or provider volumes.

Writers outside systemd and `user.slice` must be fenced explicitly. AppArmor
runtime state, custom routes, namespaces, and workload data tied to source host
identity are not yet generalized. Read [Compatibility and limitations](docs/compatibility.md)
before relying on a recovery.

## Documentation

- [Operations](docs/operations.md) — installation, credentials, configuration,
  storage preparation, systemd units, and lifecycle commands.
- [Compatibility and limitations](docs/compatibility.md) — what must match,
  protected host state, consistency boundary, and unsupported cases.
- [Validation and tested systems](docs/testing.md) — test matrix, evidence level,
  destructive scenarios, and how to run the suites.
- [Design and implementation plan](plan.md) — state model, capture/restore
  transactions, engine changes, and release criteria.
- [Third-party notices](THIRD_PARTY_NOTICES.md) — Restic attribution and license.
