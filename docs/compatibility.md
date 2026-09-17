# Compatibility and limitations

Wormhole transplants a persistent change layer onto a compatible fresh host. It
is deliberately stricter than a general backup restore: it rejects a target
when applying the layer could overwrite provider identity or create an
unverifiable hybrid system.

## Compatibility contract

A restore requires all of the following:

- the same Wormhole environment ID, manifest schema, engine stamp, and policy
  hash;
- the same logical baseline snapshot;
- matching OS identity and release, CPU architecture, and cgroup generation;
- the exact running kernel release;
- a managed target filesystem that still matches the recorded baseline, except
  at exact paths the selected manifest owns;
- compatible mounted filesystems with sufficient bytes and inodes;
- no protected-path, account-ID, or host-identity collision.

Creating two VMs from the same provider image name is not always sufficient:
providers can silently refresh an image to a newer kernel. Check `uname -r` and
the base image contents, not only the catalog label.

Cross-distribution, cross-release, cross-architecture, and cross-kernel moves
are outside the current product.

## Persistent state in scope

The default managed root is `/`. Wormhole captures ordinary persistent Linux
changes, including:

- files and directories under `/etc`, `/usr`, `/opt`, `/var`, `/home`, and
  `/root` unless a narrow exclusion protects host-owned state;
- additions, content changes, deletions, type changes, modes, ownership, ACLs,
  xattrs, file capabilities, hard links, sparse files, FIFOs, and unusual path
  names;
- dpkg or RPM package inventory changes;
- users, groups, password/shadow entries, home data, and administrator keys;
- systemd service, socket, timer, path, mount, and automount definitions and
  stable intent;
- application and database files, container engine state, generated artifacts,
  and mounted persistent filesystems;
- guest firewall rules, portable runtime sysctls, modules loaded after the
  baseline, and SELinux Enforcing/Permissive state.

Wormhole does not identify PostgreSQL, Docker, nginx, Python, Node, Go, or other
applications specially. They are test fixtures for the generic filesystem and
service model, not product-specific restore branches.

## State deliberately preserved from the target

The replacement VM keeps its own:

- hostname, machine ID, IP addresses, routes, and provider network files;
- SSH host keys and target administrator access;
- cloud-init and provider-agent state;
- bootloader, kernel, baseline modules, and recovery-agent files;
- transient `/proc`, `/sys`, `/dev`, `/run`, temporary files, caches, and
  selected volatile logs.

Account databases, `/etc/hosts`, and administrator `authorized_keys` contain a
mix of lab-owned and target-owned data. Wormhole reconciles those records
instead of replacing the whole file. It preserves target-only provider accounts
and keys and rejects numeric UID/GID conflicts.

The default exclusions are intentionally narrow and live in
[`cmd/wormhole/config.go`](../cmd/wormhole/config.go). Review them for every new
base image. Broadly excluding `/etc` or `/var` would make a restore appear safe
while silently dropping real lab state.

## Consistency boundary

Before snapshotting, Wormhole inventories system state, stops active
non-protected systemd workloads and transient system scopes, freezes
`user.slice`, records package/account state, and flushes filesystem writes.
Capture runs from `system.slice` when the provided units are used, so it remains
alive while user work is frozen.

This boundary covers normal services, interactive shells, containers managed by
systemd services, and writers in the user slice. It cannot discover every
possible writer. Processes deliberately placed outside those scopes, remote
writers, hypervisor-side storage users, and distributed workloads must be
quiesced or fenced by the manager.

Application-consistent backup still depends on the application honoring normal
service stop semantics and flushing its data. Wormhole provides a crash-safe,
generic boundary; it does not replace database-specific distributed consensus
or external-service coordination.

## Runtime state

Supported runtime state is deliberately bounded:

- Stateless nftables rulesets or normalized iptables/ip6tables rules are
  captured, verified, applied after service activation, and rolled back on
  failure.
- Portable writable sysctls are restored. Host identity, interface-specific,
  per-boot secret, and automatically sized reserve keys are excluded.
- Only modules added after the baseline are loaded. Baseline module removals are
  ignored so Wormhole cannot detach the target's network or storage driver.
- SELinux Enforcing↔Permissive transitions are supported and rolled back on
  failure. Transitions to or from Disabled require reboot-level policy changes
  and are rejected.

Custom routes, network namespaces, eBPF program state, AppArmor runtime/profile
state, device state, and general kernel object state are not yet modeled.
Persistent configuration files for those features may be captured, but their
runtime effects are not a current guarantee.

## Storage boundary

Mounted persistent filesystems remain mounted during capture so their contents
are included. Before restore, the manager must recreate the backing device and
mount it at the same path. Wormhole validates mount presence, filesystem type,
available space, and inode capacity before modifying the target.

Wormhole does not create or reconstruct:

- cloud volumes or attachment relationships;
- partition tables, RAID, LVM, or ZFS pools;
- LUKS or other encryption mappings;
- filesystem creation, resize policy, or mount credentials.

Those belong in the VM manager's infrastructure contract.

## Not preserved

Wormhole is not live migration. It does not preserve RAM, process memory, open
file descriptors, network connections, PIDs, kernel caches, unsaved editor
buffers, or the wall-clock instant at which a process was running.

It also cannot generically rewrite application data that embeds the source
hostname, IP address, node certificate, or cluster identity. The target host
keeps its own provider identity; an application that treats host identity as
data needs its own portable configuration or an explicit compatibility rule.

## Failure behavior

Wormhole fails before mutation on a missing source-fence assertion, wrong
repository password, live repository lease, incompatible target, unrelated
target drift, missing/wrong/undersized mount, protected path, or invalid
manifest.

Restored files are independently snapshotted and compared with the capture
before workloads activate. Host identity is checked again after activation. A
restore reports `ready` only after verification and a filesystem durability
barrier.

If a failure occurs after mutation, workloads remain stopped and the durable job
checkpoint supports retrying the same capture. Repository corruption is not
accepted as partial success. The manager should never serve a VM whose restore
did not report `ready`.
