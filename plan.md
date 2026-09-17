# Wormhole — Generic Linux Lab State Transplant

Status: validated development preview; not yet product-qualified

Date: 2026-09-17

## Current implementation status

The baseline, capture, committed manifest, selective restore, tombstones, account
and mixed-file reconciliation, firewall, portable sysctl, SELinux enforcement,
source-added module state, generic systemd intent, protected-host verification,
storage preflight, workflow-wide repository lease, pinned Restic extensions, and
S3 credential plumbing are implemented. Local checks pass.

The destructive Hetzner lifecycle now passes: the harness records a baseline,
captures real work, deletes the source, restores a fresh target, reboots and
validates it independently, performs continued writes, recaptures, and restores
onto a third VM. Current-build Ubuntu 24.04 coverage includes nginx, SQLite,
Python, Node, Go, PostgreSQL, Docker, and ext4. Current-build Fedora 44 coverage
includes a Permissive-to-Enforcing SELinux transition. Development builds also
completed Debian 12, Rocky Linux 10, AlmaLinux 10 with XFS, CentOS Stream 10,
and openSUSE 16. Interruption, repository corruption/repair, live-lock,
bad-credential, target-drift, source-fence, missing/wrong/undersized-volume, and
hostile-path cases have been exercised. Exact evidence is tracked in
[docs/testing.md](docs/testing.md).

That validates the core mechanism, not the full product promise. Remaining
release blockers are:

- Complete a current-build lifecycle on every OS version the product claims to
  support; the attempted all-version Hetzner matrix was intentionally stopped
  before completion.
- Repeat the final destructive interruption, corruption, and live-lease profile
  after the last durability-only engine stamp change.
- Prove or explicitly require manager fencing for writers outside systemd and
  `user.slice`, including distributed workloads whose state spans machines.
- Define the VM-manager contract for extra disks, partitions, LVM, encryption
  mappings, and persistent mount topology; Wormhole restores files but does not
  recreate block-device layouts.
- Define or bound remaining runtime kernel state beyond firewall rules, portable
  sysctls, SELinux enforcement, and source-added modules, including routes,
  namespaces, eBPF, and AppArmor/profile state.
- Define how a generic restore handles workload data containing the source
  hostname, address, certificates, or node identity while the replacement keeps
  its own provider identity.
- Qualify distributed/orchestrated continuation without application-specific
  capture branches.
- Repeat the lifecycle on another provider; Hetzner-only evidence does not
  satisfy the cross-provider requirement.

Until these gates pass, Wormhole is suitable for development experiments on
disposable labs only.

## Product promise

Wormhole preserves a lab across disposable virtual machines:

1. A fresh VM boots from a known base image.
2. The VM manager starts Wormhole with an environment ID, an S3-compatible repository, and temporary credentials.
3. Wormhole records the reusable baseline while excluding identity and configuration owned by that particular VM or its provider.
4. The user changes anything in the lab: files, packages, accounts, services, application data, runtimes, or locally persisted orchestration state.
5. Before shutdown, the manager fences user access and asks Wormhole to capture the complete persistent change layer.
6. Wormhole uploads new content and an authenticated recovery manifest. Content already stored for the baseline is deduplicated.
7. The old VM may be destroyed.
8. A fresh compatible VM later boots from the same logical base. Its manager injects repository access and asks Wormhole to restore the selected capture.
9. Wormhole applies the saved change layer, preserves the replacement VM's host identity and connectivity, restores service intent, and verifies the result before declaring it ready.

The recovered machine should present the same logical lab at the capture boundary. RAM, running processes, open connections, PIDs, and unsaved editor buffers are outside the promise.

Wormhole is workload-agnostic. It does not recognize or branch on particular container engines, cluster distributions, databases, language stacks, or lab products. Those are ordinary consumers of filesystem and service state. Qualification fixtures may use representative workloads, but they must not change the capture model.

## State model

- `B` is the persistent state of the reusable base VM.
- `S` is the persistent state at capture time.
- `D` is every persistent addition, modification, metadata change, type change, and deletion between `B` and `S`.
- `H` is host-owned identity and provider configuration on the replacement VM.

Each recovery point is a complete logical snapshot of `S` plus an explicit manifest for `D`. Restic stores the baseline once and deduplicates unchanged content, so later captures upload only data that is new to the repository. A restore applies `D` to a compatible instance of `B` while preserving `H`.

Captures are not incremental replay chains. Any committed capture can be restored directly while its baseline and repository data remain available.

## Generic capture boundary

The default managed scope is the root filesystem, including mounted persistent filesystems that the VM manager recreates at the same paths before restore. This includes ordinary system-administration changes under `/etc`, package databases, cron, users, service definitions, resolver and mount configuration, permissions, ACLs, capabilities, and application data. Wormhole dynamically excludes transient mount types such as overlay, tmpfs, and kernel virtual filesystems, along with its own state and narrow host-owned identity fields. The VM manager may add exclusions or protected units for an image without defining an application profile.

Before baseline and capture Wormhole:

1. inventories host identity, runtime firewall/sysctl/loaded-module state, and all systemd service/socket/timer/path/mount/automount units plus transient scopes, normalizing transitional unit states to stable intent;
2. stops active non-host units and transient system scopes, then freezes the user slice when available;
3. inventories packages, accounts, and reconciled host-sensitive text files after writers stop, then flushes filesystem writes;
4. creates the snapshot and change manifest;
5. resumes the stopped units unless the manager requested `--leave-stopped` before VM destruction.

This captures arbitrary persistent state rather than a curated list of application directories. Workloads with writers outside systemd or the user slice must be fenced by the VM manager before capture. The `--source-fenced` restore flag records that the manager owns this lifecycle boundary.

Mounts remain attached while their writers are quiesced so their contents stay inside the snapshot. Baseline mount units belong to the replacement host and are not replayed. Mount and automount units created by the lab after baseline are restored and returned to their captured active or inactive state; their backing devices must already satisfy the manager storage contract.

## Host-owned state

The replacement keeps its own:

- hostname and machine ID;
- network configuration, addresses, and default routes;
- SSH host keys and provider administrator access;
- cloud initialization and provider-agent state;
- bootloader, baseline kernel/modules, and recovery-agent files;
- transient runtime trees and logs that cannot be transplanted safely.

The default exclusion policy protects these fields rather than excluding broad system configuration directories. Restore rejects any manifest entry that crosses the policy boundary and compares host identity before and after apply.

Account databases have mixed ownership. Wormhole records line-level changes keyed by account/group name, preserves target-only provider accounts, rejects UID/GID collisions, and writes reconciled files atomically.

`/etc/hosts` and administrator `authorized_keys` files also have mixed ownership. Wormhole records baseline-to-capture line and metadata changes, applies user additions over the target file, maps source hostname/address entries to the replacement identity, and never removes replacement administrator keys. Authorized-key files created after baseline automatically join this reconciliation set, while target-only administrator key paths are added to the restore-time protection policy. Other configured text files can use the same reconciliation path.

Guest firewall rules are state outside the filesystem. Wormhole records stateless nftables rulesets or normalized iptables/ip6tables rules, requires the target firewall to match the baseline before apply, restores captured rules after service activation, verifies them, and rolls back to the target rules if restore fails.

Portable writable sysctls are also state outside the filesystem. Wormhole records baseline-to-capture value changes, excludes host identity, interface-specific, per-boot secret, and automatically sized reserve keys, requires compatible target values, then applies, verifies, and rolls back those changes. Persistent sysctl configuration remains part of the normal filesystem snapshot.

The running kernel must match exactly. Wormhole records modules loaded after the baseline, verifies they exist on the target, loads them before workload activation, verifies them, and unloads modules it loaded if restore fails. Baseline-module removals are ignored rather than replayed because unloading one could detach the replacement VM's network or storage device.

SELinux enforcing/permissive state is recorded separately from its on-disk policy. Restore requires the target to match either the baseline or captured state, applies and verifies a changed mode after workload activation, and rolls it back on failure. Transitions to or from disabled SELinux require a reboot and are rejected as runtime changes.

## Compatibility contract

Restore requires:

- the same environment ID and manifest schema;
- the same logical baseline snapshot and policy hash;
- matching OS identity/release and architecture;
- the exact running kernel release;
- matching cgroup generation;
- a target whose managed state still matches the baseline;
- enough filesystem semantics and capacity for the restored data;
- no protected path or host-identity collision.

Core OS transitions that could invalidate the running recovery process are rejected. Cross-distribution and cross-architecture migration are separate products, not implicit restore behavior.

## Storage and credentials

The VM manager supplies credentials at runtime. Wormhole neither provisions buckets nor persists cloud credentials in its manifests or state directory.

Required environment:

```text
WORMHOLE_ENVIRONMENT_ID
RESTIC_REPOSITORY
RESTIC_PASSWORD, RESTIC_PASSWORD_FILE, or RESTIC_PASSWORD_COMMAND
```

For S3-compatible storage the manager also supplies the standard temporary AWS variables required by Restic. Repository encryption, integrity checking, locking, deduplication, and object transfer remain Restic responsibilities. Wormhole holds one refreshed exclusive Restic lock from manifest selection through workflow completion, removes only stale locks before acquisition, and fails closed if the lease process dies. The lease covers the whole repository, so separate environments sharing one repository serialize; an isolated repository per environment avoids that throughput limit.

Snapshots and manifests carry environment-scoped tags. Restore resolves only snapshots for the configured environment and uses exact snapshot IDs once selected.

## Commands

```text
wormhole inventory
wormhole baseline create
wormhole capture run [--leave-stopped]
wormhole restore apply --source-fenced [--manifest latest|ID]
wormhole inspect
wormhole status [--job ID]
```

The VM manager installs the binary and invokes these commands through the provided systemd templates. It starts baseline explicitly after initial boot, capture after fencing access, and restore before returning the replacement VM to the user.

## Capture transaction

1. Validate configuration, initialize/open the repository, and acquire an exclusive workflow-wide repository lease.
2. Load the environment's baseline by exact ID.
3. Verify the current machine is compatible with that baseline.
4. Record source host identity, firewall rules, sysctls, loaded modules, and unit intent at the running-state boundary.
5. Quiesce generic writers and freeze the user slice when available.
6. Record accounts, reconciled files, and packages, then flush pending writes.
7. Create a full logical Restic snapshot using the baseline as parent.
8. Diff it against the baseline with portable metadata comparison.
9. Reject changed paths outside the managed policy.
10. Build the manifest with changed paths, tombstones, structured account/package/mixed-file/firewall/sysctl/module changes, storage requirements, service intent, policy hash, and snapshot IDs.
11. Store the manifest as an encrypted environment-scoped Restic snapshot.
12. Thaw the user slice, resume units unless destruction fencing keeps them stopped, and only then mark the job complete.

A capture is recoverable only after its manifest commit succeeds. A failed upload never replaces the last known-good capture.

## Restore transaction

1. Require the manager's source-fenced assertion, acquire the guest operation lock, and acquire an exclusive workflow-wide repository lease before manifest selection.
2. Load and validate the selected committed manifest.
3. Verify schema, environment, policy, baseline, and target compatibility.
4. Save the target's protected host identity.
5. Stop active non-host units and transient scopes, freeze the user slice when available, then snapshot the target and prove its managed scope matches the baseline.
6. Pre-delete paths whose type changed.
7. Restore exactly the manifest's changed paths into `/`.
8. Apply tombstones with protected-path checks.
9. Reconcile account database and mixed-ownership text-file changes atomically.
10. Snapshot the result and compare it with the captured state before activation.
11. Restore unit enable/mask and active/stopped intent.
12. Restore and verify source-added kernel modules, captured guest firewall rules, portable sysctl changes, and SELinux enforcement state.
13. Verify accounts, packages, all captured unit intent, and protected host identity.
14. Thaw the user slice and mark the durable job record complete.

Jobs record their phase under `/var/lib/wormhole/jobs`. A repeated restore resumes an interrupted apply when it references the same capture. Cancellation terminates the child process. Failures before mutation resume target services; failures after mutation leave workloads stopped for an idempotent retry.

Before mutation, restore durably records the fresh target's baseline inventories and host identity. After verification it promotes that record to the new VM's local `baseline.json`. The user can therefore continue working and capture the restored lab again; the next capture still compares directly with the original repository baseline, so it remains independently restorable rather than depending on a replay chain.

The target preflight permits drift only at exact paths already owned by the selected manifest because those paths will be replaced or deleted. Any unrelated path, including an unexpected descendant beneath a planned directory, still fails closed. This permits the manager to prepare declared mountpoints without accepting arbitrary target state.

## Engine changes

Wormhole uses a shallow, pinned Restic fork and keeps its repository format unchanged. The fork adds only the primitives needed by the generic transplant flow:

- a NUL-delimited exact-path include file for unambiguous selective restore;
- portable snapshot diffing that ignores inode, device, access-time, change-time, and directory-time noise while retaining content, file modification time, ownership, mode, ACL, capability, xattr, and hard-link changes.
- a hidden workflow lease command so every repository operation in one baseline, capture, or restore runs under one refreshed exclusive lock.

All ownership, compatibility, lifecycle, and protected-state decisions stay in Wormhole.

## Validation

The test matrix is organized by behavior rather than product name:

- files with content, metadata, hard-link, symlink, sparse-file, special-name, deletion, and type transitions;
- package installation/removal, managed account changes, `/etc/hosts`, and administrator-key reconciliation;
- enabled, disabled, masked, active, inactive, socket, timer, path, mount, and automount unit intent;
- stateful services with databases, local volumes, generated artifacts, firewall rules, runtime sysctls, added kernel modules, and continuation writes;
- containerized and orchestrated workloads using multiple interchangeable implementations as fixtures;
- different source and destination hostnames, addresses, machine IDs, host keys, and providers;
- interruption, retry, corrupt data, stale locks, insufficient space, incompatible target, hostile paths, and credential loss.

No fixture earns a special code path. A failure either exposes a generic persistent-state gap or documents a compatibility boundary that applies to the underlying mechanism.

Acceptance requires destroying the source VM, restoring onto a newly provisioned compatible VM, comparing independent source/target observations, exercising each restored workload with new writes, capturing that continued work again, and proving the target retained its own provider identity and access.

## Definition of done

- Baseline and capture are separate durable objects.
- Each capture represents the complete persistent change layer and uploads no duplicate unchanged content.
- A source VM can be destroyed before recovery begins.
- A fresh running VM can restore additions, changes, metadata, type transitions, and deletions without replacing its boot disk.
- Packages, accounts, arbitrary application data, and generic service intent survive.
- Stateful containerized and orchestrated lab fixtures resume and accept new work without runtime-specific Wormhole logic.
- The destination retains its network, machine identity, SSH keys, provider access, and recovery connectivity.
- Conflicts, incompatibility, corruption, interruption, and path-boundary violations fail closed and never report ready.
- Recovery artifacts and their externally managed encryption material outlive the source VM.
- The full lifecycle passes on disposable VMs from more than one provider.

The decisive test is: capture real stateful work, destroy its VM, restore it onto a differently identified fresh running VM, and prove both that the work continues and that the replacement remains a healthy independent host.
